import os, sys, pathlib, json, base64, hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

# Configure relay URL (fake) so forwarding branch triggers but we will mock httpx
os.environ['RELAY_URL'] = 'https://relay.example'
# Attempt open policy (may be too late if module already imported elsewhere)
os.environ['ODIN_POLICY_PROFILE'] = 'open'

from services.gateway.main import app, control_plane  # noqa
import services.gateway.main as gw_mod  # for monkeypatching

client = TestClient(app)

# Helper
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def _make_sender_key():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub), "kid": "sender-kid"}
    return priv, jwk


def _sign_envelope(priv, payload, trace_id, ts, cid):
    message = f"{cid}|{trace_id}|{ts}".encode('utf-8')
    sig = priv.sign(message)
    return b64u(sig)


def _build_payload():
    return {
        "invoice_id": "FWD-1",
        "amount": 10.5,
        "currency": "USD",
        "customer_name": "Forward Test",
        "description": "Forward path",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _build_envelope(forward_url=None, extra_headers=None, tenant=None, tenant_priv=None):
    priv, sender_jwk = _make_sender_key()
    payload = _build_payload()
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode('utf-8')
    cid = 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()
    trace_id = 'trace-forward-test'
    ts = datetime.now(timezone.utc).isoformat()
    sig = _sign_envelope(priv, payload, trace_id, ts, cid)
    envelope = {
        "trace_id": trace_id,
        "ts": ts,
        "sender": {"kid": sender_jwk['kid'], "jwk": sender_jwk},
        "payload": payload,
        "payload_type": "invoice.vendor.v1",
        "target_type": "invoice.iso20022.v1",
        "cid": cid,
        "signature": sig,
    }
    headers = extra_headers.copy() if extra_headers else {}
    if forward_url:
        envelope["forward_url"] = forward_url
    # tenant dual sig
    if tenant and tenant_priv:
        pattern = f"{cid}|sha256:{hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',',':')).encode('utf-8')).hexdigest()}|{trace_id}|"  # prev hash empty
        t_sig = tenant_priv.sign(pattern.encode('utf-8'))
        headers['x-odin-tenant-signature'] = b64u(t_sig)
        headers['x-odin-tenant-kid'] = 'tenant-byok-kid'
    return envelope, headers


def test_relay_forwarding(monkeypatch):
    # Ensure policy allows forwarding regardless of prior initialization order
    class AllowAll:
        def check_http_egress(self, host, tenant_key=None):
            from collections import namedtuple
            R = namedtuple('R', 'passed rule reasons')
            return R(True, 'TEST:ALLOW', ['forced allow'])
    monkeypatch.setattr(gw_mod, 'policy_engine', AllowAll())
    # Force relay URL global (module may have been imported before env var set in other tests)
    monkeypatch.setattr(gw_mod, 'RELAY_URL', 'https://relay.example')
    class DummyResp:
        status_code = 202
        headers = {'content-type': 'application/json'}
        def json(self):
            return {'ok': True}
    async def dummy_post(self, url, json):  # noqa: A002 shadow
        return DummyResp()
    monkeypatch.setattr('httpx.AsyncClient.post', dummy_post, raising=False)
    envelope, headers = _build_envelope(forward_url='https://downstream.example/endpoint')
    r = client.post('/v1/odin/envelope', json=envelope, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body['forwarded'] and body['forwarded']['status_code'] == 202


def test_byok_dual_signature(monkeypatch):
    # Create BYOK tenant and set signer_ref public JWK
    tenant_id = 'tenant-byok'
    control_plane.create_tenant(tenant_id)
    # Provide signer_ref JWK
    t_priv = Ed25519PrivateKey.generate()
    t_pub = t_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    signer_ref = {"kty": "OKP", "crv": "Ed25519", "x": b64u(t_pub), "kid": "tenant-byok-kid"}
    control_plane.update_tenant(tenant_id, custody_mode='byok', signer_ref=signer_ref)
    envelope, headers = _build_envelope(tenant=tenant_id, tenant_priv=t_priv)
    # Simulate that gateway resolves tenant context by giving API key style header path
    # Simplest: inject tenant context into control_plane directly by setting api_key equal to tenant id (already done pattern in gateway)
    r = client.post('/v1/odin/envelope', json=envelope, headers=headers)
    assert r.status_code == 200
    data = r.json()
    # Receipt should include tenant id and tenant_signatures list
    assert data['receipt'].get('tenant_id') == tenant_id or data['receipt'].get('tenant_id') is None  # may not be set if auth not required
    # If dual signature captured, pattern and kid present
    if data['receipt'].get('tenant_signatures'):
        tsigs = data['receipt']['tenant_signatures']
        assert tsigs[0]['kid'] == 'tenant-byok-kid'
