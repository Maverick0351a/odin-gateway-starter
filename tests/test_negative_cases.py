import base64
import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

BASELINE_ADMIN = 'test-admin-token'

def _reload_gateway():
    if 'services.gateway.main' in sys.modules:
        del sys.modules['services.gateway.main']
    from services.gateway.main import app  # type: ignore
    return app

@pytest.fixture()
def neg_client():
    # Save original env
    orig = {k: os.environ.get(k) for k in ['ODIN_REQUIRE_API_KEY','ODIN_ADMIN_TOKEN','CONTROL_PLANE_PATH']}
    # Configure negative test environment
    os.environ['ODIN_REQUIRE_API_KEY'] = '1'
    os.environ['ODIN_ADMIN_TOKEN'] = 'neg-admin'
    os.environ['CONTROL_PLANE_PATH'] = 'neg_control_plane.json'
    app = _reload_gateway()
    client = TestClient(app)
    yield client
    # Restore baseline (no API key requirement, standard admin token)
    for k,v in orig.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    # Ensure API key requirement disabled for subsequent tests
    os.environ.pop('ODIN_REQUIRE_API_KEY', None)
    os.environ['ODIN_ADMIN_TOKEN'] = BASELINE_ADMIN
    _reload_gateway()

def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def build_env(priv: Ed25519PrivateKey, trace_id: str, payload: dict) -> dict:
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    cid = 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    msg = f"{cid}|{trace_id}|{ts}".encode('utf-8')
    sig = priv.sign(msg)
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return {
        'trace_id': trace_id,
        'ts': ts,
        'sender': {'kid': 'neg-sender', 'jwk': {'kty':'OKP','crv':'Ed25519','x': b64u(pub),'kid':'neg-sender'}},
        'payload': payload,
        'payload_type': 'invoice.vendor.v1',
        'target_type': 'invoice.iso20022.v1',
        'cid': cid,
        'signature': b64u(sig)
    }

def test_admin_unauthorized(neg_client):
    r = neg_client.get('/v1/admin/tenants')
    assert r.status_code in (401,403)

def test_bad_mac_rejected(neg_client):
    # Create tenant + key (allow 400 if tenant already created by flaky prior run)
    r = neg_client.post('/v1/admin/tenants', headers={'x-admin-token':'neg-admin'}, json={'tenant_id':'badmac'})
    assert r.status_code in (200,400)
    r = neg_client.post('/v1/admin/tenants/badmac/keys', headers={'x-admin-token':'neg-admin'})
    rec = r.json(); key = rec['key']; secret = rec['secret']
    priv = Ed25519PrivateKey.generate()
    env = build_env(priv, 'trace-'+uuid.uuid4().hex[:8], {'val':1})
    # Wrong MAC (sign with different message)
    wrong_msg = (env['cid']+ '|WRONG|' + env['ts']).encode()
    mac = hmac.new(secret.encode(), wrong_msg, hashlib.sha256).digest()
    mac_b64u = b64u(mac.encode() if isinstance(mac, str) else mac)
    r2 = neg_client.post('/v1/odin/envelope', json=env, headers={'X-ODIN-API-Key': key, 'X-ODIN-API-MAC': mac_b64u})
    assert r2.status_code == 401

def test_tampered_export_detection(neg_client):
    # Happy path send
    r = neg_client.post('/v1/admin/tenants', headers={'x-admin-token':'neg-admin'}, json={'tenant_id':'tamper'})
    assert r.status_code in (200,400)  # tenant may already exist from previous test run
    r = neg_client.post('/v1/admin/tenants/tamper/keys', headers={'x-admin-token':'neg-admin'})
    rec = r.json(); key = rec['key']; secret = rec['secret']
    priv = Ed25519PrivateKey.generate()
    env = build_env(priv, 'trace-'+uuid.uuid4().hex[:8], {'val':2})
    msg = f"{env['cid']}|{env['trace_id']}|{env['ts']}".encode()
    mac = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    mac_b64u = b64u(mac)
    r_ok = neg_client.post('/v1/odin/envelope', json=env, headers={'X-ODIN-API-Key': key, 'X-ODIN-API-MAC': mac_b64u})
    assert r_ok.status_code == 200
    # Get export bundle
    exp = neg_client.get(f"/v1/receipts/export/{env['trace_id']}")
    assert exp.status_code == 200
    body = exp.json()
    bundle = body.get('bundle') or body
    # Tamper a receipt hash locally and recompute chain check logic (simulate external verifier)
    receipts = bundle.get('receipts', [])
    if receipts:
        receipts[0]['receipt_hash'] = 'deadbeef'*8
        # Recompute linkage check similar to dashboard logic
        prev = None; chain_ok = True
        for i,r in enumerate(receipts):
            r_copy = dict(r); r_copy.pop('receipt_signature', None)
            h_local = hashlib.sha256(json.dumps(r_copy, sort_keys=True, separators=(',',':')).encode()).hexdigest()
            if h_local != r.get('receipt_hash'): chain_ok = False; break
            if i and r.get('prev_receipt_hash') != prev.get('receipt_hash'): chain_ok = False; break
            prev = r
        assert chain_ok is False

    # Control plane file left for potential inspection; removal handled by fixture scope end

def test_replay_detection(neg_client):
    # Set tighter skew to speed test
    os.environ['ODIN_MAX_SKEW_SECONDS'] = '300'
    # Issue tenant + key
    neg_client.post('/v1/admin/tenants', headers={'x-admin-token':'neg-admin'}, json={'tenant_id':'replay'})
    rec = neg_client.post('/v1/admin/tenants/replay/keys', headers={'x-admin-token':'neg-admin'}).json()
    key, secret = rec['key'], rec['secret']
    priv = Ed25519PrivateKey.generate()
    trace = 'trace-'+uuid.uuid4().hex[:8]
    env = build_env(priv, trace, {'foo':1})
    # Compute correct MAC
    msg = f"{env['cid']}|{env['trace_id']}|{env['ts']}".encode()
    mac = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    mac_b64u = b64u(mac)
    r1 = neg_client.post('/v1/odin/envelope', json=env, headers={'X-ODIN-API-Key': key, 'X-ODIN-API-MAC': mac_b64u})
    assert r1.status_code == 200
    # Replay exact same envelope (should 409)
    r2 = neg_client.post('/v1/odin/envelope', json=env, headers={'X-ODIN-API-Key': key, 'X-ODIN-API-MAC': mac_b64u})
    assert r2.status_code == 409

def test_timestamp_skew_rejected(neg_client):
    # Reduce skew window
    os.environ['ODIN_MAX_SKEW_SECONDS'] = '1'
    neg_client.post('/v1/admin/tenants', headers={'x-admin-token':'neg-admin'}, json={'tenant_id':'skew'})
    rec = neg_client.post('/v1/admin/tenants/skew/keys', headers={'x-admin-token':'neg-admin'}).json()
    key, secret = rec['key'], rec['secret']
    priv = Ed25519PrivateKey.generate()
    # Build env with old timestamp
    from datetime import datetime, timedelta, timezone
    old_ts = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    payload = {'val':3}
    import json as _json
    payload_bytes = _json.dumps(payload, sort_keys=True, separators=(',',':')).encode()
    cid = 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()
    trace_id = 'trace-'+uuid.uuid4().hex[:8]
    msg_plain = f"{cid}|{trace_id}|{old_ts}".encode()
    sig = priv.sign(msg_plain)
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    env = {
        'trace_id': trace_id,
        'ts': old_ts,
        'sender': {'kid': 'skew-sender', 'jwk': {'kty':'OKP','crv':'Ed25519','x': b64u(pub),'kid':'skew-sender'}},
        'payload': payload,
        'payload_type': 'invoice.vendor.v1',
        'target_type': 'invoice.iso20022.v1',
        'cid': cid,
        'signature': b64u(sig)
    }
    mac = hmac.new(secret.encode(), msg_plain, hashlib.sha256).digest(); mac_b64u = b64u(mac)
    r = neg_client.post('/v1/odin/envelope', json=env, headers={'X-ODIN-API-Key': key, 'X-ODIN-API-MAC': mac_b64u})
    assert r.status_code == 400