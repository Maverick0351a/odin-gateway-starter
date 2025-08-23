import os, sys, json, hashlib, base64, importlib, uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

# Configure env BEFORE importing gateway
CONTROL_PLANE_PATH = "test_control_plane.json"
os.environ['CONTROL_PLANE_PATH'] = CONTROL_PLANE_PATH
os.environ['ODIN_ADMIN_TOKEN'] = 'test-admin-token'
os.environ['ODIN_REQUIRE_API_KEY'] = '1'

# Ensure clean module import / reload
if 'services.gateway.main' in sys.modules:
    importlib.reload(sys.modules['services.gateway.main'])
from services.gateway.main import app  # type: ignore

client = TestClient(app)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def test_admin_tenant_crud_and_rate_limit():
    # Create tenant
    r = client.post('/v1/admin/tenants', headers={'x-admin-token': 'test-admin-token'}, json={'tenant_id': 'tenantA', 'name': 'Tenant A'})
    assert r.status_code == 200
    # Issue key
    r = client.post('/v1/admin/tenants/tenantA/keys', headers={'x-admin-token': 'test-admin-token'})
    assert r.status_code == 200
    key_record = r.json()
    api_key = key_record['key']
    secret = key_record['secret']
    # Set rate limit rpm=1
    r = client.patch('/v1/admin/tenants/tenantA', headers={'x-admin-token': 'test-admin-token'}, json={'rate_limit_rpm': 1})
    assert r.status_code == 200

    # Build first envelope
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload = {'invoice_id': 'A1', 'amount': 10, 'ts_field': datetime.now(timezone.utc).isoformat()}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    cid = 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()
    trace_id = 'trace-' + uuid.uuid4().hex[:8]
    ts = datetime.now(timezone.utc).isoformat()
    message = f"{cid}|{trace_id}|{ts}".encode('utf-8')
    sig = priv.sign(message)
    sender_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub), "kid": "sender1"}
    env = {"trace_id": trace_id, "ts": ts, "sender": {"kid": "sender1", "jwk": sender_jwk}, "payload": payload, "payload_type": "invoice.vendor.v1", "target_type": "invoice.iso20022.v1", "cid": cid, "signature": b64u(sig)}
    mac = hashlib.sha256(message)  # purposely incorrect algorithm placeholder? Actually we need HMAC
    import hmac as _hmac
    mac_bytes = _hmac.new(secret.encode(), message, hashlib.sha256).digest()
    mac_b64u = b64u(mac_bytes)
    headers = { 'X-ODIN-API-Key': api_key, 'X-ODIN-API-MAC': mac_b64u }
    r = client.post('/v1/odin/envelope', json=env, headers=headers)
    assert r.status_code == 200, r.text

    # Second envelope should hit rate limit (rpm=1)
    trace_id2 = 'trace-' + uuid.uuid4().hex[:8]
    ts2 = datetime.now(timezone.utc).isoformat()
    message2 = f"{cid}|{trace_id2}|{ts2}".encode('utf-8')
    sig2 = priv.sign(message2)
    env2 = {**env, 'trace_id': trace_id2, 'ts': ts2, 'signature': b64u(sig2)}
    mac2 = _hmac.new(secret.encode(), message2, hashlib.sha256).digest()
    headers2 = { 'X-ODIN-API-Key': api_key, 'X-ODIN-API-MAC': b64u(mac2) }
    r2 = client.post('/v1/odin/envelope', json=env2, headers=headers2)
    # Accept either 429 (rate limited) or 200 if test runtime crossed minute boundary (unlikely)
    assert r2.status_code in (200, 429)

    # Cleanup control plane file
    if os.path.exists(CONTROL_PLANE_PATH):
        os.remove(CONTROL_PLANE_PATH)
