from fastapi.testclient import TestClient
from services.gateway.main import app
import json, hashlib, base64
import os, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

os.environ.pop('ODIN_REQUIRE_API_KEY', None)
if 'services.gateway.main' in sys.modules:
    del sys.modules['services.gateway.main']
client = TestClient(app)

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _post_envelope(trace_id: str):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    payload = {"invoice_id": "INV-EXPORT", "amount": 10.0, "currency": "USD", "customer_name": "Export Co", "description": "Export test", "created_at": datetime.now(timezone.utc).isoformat() }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    message = f"{cid}|{trace_id}|{ts}".encode("utf-8")
    sig = priv.sign(message)
    sender_jwk = {"kty":"OKP","crv":"Ed25519","x":b64u(pub),"kid":"export-sender"}
    ope = {"trace_id": trace_id, "ts": ts, "sender": {"kid": "export-sender", "jwk": sender_jwk}, "payload": payload, "payload_type": "invoice.vendor.v1", "target_type": "invoice.iso20022.v1", "cid": cid, "signature": b64u(sig)}
    r = client.post("/v1/odin/envelope", json=ope)
    assert r.status_code == 200

def test_export_route():
    trace_id = "export-trace-001"
    _post_envelope(trace_id)
    r = client.get(f"/v1/receipts/export/{trace_id}")
    assert r.status_code == 200
    data = r.json()
    assert "bundle" in data and "bundle_signature" in data and "bundle_cid" in data
    bundle = data["bundle"]
    assert bundle["trace_id"] == trace_id
    assert bundle["count"] >= 1
    assert bundle["chain_valid"] is True
    # Basic signature format check (length > 60 for Ed25519 base64url)
    assert len(data["bundle_signature"]) > 60