import os, sys
os.environ.pop('ODIN_REQUIRE_API_KEY', None)
if 'services.gateway.main' in sys.modules:
    del sys.modules['services.gateway.main']
from fastapi.testclient import TestClient
from services.gateway.main import app
import json, hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64

client = TestClient(app)

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"

def test_jwks():
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    keys = r.json().get("keys", [])
    assert isinstance(keys, list) and len(keys) >= 1
    assert keys[0]["kty"] == "OKP"

def test_envelope_end_to_end():
    # Build signed envelope
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    payload = {
        "invoice_id": "INV-TEST",
        "amount": 123.45,
        "currency": "USD",
        "customer_name": "Test Co",
        "description": "Unit test",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    trace_id = "test-trace-001"
    ts = datetime.now(timezone.utc).isoformat()
    message = f"{cid}|{trace_id}|{ts}".encode("utf-8")
    sig = priv.sign(message)
    sender_jwk = {"kty":"OKP","crv":"Ed25519","x":b64u(pub).decode("ascii"),"kid":"unit-sender"}

    ope = {
        "trace_id": trace_id,
        "ts": ts,
        "sender": {"kid": "unit-sender", "jwk": sender_jwk},
        "payload": payload,
        "payload_type": "invoice.vendor.v1",
        "target_type": "invoice.iso20022.v1",
        "cid": cid,
        "signature": b64u(sig).decode("ascii"),
    }
    r = client.post("/v1/odin/envelope", json=ope)
    assert r.status_code == 200
    data = r.json()
    assert data["trace_id"] == trace_id
    assert "receipt" in data
    assert "normalized_payload" in data
