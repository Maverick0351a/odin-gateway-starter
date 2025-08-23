import base64, hashlib, json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from services.gateway.main import app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _b64u(b: bytes) -> str:
    import base64 as _b
    return _b.urlsafe_b64encode(b).rstrip(b"=").decode()


def build_signed_envelope(payload_type="invoice.vendor.v1", target_type="invoice.iso20022.v1"):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload = {
        "invoice_id": "FIXTURE-INV",
        "amount": 1.23,
        "currency": "USD",
        "customer_name": "Fixture Co",
        "description": "Fixture payload",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    trace_id = "fixture-trace"
    ts = datetime.now(timezone.utc).isoformat()
    msg = f"{cid}|{trace_id}|{ts}".encode()
    sig = _b64u(priv.sign(msg))
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub), "kid": "fixture-sender"}
    return {
        "trace_id": trace_id,
        "ts": ts,
        "sender": {"kid": "fixture-sender", "jwk": jwk},
        "payload": payload,
        "payload_type": payload_type,
        "target_type": target_type,
        "cid": cid,
        "signature": sig,
    }


def test_fixture_client_health(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_fixture_client_envelope(client):
    env = build_signed_envelope()
    r = client.post("/v1/odin/envelope", json=env)
    assert r.status_code == 200
    d = r.json()
    assert d["trace_id"] == env["trace_id"]
    assert "receipt" in d
    assert d["receipt"].get("normalized_cid") or d.get("normalized_payload")
