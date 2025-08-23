import os
import sys
import pathlib
import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

# Ensure clean env for tests (no API key requirement)
os.environ.pop('ODIN_REQUIRE_API_KEY', None)

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

from services.gateway.main import app  # noqa: E402

client = TestClient(app)

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=') .decode('ascii')


def _build_signed_envelope(trace_id: str, ts: str | None = None):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = {
        "invoice_id": "INV-ERR",
        "amount": 1.0,
        "currency": "USD",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    ts_final = ts or datetime.now(timezone.utc).isoformat()
    message = f"{cid}|{trace_id}|{ts_final}".encode("utf-8")
    sig = priv.sign(message)
    sender_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub), "kid": "err-sender"}
    envelope = {
        "trace_id": trace_id,
        "ts": ts_final,
        "sender": {"kid": "err-sender", "jwk": sender_jwk},
        "payload": payload,
        "payload_type": "invoice.vendor.v1",
        "target_type": "invoice.iso20022.v1",
        "cid": cid,
        "signature": b64u(sig),
    }
    return envelope, priv


def test_bad_timestamp_format():
    envelope, _ = _build_signed_envelope("trace-badts", ts="not-a-timestamp")
    r = client.post("/v1/odin/envelope", json=envelope)
    assert r.status_code == 400
    assert "Invalid ts" in r.text


def test_timestamp_too_old(monkeypatch):
    envelope, _ = _build_signed_envelope("trace-old", ts=(datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat())
    monkeypatch.setenv("ODIN_MAX_SKEW_SECONDS", "1")  # tighten skew window
    r = client.post("/v1/odin/envelope", json=envelope)
    assert r.status_code == 400
    assert "too far in past" in r.text


def test_bad_signature():
    envelope, _ = _build_signed_envelope("trace-badsig")
    envelope["signature"] = "AAAA"  # corrupt signature
    r = client.post("/v1/odin/envelope", json=envelope)
    assert r.status_code == 400
    assert "Invalid signature" in r.text


def test_replay_detection():
    envelope, _ = _build_signed_envelope("trace-replay")
    r1 = client.post("/v1/odin/envelope", json=envelope)
    assert r1.status_code == 200
    r2 = client.post("/v1/odin/envelope", json=envelope)
    assert r2.status_code == 409
    assert "Replay detected" in r2.text


def test_policy_block_forward_url():
    envelope, _ = _build_signed_envelope("trace-policy")
    # Provide a forward_url to trigger policy evaluation (default allowlist empty => blocked)
    envelope["forward_url"] = "https://blocked.example.com/api"
    r = client.post("/v1/odin/envelope", json=envelope)
    assert r.status_code == 403
    assert "Egress blocked" in r.text


def test_missing_sender_key():
    envelope, _ = _build_signed_envelope("trace-nokey")
    # Remove sender key info entirely
    envelope["sender"] = {"kid": "nope"}
    r = client.post("/v1/odin/envelope", json=envelope)
    assert r.status_code == 400
    assert "No sender JWK" in r.text
