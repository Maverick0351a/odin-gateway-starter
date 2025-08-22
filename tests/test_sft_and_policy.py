import os, json, hashlib, base64, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=') .decode('ascii')


def _post(app, payload, payload_type, target_type, trace_id="test-trace-pol-1", forward_url=None, headers=None):
    client = TestClient(app)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    msg = f"{cid}|{trace_id}|{ts}".encode("utf-8")
    sig = priv.sign(msg)
    sender_jwk = {"kty":"OKP","crv":"Ed25519","x":b64u(pub),"kid":"demo"}
    ope = {"trace_id": trace_id, "ts": ts, "sender": {"kid":"demo", "jwk": sender_jwk}, "payload": payload, "payload_type": payload_type, "target_type": target_type, "cid": cid, "signature": b64u(sig)}
    if forward_url:
        ope["forward_url"] = forward_url
    return client.post("/v1/odin/envelope", json=ope, headers=headers or {})


def test_openai_tooluse_mapping(monkeypatch):
    if "services.gateway.main" in sys.modules:
        del sys.modules["services.gateway.main"]
    from services.gateway.main import app
    payload = {
        "tool_calls": [
            {"type":"function","function":{"name":"create_invoice","arguments":json.dumps({
                "invoice_id":"INV-OAI-1","amount":321.5,"currency":"USD","customer_name":"OpenAI Co","description":"Tool use"})}}
        ],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    r = _post(app, payload, "openai.tooluse.invoice.v1", "invoice.iso20022.v1")
    assert r.status_code == 200
    data = r.json()
    # 'source' key removed in new mapping; ensure mapping succeeded by checking core note field
    assert "fields_mapped" in data["sft_notes"]


def test_claude_tooluse_mapping(monkeypatch):
    if "services.gateway.main" in sys.modules:
        del sys.modules["services.gateway.main"]
    from services.gateway.main import app
    payload = {
        "content": [
            {"type":"tool_use", "name":"create_invoice", "input": {"invoice_id":"INV-CL-1","amount":77.7,"currency":"USD","customer_name":"Claude Corp","description":"Claude tool"}}
        ],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    r = _post(app, payload, "claude.tooluse.invoice.v1", "invoice.iso20022.v1")
    assert r.status_code == 200
    data = r.json()
    assert "fields_mapped" in data["sft_notes"]


def test_key_rotation_and_status(monkeypatch):
    monkeypatch.setenv("ODIN_ADDITIONAL_PUBLIC_JWKS", json.dumps({
        "keys": [{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "kid":"legacy-key-1"}] }))
    if "services.gateway.main" in sys.modules:
        del sys.modules["services.gateway.main"]
    from services.gateway.main import app
    client = TestClient(app)
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    keys = resp.json().get("keys", [])
    assert any(k.get("status") == "active" for k in keys)
    assert any(k.get("status") == "legacy" for k in keys)


def test_per_tenant_hel_allow(monkeypatch):
    monkeypatch.setenv("HEL_ALLOWLIST", "")
    monkeypatch.setenv("HEL_TENANT_ALLOWLISTS", json.dumps({"tenant-123":["allowed.example.com"]}))
    if "services.gateway.main" in sys.modules:
        del sys.modules["services.gateway.main"]
    from services.gateway.main import app
    r = _post(app, {"invoice_id":"X","amount":1,"currency":"USD","customer_name":"T","description":"D","created_at": datetime.now(timezone.utc).isoformat()}, "invoice.vendor.v1", "invoice.iso20022.v1", forward_url="https://allowed.example.com/endpoint", headers={"X-ODIN-API-Key":"tenant-123"})
    assert r.status_code == 200
    r2 = _post(app, {"invoice_id":"X2","amount":1,"currency":"USD","customer_name":"T","description":"D","created_at": datetime.now(timezone.utc).isoformat()}, "invoice.vendor.v1", "invoice.iso20022.v1", forward_url="https://blocked.example.net/", headers={"X-ODIN-API-Key":"tenant-123"})
    assert r2.status_code == 403
