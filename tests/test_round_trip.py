import base64
import hashlib
import json
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=') .decode('ascii')

def _post(app, payload, payload_type, target_type, trace_id="rt-trace-1"):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    msg = f"{cid}|{trace_id}|{ts}".encode("utf-8")
    sig = priv.sign(msg)
    sender_jwk = {"kty":"OKP","crv":"Ed25519","x":b64u(pub),"kid":"rt"}
    env = {"trace_id": trace_id, "ts": ts, "sender": {"kid":"rt","jwk": sender_jwk}, "payload": payload, "payload_type": payload_type, "target_type": target_type, "cid": cid, "signature": b64u(sig)}
    client = TestClient(app)
    return client.post("/v1/odin/envelope", json=env)

def test_round_trip_iso_to_openai(monkeypatch):
    if "services.gateway.main" in sys.modules:
        del sys.modules["services.gateway.main"]
    from services.gateway.main import app
    # First produce ISO via openai tool-use forward mapping
    tool_payload = {
        "tool_calls": [{"type":"function","function":{"name":"create_invoice","arguments": json.dumps({
            "invoice_id":"INV-RT-1","amount":10.5,"currency":"USD","customer_name":"Round Trip LLC","description":"RT Demo"
        })}}],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    r1 = _post(app, tool_payload, "openai.tooluse.invoice.v1", "invoice.iso20022.v1")
    assert r1.status_code == 200
    iso_doc = r1.json()["normalized_payload"]
    # Now reverse: iso -> openai.tooluse
    r2 = _post(app, iso_doc, "invoice.iso20022.v1", "openai.tooluse.invoice.v1")
    assert r2.status_code == 200
    back = r2.json()["normalized_payload"]
    # Validate the reconstructed tool call has expected function name and arguments
    tc = back["tool_calls"][0]
    assert tc["function"]["name"] == "create_invoice"
    args = json.loads(tc["function"]["arguments"])
    assert args["invoice_id"] == "INV-RT-1"
    assert float(args["amount"]) == 10.5
