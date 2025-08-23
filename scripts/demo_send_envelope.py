# Demo: craft and send a signed OPE envelope to the local gateway
import base64
import hashlib
import json
import os
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

# Sender key (demo uses a new key each run)
priv = Ed25519PrivateKey.generate()
raw = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

payload = {
    "tool_calls": [
        {"type": "function", "function": {"name": "create_invoice", "arguments": json.dumps({
            "invoice_id": "INV-OAI-1",
            "amount": 321.5,
            "currency": "USD",
            "customer_name": "OpenAI Co",
            "description": "Tool use"
        })}}
    ],
    "created_at": datetime.now(timezone.utc).isoformat()
}

payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
trace_id = os.getenv("TRACE_ID", "demo-trace-001")
ts = datetime.now(timezone.utc).isoformat()
message = f"{cid}|{trace_id}|{ts}".encode("utf-8")
signature = b64u(priv.sign(message))

sender_jwk = {"kty":"OKP","crv":"Ed25519","x":b64u(pub),"kid":"demo-sender"}

ope = {
    "trace_id": trace_id,
    "ts": ts,
    "sender": {"kid": "demo-sender", "jwk": sender_jwk},
    "payload": payload,
    "payload_type": "openai.tooluse.invoice.v1",
    "target_type": "invoice.iso20022.v1",
    "cid": cid,
    "signature": signature,
    # "forward_url": "https://postman-echo.com/post",
}

print("Sending OPE to http://localhost:8080/v1/odin/envelope ...")
resp = requests.post("http://localhost:8080/v1/odin/envelope", json=ope, timeout=10)
print("Status:", resp.status_code)
print("Headers:", {k:v for k,v in resp.headers.items() if k.lower().startswith("x-odin")})
try:
    print("Body:", json.dumps(resp.json(), indent=2))
except Exception:
    print("Body:", resp.text)
