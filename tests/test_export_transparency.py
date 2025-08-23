import base64
import datetime
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from services.gateway.main import app

client = TestClient(app)

def b64u(b: bytes):
    return base64.urlsafe_b64encode(b).rstrip(b'=')

def _send_basic_envelope(trace_id: str):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload = {"x":1}
    import hashlib as _hashlib
    import json as _json
    payload_bytes = _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    cid = "sha256:" + _hashlib.sha256(payload_bytes).hexdigest()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    msg = f"{cid}|{trace_id}|{ts}".encode()
    sig = priv.sign(msg)
    sender_jwk = {"kty":"OKP","crv":"Ed25519","x": b64u(pub).decode(),"kid":"t-export"}
    # Use known payload_type expected by SFT to avoid transform error
    env = {"trace_id": trace_id, "ts": ts, "sender": {"kid":"t-export","jwk": sender_jwk}, "payload": payload, "payload_type":"invoice.vendor.v1","target_type":"invoice.iso20022.v1","cid": cid, "signature": b64u(sig).decode()}
    r = client.post("/v1/odin/envelope", json=env)
    assert r.status_code == 200

def test_export_inclusion_proof():
    trace_id = "tx-proof-1"
    _send_basic_envelope(trace_id)
    r = client.get(f"/v1/receipts/export/{trace_id}")
    assert r.status_code == 200
    data = r.json()
    t = data.get("transparency")
    assert t and "audit_path" in t
    # Verify inclusion proof using exported path
    leaf_hash = t["leaf_hash"]
    root = t["root"]
    # Recompute root from path
    cur = leaf_hash
    for step in t["audit_path"]:
        sib = step["sibling"]
        if step["side"] == "right":
            cur = hashlib.sha256(bytes.fromhex(cur)+bytes.fromhex(sib)).hexdigest()
        else:
            cur = hashlib.sha256(bytes.fromhex(sib)+bytes.fromhex(cur)).hexdigest()
    assert cur == root