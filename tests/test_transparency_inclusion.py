import base64
import datetime
import json
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from services.gateway.main import app
from odin_core.transparency import TransparencyLog

client = TestClient(app)

def b64u(b: bytes):
    return base64.urlsafe_b64encode(b).rstrip(b'=')


def _send_basic_envelope(trace_id: str):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload = {"x": 42}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    cid = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    msg = f"{cid}|{trace_id}|{ts}".encode()
    sig = priv.sign(msg)
    sender_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub).decode(), "kid": "t-inc"}
    env = {"trace_id": trace_id, "ts": ts, "sender": {"kid": "t-inc", "jwk": sender_jwk}, "payload": payload,
            "payload_type": "invoice.vendor.v1", "target_type": "invoice.iso20022.v1", "cid": cid, "signature": b64u(sig).decode()}
    r = client.post("/v1/odin/envelope", json=env)
    assert r.status_code == 200


def test_transparency_verify_inclusion_and_negative():
    """Validate TransparencyLog.verify_inclusion on export bundle and ensure tampering is detected."""
    trace_id = "tx-inc-1"
    _send_basic_envelope(trace_id)
    r = client.get(f"/v1/receipts/export/{trace_id}")
    assert r.status_code == 200
    data = r.json()
    t = data["transparency"]
    leaf_hash = t["leaf_hash"]
    path = t["audit_path"]
    root = t["root"]
    leaf_index = t["leaf_index"]
    tree_size = t["tree_size"]

    # Positive verification
    assert TransparencyLog.verify_inclusion(leaf_hash, leaf_index, tree_size, path, root) is True

    # Tamper leaf hash
    bad_leaf = ("0" if leaf_hash[0] != "0" else "1") + leaf_hash[1:]
    assert TransparencyLog.verify_inclusion(bad_leaf, leaf_index, tree_size, path, root) is False

    if path:  # Tamper first sibling if path non-empty
        tampered_path = [dict(step) for step in path]
        sib = tampered_path[0]["sibling"]
        tampered_path[0]["sibling"] = ("f" if sib[0] != "f" else "e") + sib[1:]
        assert TransparencyLog.verify_inclusion(leaf_hash, leaf_index, tree_size, tampered_path, root) is False

    # Tamper root expectation
    bad_root = ("a" if root[0] != "a" else "b") + root[1:]
    assert TransparencyLog.verify_inclusion(leaf_hash, leaf_index, tree_size, path, bad_root) is False
