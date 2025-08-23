import base64
import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, Optional, Tuple

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = ["OPEClient", "b64u", "cid_sha256", "canonical_json"]

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def cid_sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def gen_trace_id() -> str:
    return str(uuid.uuid4())

def now_ts_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class SignatureError(Exception):
    pass

class VerificationError(Exception):
    pass

class OPEClient:
    """Minimal client for creating, sending, and verifying OPE envelopes.

    Automatically verifies response signatures, receipt chain linkage,
    and export bundles through helper methods.
    """
    def __init__(self, gateway_url: str, sender_priv_b64: str, sender_kid: str):
        self.gateway_url = gateway_url.rstrip("/")
        priv_raw = b64u_decode(sender_priv_b64)
        if len(priv_raw) != 32:
            raise ValueError("Ed25519 private key raw bytes must be 32 bytes")
        self._priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
        self._pub = self._priv.public_key()
        self.sender_kid = sender_kid

    def public_jwk(self) -> Dict[str, Any]:
        pub_raw = self._pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub_raw), "kid": self.sender_kid}

    def create_envelope(self, payload: Dict[str, Any], payload_type: str, target_type: str, trace_id: Optional[str] = None, ts: Optional[str] = None) -> Dict[str, Any]:
        trace_id = trace_id or gen_trace_id()
        ts = ts or now_ts_iso()
        payload_bytes = canonical_json(payload)
        cid = cid_sha256(payload_bytes)
        msg = f"{cid}|{trace_id}|{ts}".encode("utf-8")
        sig = self._priv.sign(msg)
        envelope = {
            "trace_id": trace_id,
            "ts": ts,
            "sender": {"kid": self.sender_kid, "jwk": self.public_jwk()},
            "payload": payload,
            "payload_type": payload_type,
            "target_type": target_type,
            "cid": cid,
            "signature": b64u(sig),
        }
        return envelope

    def _fetch_jwks(self) -> Dict[str, Any]:
        r = httpx.get(f"{self.gateway_url}/.well-known/jwks.json", timeout=10)
        r.raise_for_status()
        return r.json()

    def _verify_response(self, body: Dict[str, Any], headers: Dict[str, str]):
        # Verify Response CID
        body_bytes = canonical_json(body)
        local_cid = cid_sha256(body_bytes)
        resp_cid = headers.get("x-odin-response-cid")
        if resp_cid and resp_cid != local_cid:
            raise VerificationError("Response CID mismatch")
        # Verify signature
        sig_b64u = headers.get("x-odin-signature")
        kid = headers.get("x-odin-kid")
        if not sig_b64u or not kid:
            raise VerificationError("Missing signature headers")
        jwks = self._fetch_jwks()
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break
        if key is None:
            raise VerificationError("Gateway key not found in JWKS")
        if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
            raise VerificationError("Unsupported gateway key type")
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64u_decode(key["x"]))
            trace_id = headers.get("x-odin-trace-id") or body.get("trace_id")
            receipt = body.get("receipt", {})
            ts = receipt.get("ts")
            msg = f"{local_cid}|{trace_id}|{ts}".encode("utf-8")
            pub.verify(b64u_decode(sig_b64u), msg)
        except Exception as e:
            raise VerificationError(f"Response signature invalid: {e}")

    def send_envelope(self, envelope: Dict[str, Any], verify_chain: bool = False) -> Tuple[Dict[str, Any], Dict[str, str]]:
        r = httpx.post(f"{self.gateway_url}/v1/odin/envelope", json=envelope, timeout=30)
        try:
            data = r.json()
        except Exception:
            raise RuntimeError(f"Gateway returned non-JSON status={r.status_code}: {r.text[:200]}")
        if r.status_code != 200:
            raise RuntimeError(f"Gateway error {r.status_code}: {data}")
        headers = {k.lower(): v for k, v in r.headers.items()}
        self._verify_response(data, headers)
        if verify_chain:
            # Basic integrity: fetch chain and ensure last receipt hash matches
            trace = data.get("trace_id") or headers.get("x-odin-trace-id")
            if trace:
                chain = self.get_chain(trace)
                hops = chain.get("hops") or []
                if not hops:
                    raise VerificationError("Empty chain returned")
                last = hops[-1]
                if last.get("receipt_hash") != headers.get("x-odin-receipt-hash"):
                    raise VerificationError("Receipt hash mismatch vs chain tail")
        return data, headers

    def get_chain(self, trace_id: str) -> Dict[str, Any]:
        r = httpx.get(f"{self.gateway_url}/v1/receipts/hops/chain/{trace_id}", timeout=10)
        r.raise_for_status()
        return r.json()

    def export_bundle(self, trace_id: str) -> Dict[str, Any]:
        r = httpx.get(f"{self.gateway_url}/v1/receipts/export/{trace_id}", timeout=15)
        r.raise_for_status()
        return r.json()

    # -------- Higher level verification helpers --------
    def verify_export_bundle(self, bundle: Dict[str, Any]) -> bool:
        bundle_obj = bundle.get("bundle") or bundle
        receipts = bundle_obj.get("receipts") or []
        prev = None
        for i, rcp in enumerate(receipts):
            # Re-hash receipt excluding signature
            r_copy = dict(rcp)
            r_copy.pop("receipt_signature", None)
            local_hash = hashlib.sha256(canonical_json(r_copy)).hexdigest()
            if local_hash != rcp.get("receipt_hash"):
                raise VerificationError(f"Receipt hash mismatch at index {i}")
            if prev and rcp.get("prev_receipt_hash") != prev.get("receipt_hash"):
                raise VerificationError(f"Chain link mismatch at index {i}")
            prev = rcp
        return True
