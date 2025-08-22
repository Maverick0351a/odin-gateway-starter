from typing import Dict, Any, Optional
import hashlib
from .utils import canonical_json, now_ts_iso
from .crypto import sign_bytes
def _strip_sig_for_hash(r: Dict[str,Any]) -> Dict[str,Any]:
    d = dict(r); d.pop("receipt_signature", None); return d
def hash_receipt(receipt: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_strip_sig_for_hash(receipt))).hexdigest()
def build_receipt(*, priv, trace_id: str, hop_index: int, request_cid: str, normalized_cid: str, policy_result: Dict[str, Any], gateway_kid: str, prev_receipt_hash: Optional[str]):
    r = {
        "trace_id": trace_id,
        "hop": hop_index,
        "ts": now_ts_iso(),
    "created_at": now_ts_iso(),
        "gateway_kid": gateway_kid,
        "request_cid": request_cid,
        "normalized_cid": normalized_cid,
        "policy": policy_result,
        "prev_receipt_hash": prev_receipt_hash,
    }
    sig = sign_bytes(priv, canonical_json(r))
    r["receipt_signature"] = sig
    r["receipt_hash"] = hash_receipt(r)
    return r
