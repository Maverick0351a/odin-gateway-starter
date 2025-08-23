from typing import Dict, Any, Optional, List
import hashlib
from .utils import canonical_json, now_ts_iso
from .signer import Signer
def _strip_sig_for_hash(r: Dict[str,Any]) -> Dict[str,Any]:
    d = dict(r); d.pop("receipt_signature", None); return d
def hash_receipt(receipt: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_strip_sig_for_hash(receipt))).hexdigest()
def build_receipt(*, signer: Signer, trace_id: str, hop_index: int, request_cid: str, normalized_cid: str, policy_result: Dict[str, Any], gateway_kid: str, prev_receipt_hash: Optional[str], policy_engine: Optional[str] = None, tenant_id: Optional[str] = None, tenant_signatures: Optional[List[Dict[str, str]]] = None):
    r = {
        "trace_id": trace_id,
        "hop": hop_index,
        "ts": now_ts_iso(),
        "created_at": now_ts_iso(),
        "gateway_kid": gateway_kid,
        "request_cid": request_cid,
        "normalized_cid": normalized_cid,
        "policy": policy_result,
        "policy_engine": policy_engine or policy_result.get("engine"),
        "prev_receipt_hash": prev_receipt_hash,
    }
    if tenant_id:
        r["tenant_id"] = tenant_id
    if tenant_signatures:
        # Each entry: {kid, sig, pattern}
        r["tenant_signatures"] = tenant_signatures
    # For backward compat the signer currently wraps Ed25519 seed; we sign the canonical receipt object.
    sig = signer.sign(canonical_json(r))
    r["receipt_signature"] = sig
    r["receipt_hash"] = hash_receipt(r)
    return r
