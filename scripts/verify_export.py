import argparse
import base64
import hashlib
import json
import sys

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def b64u_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def compute_receipt_hash(receipt: dict) -> str:
    r = dict(receipt)
    r.pop("receipt_signature", None)
    return sha256_hex(canonical(r))

def verify_sig_with_jwk(jwk: dict, message: bytes, sig_b64u: str) -> bool:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
        pub.verify(b64u_decode(sig_b64u), message)
        return True
    except Exception:
        return False

def main():
    ap = argparse.ArgumentParser(description="Verify ODIN export bundle by trace_id")
    ap.add_argument("--url", default="http://127.0.0.1:8080", help="Gateway base URL")
    ap.add_argument("--trace-id", required=True, help="Trace ID to export and verify")
    args = ap.parse_args()

    exp = requests.get(f"{args.url}/v1/receipts/export/{args.trace_id}", timeout=15)
    if exp.status_code != 200:
        print(f"[FAIL] export returned {exp.status_code}: {exp.text}")
        sys.exit(2)

    data = exp.json()
    headers = {k.lower(): v for k, v in exp.headers.items()}
    resp_cid_hdr = headers.get("x-odin-response-cid")
    sig_hdr = headers.get("x-odin-signature")
    kid_hdr = headers.get("x-odin-kid")
    trace_hdr = headers.get("x-odin-trace-id") or data.get("trace_id") or args.trace_id

    chain = data.get("chain")
    if chain is None:
        chain = data.get("hops", [])
    if not isinstance(chain, list) or not chain:
        print("[FAIL] No chain/hops in export payload")
        sys.exit(2)

    for i, rcp in enumerate(chain):
        local_hash = compute_receipt_hash(rcp)
        if local_hash != rcp.get("receipt_hash"):
            print(f"[FAIL] receipt[{i}] hash mismatch: local={local_hash} != remote={rcp.get('receipt_hash')}")
            sys.exit(2)
        if i > 0:
            prev = chain[i-1]
            if rcp.get("prev_receipt_hash") != prev.get("receipt_hash"):
                print(f"[FAIL] chain broken at hop {i}: prev_receipt_hash does not match")
                sys.exit(2)
    print("[OK] chain linkage + receipt hashes verified")

    local_resp_cid = "sha256:" + sha256_hex(canonical(data))
    if resp_cid_hdr and local_resp_cid != resp_cid_hdr:
        print(f"[FAIL] response CID mismatch: {local_resp_cid} != {resp_cid_hdr}")
        sys.exit(2)
    print(f"[OK] response CID {local_resp_cid}")

    if not sig_hdr:
        print("[WARN] No X-ODIN-Signature header present; skipping signature verification")
        sys.exit(0)

    jwks = requests.get(f"{args.url}/.well-known/jwks.json", timeout=10).json()
    keys = jwks.get("keys", [])
    if not keys:
        print("[FAIL] No JWKS keys exposed by gateway")
        sys.exit(2)

    jwk = None
    if kid_hdr:
        for k in keys:
            if k.get("kid") == kid_hdr:
                jwk = k; break
    if jwk is None:
        jwk = keys[0]

    candidate_ts = []
    if "ts" in data: candidate_ts.append(data["ts"])
    if chain and "ts" in chain[-1]: candidate_ts.append(chain[-1]["ts"])
    candidate_ts = [t for i, t in enumerate(candidate_ts) if t and t not in candidate_ts[:i]]

    verified = False
    for ts in candidate_ts + [None]:
        if ts is None:
            msg = local_resp_cid.encode("utf-8")
        else:
            msg = f"{local_resp_cid}|{trace_hdr}|{ts}".encode("utf-8")
        if verify_sig_with_jwk(jwk, msg, sig_hdr):
            print(f"[OK] signature verified with KID={jwk.get('kid')} using {'cid|trace|ts' if ts else 'cid'} message format")
            verified = True
            break

    if not verified:
        print("[FAIL] signature verification failed with all candidate message formats")
        sys.exit(2)

if __name__ == "__main__":
    main()
