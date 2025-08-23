import base64
import hashlib
import json
import os
from typing import Any, Dict, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

HOSTED_VERIFY_BASE_URL = os.getenv("HOSTED_VERIFY_BASE_URL")  # optional external canonical URL
app = FastAPI(title="ODIN Dashboard", version="0.2.0")
BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

def b64u_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def canonical(obj) -> bytes:
    import json as _json
    return _json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

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

GATEWAY_URL_DEFAULT = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, gateway_url: Optional[str] = None, trace_id: Optional[str] = None):
    gw = gateway_url or GATEWAY_URL_DEFAULT
    return templates.TemplateResponse("index.html", {"request": request, "gateway_url": gw, "trace_id": trace_id or "", "hosted_base": HOSTED_VERIFY_BASE_URL})

@app.get("/trace/{trace_id}", response_class=HTMLResponse)
async def view_trace(trace_id: str, request: Request, gateway_url: Optional[str] = None):
    gw = (gateway_url or GATEWAY_URL_DEFAULT).rstrip('/')
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{gw}/v1/receipts/hops/chain/{trace_id}")
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        raise HTTPException(502, f"Failed to fetch chain: {e}")
    chain = data.get("hops", [])
    # Recompute linkage
    enriched = []
    prev_hash = None
    all_ok = True
    for idx, hop in enumerate(chain):
        local_hash = compute_receipt_hash(hop)
        hash_ok = (local_hash == hop.get("receipt_hash"))
        link_ok = (idx == 0) or (hop.get("prev_receipt_hash") == prev_hash)
        hop_ok = (hop.get("hop") == idx)
        if not (hash_ok and link_ok and hop_ok):
            all_ok = False
        enriched.append({"hop": hop, "hash_ok": hash_ok, "link_ok": link_ok, "hop_ok": hop_ok})
        prev_hash = hop.get("receipt_hash")
    return templates.TemplateResponse("trace.html", {"request": request, "gateway_url": gw, "trace_id": trace_id, "chain": enriched, "all_ok": all_ok})

@app.get("/export/{trace_id}", response_class=HTMLResponse)
async def view_export(trace_id: str, request: Request, gateway_url: Optional[str] = None):
    gw = (gateway_url or GATEWAY_URL_DEFAULT).rstrip('/')
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            exp = await client.get(f"{gw}/v1/receipts/export/{trace_id}")
        exp.raise_for_status()
    except Exception as e:
        raise HTTPException(502, f"Failed to fetch export: {e}")
    headers = {k.lower(): v for k,v in exp.headers.items()}
    body = exp.json()
    bundle = body.get("bundle") or body
    chain = bundle.get("receipts") or body.get("receipts") or []
    # Chain verification
    chain_ok = True
    prev = None
    for i, rcp in enumerate(chain):
        if compute_receipt_hash(rcp) != rcp.get("receipt_hash"):
            chain_ok = False
            break
        if i > 0 and rcp.get("prev_receipt_hash") != prev.get("receipt_hash"):
            chain_ok = False
            break
        prev = rcp
    # Bundle CID (canonical deterministic ordering)
    canonical_bytes = canonical(bundle)
    local_bundle_cid = "sha256:" + sha256_hex(canonical_bytes)
    bundle_cid_hdr = headers.get("x-odin-bundle-cid") or headers.get("x-odin-response-cid")
    cid_ok = (bundle_cid_hdr == local_bundle_cid) if bundle_cid_hdr else True

    # Signature verification (attempt known message formats)
    sig = headers.get("x-odin-bundle-signature") or headers.get("x-odin-signature")
    kid = headers.get("x-odin-kid")
    sig_ok = False
    # sig_error retained earlier only for debugging; remove assignment to satisfy lint
    verified_format = None
    attempted_formats = []
    if sig and kid:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                jwks = (await client.get(f"{gw}/.well-known/jwks.json")).json()
            jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
            if jwk:
                exported_at = bundle.get("exported_at") or bundle.get("ts")
                candidates: Dict[str, bytes] = {}
                if exported_at:
                    candidates["cid|trace|exported_at"] = f"{local_bundle_cid}|{trace_id}|{exported_at}".encode("utf-8")
                candidates["cid-only"] = local_bundle_cid.encode("utf-8")
                for label, msg_bytes in candidates.items():
                    attempted_formats.append(label)
                    if verify_sig_with_jwk(jwk, msg_bytes, sig):
                        sig_ok = True
                        verified_format = label
                        break
        except Exception:
            pass
    status = {
        "chain_ok": chain_ok,
        "cid_match": cid_ok,
        "sig_ok": sig_ok,
        "sig_variant": verified_format,
    }
    return templates.TemplateResponse("export.html", {
        "request": request,
        "gateway_url": gw,
        "trace_id": trace_id,
        "bundle": bundle,
        "status": status,
        "resp_cid_computed": local_bundle_cid,
        "resp_cid_header": bundle_cid_hdr,
        "kid": kid,
    })

# --- Hosted Verify JSON APIs ---

def _verify_bundle(bundle: dict, kid: Optional[str], jwk: Optional[dict], trace_id: str, signature: Optional[str]) -> Dict[str, Any]:
    receipts = bundle.get("receipts", [])
    # Chain + hash validation
    chain_ok = True
    prev = None
    for i, r in enumerate(receipts):
        if compute_receipt_hash(r) != r.get("receipt_hash"):
            chain_ok = False
            break
        if i and r.get("prev_receipt_hash") != prev.get("receipt_hash"):
            chain_ok = False
            break
        # hop ordering check (defensive; hop may be int index)
        if r.get("hop") != i:
            chain_ok = False
            break
        prev = r
    # CID over full bundle (excluding no fields; spec v1 uses entire bundle w/out signature field)
    canonical_bytes = canonical(bundle)
    bundle_cid = "sha256:" + sha256_hex(canonical_bytes)
    sig_ok = False
    sig_variant = None
    if signature and jwk:
        exported_at = bundle.get("exported_at") or bundle.get("ts") or ""
        candidates = {
            "cid|trace|exported_at": f"{bundle_cid}|{trace_id}|{exported_at}".encode("utf-8"),
            "cid-only": bundle_cid.encode("utf-8"),
        }
        for label, msg in candidates.items():
            if verify_sig_with_jwk(jwk, msg, signature):
                sig_ok = True
                sig_variant = label
                break
    return {
        "trace_id": trace_id,
        "bundle_cid": bundle_cid,
        "chain_ok": chain_ok,
        "sig_ok": sig_ok,
        "sig_variant": sig_variant,
        "count": len(receipts),
    }

@app.get("/verify/{trace_id}")
async def verify_trace(trace_id: str, gateway_url: Optional[str] = None):
    """Fetch export bundle from gateway and verify locally (JSON API)."""
    gw = (gateway_url or GATEWAY_URL_DEFAULT).rstrip('/')
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{gw}/v1/receipts/export/{trace_id}")
            resp.raise_for_status()
            data = resp.json()
            jwks = (await client.get(f"{gw}/.well-known/jwks.json")).json()
    except Exception as e:
        raise HTTPException(502, f"Fetch failed: {e}")
    bundle = data.get("bundle") or data
    kid = data.get("bundle", {}).get("gateway_kid") or bundle.get("gateway_kid")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    sig = data.get("bundle_signature") or data.get("signature")
    result = _verify_bundle(bundle, kid, jwk, trace_id, sig)
    result.update({
        "gateway_kid": kid,
        "signature": sig,
    })
    return JSONResponse(result)

@app.post("/verify/bundle")
async def verify_bundle_upload(file: UploadFile = File(...), kid: Optional[str] = None, gateway_url: Optional[str] = None, signature: Optional[str] = None):
    """Upload a bundle JSON file and optionally resolve JWKS to verify signature."""
    try:
        raw = await file.read()
        bundle = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise HTTPException(400, f"Invalid JSON: {e}")
    jwk = None
    if gateway_url and kid:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                jwks = (await client.get(f"{gateway_url.rstrip('/')}/.well-known/jwks.json")).json()
            jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        except Exception:
            jwk = None
    trace_id = bundle.get("trace_id", "unknown")
    sig = signature or bundle.get("bundle_signature")
    result = _verify_bundle(bundle, kid, jwk, trace_id, sig)
    result.update({"gateway_kid": kid, "uploaded": True})
    return JSONResponse(result)
