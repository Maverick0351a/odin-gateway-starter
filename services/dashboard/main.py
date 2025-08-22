import os, json, hashlib, base64
from typing import Optional, Any, Dict
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

app = FastAPI(title="ODIN Dashboard", version="0.1.0")
BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

def b64u_decode(s: str) -> bytes:
    s = s.strip(); pad = "=" * (-len(s) % 4); return base64.urlsafe_b64decode(s + pad)

def canonical(obj) -> bytes:
    import json as _json
    return _json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def compute_receipt_hash(receipt: dict) -> str:
    r = dict(receipt); r.pop("receipt_signature", None)
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
    return templates.TemplateResponse("index.html", {"request": request, "gateway_url": gw, "trace_id": trace_id or ""})

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
        if not (hash_ok and link_ok):
            all_ok = False
        enriched.append({"hop": hop, "hash_ok": hash_ok, "link_ok": link_ok})
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
            chain_ok = False; break
        if i>0 and rcp.get("prev_receipt_hash") != prev.get("receipt_hash"):
            chain_ok = False; break
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
    sig_error = None
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
        except Exception as e:
            sig_error = str(e)
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
