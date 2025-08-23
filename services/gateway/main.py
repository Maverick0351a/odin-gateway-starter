import os, json, logging
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
import httpx
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
import time
from cryptography.hazmat.primitives import serialization
import hmac, hashlib

import sys, pathlib
# Robustly add any ancestor ./packages directory to sys.path for CI/import resilience
for anc in pathlib.Path(__file__).resolve().parents:
    cand = anc / 'packages'
    if (cand / 'odin_core' / 'control.py').exists():
        p = str(cand)
        if p not in sys.path:
            sys.path.insert(0, p)
        break

from odin_core import (
    verify_with_jwk,
    cid_sha256, now_ts_iso, gen_trace_id, transform_payload, SFTError,
    PolicyManager, build_receipt, ReceiptStore, b64u_encode, canonical_json
)
from odin_core.signer import load_signer
try:
    from odin_core.control import ControlPlane  # direct module import
except Exception as _cp_err:  # noqa
    # Fallback: manual spec load if standard import failed for any reason
    # Re-run ancestor scan (defensive)
    spec_dir = None
    for anc in pathlib.Path(__file__).resolve().parents:
        cand = anc / 'packages' / 'odin_core'
        if (cand / 'control.py').exists():
            spec_dir = cand
            break
    if spec_dir is None:
        raise ImportError(f"ControlPlane module not located via ancestor scan: {_cp_err}")
    ctrl_file = spec_dir / 'control.py'
    if ctrl_file.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location('odin_core.control', ctrl_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore
            ControlPlane = getattr(module, 'ControlPlane')  # type: ignore
        else:
            raise ImportError(f"Unable to load ControlPlane (spec failure): {_cp_err}")
    else:
        raise ImportError(f"ControlPlane module not found at {ctrl_file}: {_cp_err}")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("odin.gateway")

_REGISTRY = CollectorRegistry()
REQS = Counter("odin_gateway_requests_total", "Gateway envelope requests", ["status"], registry=_REGISTRY)
PROC = Histogram("odin_gateway_processing_seconds", "Gateway envelope processing seconds", registry=_REGISTRY)

_signer = load_signer()
GATEWAY_KID = _signer.kid()
GATEWAY_JWK = _signer.public_jwk()

def _load_additional_jwks():
    raw = os.getenv("ODIN_ADDITIONAL_PUBLIC_JWKS")
    if not raw:
        return None
    try:
        import json as _json
        jwks = _json.loads(raw)
        if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
            return jwks
    except Exception as e:
        logger.warning(f"Failed parsing ODIN_ADDITIONAL_PUBLIC_JWKS: {e}")
    return None

policy_engine = PolicyManager()
store = ReceiptStore()
control_plane = ControlPlane()
rate_limiter = control_plane.rate_limiter()

ADMIN_TOKEN = os.getenv("ODIN_ADMIN_TOKEN")
REQUIRE_API_KEY = os.getenv("ODIN_REQUIRE_API_KEY", "0").lower() in ("1", "true", "yes")

# Optional API key + HMAC auth
def _load_api_key_secrets():
    raw = os.getenv("ODIN_API_KEY_SECRETS")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            # { api_key: secret_string }
            return {str(k): str(v) for k,v in data.items()}
    except Exception as e:
        logger.warning(f"Failed parsing ODIN_API_KEY_SECRETS: {e}")
    return {}

API_KEY_SECRETS = _load_api_key_secrets()

RELAY_URL = os.getenv("RELAY_URL")

class Sender(BaseModel):
    kid: Optional[str] = None
    jwk: Optional[Dict[str, Any]] = None
    jwks_uri: Optional[str] = None

class OPE(BaseModel):
    trace_id: str = Field(default_factory=gen_trace_id)
    ts: str = Field(default_factory=now_ts_iso)
    sender: Sender
    payload: Dict[str, Any]
    payload_type: str = "invoice.vendor.v1"
    target_type: str = "invoice.iso20022.v1"
    cid: Optional[str] = None
    signature: str
    forward_url: Optional[str] = None

app = FastAPI(title="ODIN Gateway", version="0.3.1")

# Optional CORS (comma-separated origins)
_cors_origins = os.getenv("CORS_ALLOW_ORIGINS")
if _cors_origins:
    origins = [o.strip() for o in _cors_origins.split(',') if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET","POST","OPTIONS"],
            allow_headers=["*"]
        )

@app.get("/.well-known/jwks.json")
def jwks():
    keys: List[Dict[str, Any]] = []
    active = dict(GATEWAY_JWK)
    active.setdefault("status", "active")
    keys.append(active)
    # Legacy / additional from env
    addl = _load_additional_jwks()
    if addl:
        for k in addl.get("keys", []):
            if isinstance(k, dict):
                k2 = dict(k)
                k2.setdefault("status", "legacy")
                keys.append(k2)
    # Control plane signer rotation legacy seeds (derive public key, never expose seed)
    signer = control_plane.data.get("signer", {})
    for legacy in signer.get("legacy", []):
        kid = legacy.get("kid")
        seed_b64 = legacy.get("seed_b64")
        if not kid or not seed_b64:
            continue
        try:
            import base64
            seed = base64.urlsafe_b64decode(seed_b64 + "=" * (-len(seed_b64) % 4))
            if len(seed) != 32:
                continue
            pk = Ed25519PrivateKey.from_private_bytes(seed).public_key()
            pub_raw = pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            keys.append({"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(pub_raw), "kid": kid, "status": "legacy"})
        except Exception:
            continue
    return {"keys": keys}

@app.get("/healthz")
def healthz():
    return {"status": "ok", "kid": GATEWAY_KID, "receipts": store.health()}

# Convenience alias some platforms expect /health
@app.get("/health")
def health_alias():
    return healthz()

@app.get("/metrics")
def metrics():
    return Response(generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)

@app.get("/v1/receipts/hops/chain/{trace_id}")
def get_chain(trace_id: str):
    chain = store.get_chain(trace_id)
    return JSONResponse(jsonable_encoder({"trace_id": trace_id, "hops": chain}))

@app.get("/v1/receipts/export/{trace_id}")
def export_chain(trace_id: str):
    """Export the full receipt chain for a trace_id as a signed bundle.

    Returns:
      bundle: { trace_id, exported_at, gateway_kid, receipts:[...], chain_valid: bool }
      bundle_cid: sha256 CID of canonical bundle JSON
      bundle_signature: gateway signature over pattern "{bundle_cid}|{trace_id}|{exported_at}" (base64url)
    """
    chain = store.get_chain(trace_id)
    # Validate link integrity
    chain_valid = True
    prev = None
    for r in chain:
        if prev and r.get("prev_receipt_hash") != prev.get("receipt_hash"):
            chain_valid = False
            break
        prev = r
    exported_at = now_ts_iso()
    bundle = {
        "trace_id": trace_id,
        "exported_at": exported_at,
        "gateway_kid": GATEWAY_KID,
        "receipts": chain,
        "chain_valid": chain_valid,
        "count": len(chain),
    }
    bundle_bytes = canonical_json(bundle)
    bundle_cid = cid_sha256(bundle_bytes)
    # Gateway signs the export bundle using active signer abstraction
    sig = _signer.sign(f"{bundle_cid}|{trace_id}|{exported_at}".encode("utf-8"))
    resp = {"bundle": bundle, "bundle_cid": bundle_cid, "bundle_signature": sig}
    headers = {"X-ODIN-Bundle-CID": bundle_cid, "X-ODIN-KID": GATEWAY_KID, "X-ODIN-Bundle-Signature": sig}
    return JSONResponse(jsonable_encoder(resp), headers=headers)

@app.post("/v1/odin/envelope")
async def accept_envelope(ope: OPE, request: Request):
    """Accept an OPE envelope, verify signature, normalize payload, enforce policy, optionally relay, return receipt.

    Prometheus manual timing is used instead of the Histogram decorator because the latter
    doesn't support awaiting async callables and was returning an un-awaited coroutine in tests.
    """
    _t0 = time.perf_counter()
    payload_bytes = json.dumps(ope.payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    cid = cid_sha256(payload_bytes)
    if ope.cid and ope.cid != cid:
        REQS.labels(status="bad_cid").inc()
        raise HTTPException(400, detail="CID does not match payload")
    ope.cid = cid

    message = f"{cid}|{ope.trace_id}|{ope.ts}".encode("utf-8")
    sender_jwk = None

    if ope.sender and ope.sender.jwk:
        sender_jwk = ope.sender.jwk
    elif ope.sender and ope.sender.jwks_uri:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(ope.sender.jwks_uri)
                resp.raise_for_status()
                jwks = resp.json()
                keys = jwks.get("keys", [])
                if ope.sender.kid:
                    for k in keys:
                        if k.get("kid") == ope.sender.kid:
                            sender_jwk = k
                            break
                if not sender_jwk and keys:
                    sender_jwk = keys[0]
        except Exception as e:
            REQS.labels(status="jwks_error").inc()
            raise HTTPException(400, detail=f"Failed to fetch/parse sender JWKS: {e}")
    else:
        REQS.labels(status="no_key").inc()
        raise HTTPException(400, detail="No sender JWK or JWKS URI provided")

    if not verify_with_jwk(sender_jwk, message, ope.signature):
        REQS.labels(status="bad_sig").inc()
        raise HTTPException(400, detail="Invalid signature")

    try:
        normalized_payload, sft_notes = transform_payload(ope.payload, ope.payload_type, ope.target_type)
    except SFTError as e:
        REQS.labels(status="sft_error").inc()
        raise HTTPException(400, detail=str(e))
    normalized_cid = cid_sha256(json.dumps(normalized_payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    policy_result = {"passed": True, "rules": []}
    forwarded = None
    api_key = request.headers.get("x-odin-api-key") or request.headers.get("x-api-key")
    tenant_ctx = None
    if api_key:
        # Prefer control plane resolution when available
        tenant_ctx = control_plane.resolve_api_key(api_key)
        # If auth not required and api_key looks like a tenant id present in control plane, synthesize context (no secret)
        if not tenant_ctx and api_key in control_plane.data.get("tenants", {}) and not auth_required:
            t = control_plane.data["tenants"][api_key]
            tenant_ctx = {"tenant_id": api_key, "secret": None, "rate_limit_rpm": t.get("rate_limit_rpm",0), "allowlist": t.get("allowlist", [])}
    # Decide if auth is required: explicit legacy env keys OR flag OR control plane keys + flag
    # Evaluate requirement dynamically so tests can toggle via environment between runs
    require_flag = os.getenv("ODIN_REQUIRE_API_KEY", "0").lower() in ("1", "true", "yes")
    auth_required = bool(API_KEY_SECRETS) or (require_flag and control_plane.data.get("tenants"))
    if auth_required:
        if not api_key:
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Missing API key")
        secret = None
        if tenant_ctx:
            secret = tenant_ctx.get("secret")
        elif api_key in API_KEY_SECRETS:
            secret = API_KEY_SECRETS[api_key]
        if not secret:
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Unknown API key")
        mac_header = request.headers.get("x-odin-api-mac")
        if not mac_header:
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Missing X-ODIN-API-MAC header")
        expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        if not hmac.compare_digest(b64u_encode(expected), mac_header):
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Bad API key MAC")
        # Rate limiting (per tenant when available; else per key)
        if tenant_ctx:
            rpm = tenant_ctx.get("rate_limit_rpm", 0) or 0
            if rpm > 0 and not rate_limiter.check(tenant_ctx["tenant_id"], rpm):
                REQS.labels(status="rate_limited").inc()
                raise HTTPException(429, detail="Rate limit exceeded")
    if ope.forward_url:
        try:
            host = httpx.URL(ope.forward_url).host
        except Exception:
            raise HTTPException(400, detail="Invalid forward_url")
        hel = policy_engine.check_http_egress(host)
        # Augment with tenant allowlist if policy failed and tenant context exists
        if not hel.passed and tenant_ctx and host in (tenant_ctx.get("allowlist") or []):
            hel = type(hel)(passed=True, rule=hel.rule, reasons=hel.reasons + [f"tenant allowlist host {host} allowed"])
        policy_result = {"passed": hel.passed, "rules": [{"rule": hel.rule, "reasons": hel.reasons}]}
        if not hel.passed:
            REQS.labels(status="policy_block").inc()
            raise HTTPException(403, detail=f"Egress blocked by policy: {hel.reasons}")

    chain = store.get_chain(ope.trace_id)
    prev_hash = chain[-1].get("receipt_hash") if chain else None
    receipt = build_receipt(
        signer=_signer,
        trace_id=ope.trace_id,
        hop_index=len(chain),
        request_cid=cid,
        normalized_cid=normalized_cid,
        policy_result=policy_result,
        gateway_kid=GATEWAY_KID,
        prev_receipt_hash=prev_hash,
    )
    store.add_receipt(receipt)

    if ope.forward_url and RELAY_URL:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                relay_resp = await client.post(f"{RELAY_URL}/v1/relay", json={
                    "trace_id": ope.trace_id,
                    "target_url": ope.forward_url,
                    "method": "POST",
                    "body": normalized_payload,
                })
                forwarded = {
                    "status_code": relay_resp.status_code,
                    "body": relay_resp.json() if "application/json" in relay_resp.headers.get("content-type", "") else relay_resp.text,
                }
        except Exception as e:
            forwarded = {"error": str(e)}

    resp_body = {
        "trace_id": ope.trace_id,
        "receipt": receipt,
        "normalized_payload": normalized_payload,
        "sft_notes": sft_notes,
        "forwarded": forwarded,
    }
    body_bytes = json.dumps(resp_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    resp_cid = cid_sha256(body_bytes)
    sig = _signer.sign(f"{resp_cid}|{ope.trace_id}|{receipt['ts']}".encode("utf-8"))

    headers = {
        "X-ODIN-Trace-Id": ope.trace_id,
        "X-ODIN-Receipt-Hash": receipt["receipt_hash"],
        "X-ODIN-Response-CID": resp_cid,
        "X-ODIN-Signature": sig,
        "X-ODIN-KID": GATEWAY_KID,
    }

    REQS.labels(status="ok").inc()
    duration = time.perf_counter() - _t0
    try:
        PROC.observe(duration)
    except Exception:
        pass
    encoded = jsonable_encoder(resp_body)
    return JSONResponse(encoded, headers=headers)

# ---------------- Admin API -----------------

def _admin_auth(request: Request):
    if not ADMIN_TOKEN:
        raise HTTPException(403, detail="Admin API disabled (no ODIN_ADMIN_TOKEN set)")
    token = request.headers.get("x-admin-token")
    if token != ADMIN_TOKEN:
        raise HTTPException(401, detail="Invalid admin token")

@app.get("/v1/admin/tenants")
def admin_list_tenants(request: Request):
    _admin_auth(request)
    return {"tenants": control_plane.list_tenants()}

@app.post("/v1/admin/tenants")
async def admin_create_tenant(request: Request):
    _admin_auth(request)
    body = await request.json()
    tenant_id = body.get("tenant_id")
    name = body.get("name")
    if not tenant_id:
        raise HTTPException(400, detail="tenant_id required")
    try:
        t = control_plane.create_tenant(tenant_id, name=name)
        return t
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

@app.get("/v1/admin/tenants/{tenant_id}")
def admin_get_tenant(tenant_id: str, request: Request):
    _admin_auth(request)
    t = control_plane.get_tenant(tenant_id)
    if not t:
        raise HTTPException(404, detail="not found")
    return t

@app.patch("/v1/admin/tenants/{tenant_id}")
async def admin_update_tenant(tenant_id: str, request: Request):
    _admin_auth(request)
    body = await request.json()
    try:
        t = control_plane.update_tenant(tenant_id, **body)
        return t
    except ValueError as e:
        raise HTTPException(404, detail=str(e))

@app.delete("/v1/admin/tenants/{tenant_id}")
def admin_delete_tenant(tenant_id: str, request: Request):
    _admin_auth(request)
    ok = control_plane.delete_tenant(tenant_id)
    if not ok:
        raise HTTPException(404, detail="not found")
    return {"deleted": True}

@app.post("/v1/admin/tenants/{tenant_id}/keys")
def admin_issue_key(tenant_id: str, request: Request):
    _admin_auth(request)
    try:
        rec = control_plane.issue_key(tenant_id)
        return rec
    except ValueError:
        raise HTTPException(404, detail="tenant not found")

@app.post("/v1/admin/tenants/{tenant_id}/keys/{key}/revoke")
def admin_revoke_key(tenant_id: str, key: str, request: Request):
    _admin_auth(request)
    ok = control_plane.revoke_key(tenant_id, key)
    if not ok:
        raise HTTPException(404, detail="not found")
    return {"revoked": True}
