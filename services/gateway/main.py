import os, json, logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
import httpx
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
import time
from cryptography.hazmat.primitives import serialization
import hmac, hashlib

import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[2] / "packages"))

from odin_core import (
    load_or_create_private_key, sign_bytes, verify_with_jwk,
    cid_sha256, now_ts_iso, gen_trace_id, transform_payload, SFTError,
    PolicyEngine, build_receipt, ReceiptStore, b64u_encode, canonical_json
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("odin.gateway")

_REGISTRY = CollectorRegistry()
REQS = Counter("odin_gateway_requests_total", "Gateway envelope requests", ["status"], registry=_REGISTRY)
PROC = Histogram("odin_gateway_processing_seconds", "Gateway envelope processing seconds", registry=_REGISTRY)

ODIN_GATEWAY_PRIVATE_KEY_B64 = os.getenv("ODIN_GATEWAY_PRIVATE_KEY_B64")
priv_key, env_kid = load_or_create_private_key(ODIN_GATEWAY_PRIVATE_KEY_B64)
GATEWAY_KID = os.getenv("ODIN_GATEWAY_KID", env_kid)

pub_raw = priv_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
GATEWAY_JWK = {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(pub_raw), "kid": GATEWAY_KID}

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

policy_engine = PolicyEngine()
store = ReceiptStore()

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

app = FastAPI(title="ODIN Gateway", version="0.3.0")

@app.get("/.well-known/jwks.json")
def jwks():
    keys = []
    active = dict(GATEWAY_JWK)
    active.setdefault("status", "active")
    keys.append(active)
    addl = _load_additional_jwks()
    if addl:
        for k in addl.get("keys", []):
            if isinstance(k, dict):
                k2 = dict(k)
                k2.setdefault("status", "legacy")
                keys.append(k2)
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
    sig = sign_bytes(priv_key, f"{bundle_cid}|{trace_id}|{exported_at}".encode("utf-8"))
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
    # Enforce API key + HMAC when configured
    if API_KEY_SECRETS:
        if not api_key or api_key not in API_KEY_SECRETS:
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Missing or unknown API key")
        mac_header = request.headers.get("x-odin-api-mac")
        if not mac_header:
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Missing X-ODIN-API-MAC header")
        # Compute expected HMAC over the same message used by the sender signature
        expected = hmac.new(API_KEY_SECRETS[api_key].encode(), message, hashlib.sha256).digest()
        exp_b64u = b64u_encode(expected)
        if not hmac.compare_digest(exp_b64u, mac_header):
            REQS.labels(status="unauthorized").inc()
            raise HTTPException(401, detail="Bad API key MAC")
    if ope.forward_url:
        try:
            host = httpx.URL(ope.forward_url).host
        except Exception:
            raise HTTPException(400, detail="Invalid forward_url")
        hel = policy_engine.check_http_egress(host, tenant_key=api_key)
        policy_result = {"passed": hel.passed, "rules": [{"rule": hel.rule, "reasons": hel.reasons}]}
        if not hel.passed:
            REQS.labels(status="policy_block").inc()
            raise HTTPException(403, detail=f"Egress blocked by policy: {hel.reasons}")

    chain = store.get_chain(ope.trace_id)
    prev_hash = chain[-1].get("receipt_hash") if chain else None
    receipt = build_receipt(
        priv=priv_key,
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
    sig = sign_bytes(priv_key, f"{resp_cid}|{ope.trace_id}|{receipt['ts']}".encode("utf-8"))

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
