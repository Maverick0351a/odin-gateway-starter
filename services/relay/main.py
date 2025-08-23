import asyncio
import ipaddress
import json
import logging
import os
import pathlib
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2] / "packages"))
from odin_core import PolicyEngine, cid_sha256, now_ts_iso  # noqa: E402
from odin_core.signer import load_signer  # noqa: E402

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("odin.relay")

_REGISTRY = CollectorRegistry()
RREQS = Counter("odin_relay_requests_total", "Relay requests", ["status"], registry=_REGISTRY)
RTIME = Histogram("odin_relay_processing_seconds", "Relay processing seconds", registry=_REGISTRY)

RELAY_ALLOWLIST = os.getenv("RELAY_ALLOWLIST", "")
policy_engine = PolicyEngine(allowlist_hosts=[h.strip() for h in RELAY_ALLOWLIST.split(",") if h.strip()])

_signer = load_signer()
RELAY_KID = os.getenv("ODIN_RELAY_KID", _signer.kid())

app = FastAPI(title="ODIN Relay", version="0.3.0")

def _is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved
    except Exception:
        return True

async def _resolve_block_private(host: str) -> None:
    try:
            loop = asyncio.get_event_loop()
            infos: List[Tuple[int, int, int, str, Tuple[str, int]]] = await loop.getaddrinfo(host, None)  # type: ignore[assignment]
            for family, _stype, _proto, _canon, sockaddr in infos:
                ip = sockaddr[0]  # type: ignore[index]
            if _is_private_ip(ip):
                raise HTTPException(403, detail=f"SSRF defense: private/reserved IP blocked for host {host}")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, detail=f"DNS resolve failed for {host}")

from pydantic import BaseModel  # noqa: E402


class RelayRequest(BaseModel):
    trace_id: str
    target_url: str
    method: str = "POST"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Any] = None
    oidc_audience: Optional[str] = None

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)

@app.post("/v1/relay")
async def relay(req: RelayRequest):
    """Relay an HTTP request to an allowed egress target with SSRF and policy checks.

    Manual timing used instead of Histogram decorator to support async.
    """
    _t0 = time.perf_counter()
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.hostname
    if not host:
        RREQS.labels(status="bad_url").inc()
        raise HTTPException(400, detail="Invalid target_url")
    await _resolve_block_private(host)
    tenant_key = None  # Future: derive from headers if passed through
    hel = policy_engine.check_http_egress(host, tenant_key=tenant_key)
    if not hel.passed:
        RREQS.labels(status="policy_block").inc()
        raise HTTPException(403, detail=f"Egress blocked: {hel.reasons}")

    headers = dict(req.headers or {})
    if req.oidc_audience:
        try:
            import google.auth.transport.requests
            import google.oauth2.id_token
            auth_req = google.auth.transport.requests.Request()
            token = google.oauth2.id_token.fetch_id_token(auth_req, req.oidc_audience)
            headers.setdefault("Authorization", f"Bearer {token}")
        except Exception as e:
            logger.warning(f"OIDC injection failed: {e}")

    method = req.method.upper()
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.request(method, req.target_url, headers=headers, json=req.body)
            content_type = resp.headers.get("content-type", "")
            try:
                body = resp.json() if "application/json" in content_type else resp.text
            except Exception:
                body = resp.text
            out = {
                "status_code": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items() if k.lower() in ("content-type", "date")},
                "body": body,
            }
    except Exception as e:
        RREQS.labels(status="upstream_error").inc()
        raise HTTPException(502, detail=f"Upstream error: {e}")

    body_bytes = json.dumps(out, sort_keys=True, separators=(",", ":")).encode("utf-8")
    resp_cid = cid_sha256(body_bytes)
    ts = now_ts_iso()
    sig = _signer.sign(f"{resp_cid}|{req.trace_id}|{ts}".encode("utf-8"))

    headers_out = {
        "X-ODIN-Trace-Id": req.trace_id,
        "X-ODIN-Response-CID": resp_cid,
        "X-ODIN-Signature": sig,
        "X-ODIN-KID": RELAY_KID,
    }
    RREQS.labels(status="ok").inc()
    duration = time.perf_counter() - _t0
    try:
        RTIME.observe(duration)
    except Exception:
        pass
    return JSONResponse(jsonable_encoder(out), headers=headers_out)
