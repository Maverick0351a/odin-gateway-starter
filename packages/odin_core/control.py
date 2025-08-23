"""Minimal in-memory ControlPlane stub for tests/CI.

Provides enough functionality for the gateway & tests without external storage.
Replace with a persistent implementation when ready.
"""
from __future__ import annotations

import datetime
import secrets
import threading
import time
from typing import Any, Dict, List, Optional


def ISO() -> str:  # noqa: N802 (keep uppercase helper name for brevity)
    """Return current UTC timestamp in ISO 8601 format with timezone (aware).

    Uses datetime.now(timezone.utc) instead of deprecated utcnow.
    """
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class ControlPlane:
    def __init__(self, path: Optional[str] = None):  # path ignored in stub
        self.data: Dict[str, Any] = {"tenants": {}, "signer": {"current": None, "legacy": []}}
        self._lock = threading.Lock()

    # ---------------- Tenant CRUD ----------------
    def list_tenants(self) -> List[Dict[str, Any]]:
        return [self._tenant_public(tid, t) for tid, t in self.data["tenants"].items()]

    def _tenant_public(self, tenant_id: str, t: Dict[str, Any]) -> Dict[str, Any]:
        pub = dict(t)
        pub["tenant_id"] = tenant_id
        pub["api_keys"] = [{k: v for k, v in ak.items() if k != "secret"} for ak in t.get("api_keys", [])]
        return pub

    def create_tenant(self, tenant_id: str, name: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if tenant_id in self.data["tenants"]:
                raise ValueError("tenant exists")
            self.data["tenants"][tenant_id] = {
                "name": name or tenant_id,
                "created_at": ISO(),
                "api_keys": [],
                "allowlist": [],
                "rate_limit_rpm": 0,  # 0 = unlimited
                "audit": {"forward_receipts": False, "forward_exports": False, "sink_type": None, "sink_config": {}},
                "status": "active",
                # Custody: mode in {odin, byok, gcpkms, awskms, azurekv}; signer_ref holds reference (e.g. key id / public jwk)
                "custody_mode": "odin",
                "signer_ref": None,  # for byok: public JWK; for kms: key resource / arn / url
            }
            return self._tenant_public(tenant_id, self.data["tenants"][tenant_id])

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        t = self.data["tenants"].get(tenant_id)
        return self._tenant_public(tenant_id, t) if t else None

    def update_tenant(self, tenant_id: str, **fields) -> Dict[str, Any]:
        with self._lock:
            t = self.data["tenants"].get(tenant_id)
            if not t:
                raise ValueError("not found")
            for k in ["name", "allowlist", "rate_limit_rpm", "audit", "status", "custody_mode", "signer_ref"]:
                if k in fields and fields[k] is not None:
                    t[k] = fields[k]
            return self._tenant_public(tenant_id, t)

    def delete_tenant(self, tenant_id: str) -> bool:
        with self._lock:
            return self.data["tenants"].pop(tenant_id, None) is not None

    # ---------------- API Keys ----------------
    def issue_key(self, tenant_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self.data["tenants"].get(tenant_id)
            if not t:
                raise ValueError("not found")
            key = "k_" + secrets.token_urlsafe(12)
            secret = "s_" + secrets.token_urlsafe(24)
            rec = {"key": key, "secret": secret, "active": True, "created_at": ISO()}
            t.setdefault("api_keys", []).append(rec)
            return rec

    def revoke_key(self, tenant_id: str, key: str) -> bool:
        with self._lock:
            t = self.data["tenants"].get(tenant_id)
            if not t:
                return False
            for ak in t.get("api_keys", []):
                if ak.get("key") == key:
                    ak["active"] = False
                    return True
            return False

    def resolve_api_key(self, key: str) -> Optional[Dict[str, Any]]:
        for tid, t in self.data["tenants"].items():
            for ak in t.get("api_keys", []):
                if ak.get("key") == key and ak.get("active"):
                    return {"tenant_id": tid, "secret": ak.get("secret"), "rate_limit_rpm": t.get("rate_limit_rpm", 0), "allowlist": t.get("allowlist", []), "audit": t.get("audit", {})}
        return None

    # ---------------- Signer Rotation (stub) ----------------
    def rotate_signer(self, current_seed_b64: str, current_kid: str):
        signer = self.data.setdefault("signer", {"current": None, "legacy": []})
        cur = signer.get("current")
        if cur:
            signer.setdefault("legacy", []).append(cur)
        signer["current"] = {"kid": current_kid, "seed_b64": current_seed_b64, "rotated_at": ISO()}
        return signer

    def jwk_overrides(self):  # legacy key metadata placeholder
        return []

    # ---------------- Rate Limiting ----------------
    def rate_limiter(self):
        return InMemoryRateLimiter()

class InMemoryRateLimiter:
    def __init__(self):
        # key -> (window_epoch_minute, count)
        self._buckets: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def check(self, key: str, rpm: int) -> bool:
        if rpm <= 0:
            return True
        now_min = int(time.time() // 60)
        with self._lock:
            win, cnt = self._buckets.get(key, (now_min, 0))
            if win != now_min:
                win, cnt = now_min, 0
            if cnt + 1 > rpm:
                self._buckets[key] = (win, cnt)
                return False
            cnt += 1
            self._buckets[key] = (win, cnt)
            return True
