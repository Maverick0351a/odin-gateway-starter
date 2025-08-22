from dataclasses import dataclass
from typing import List, Dict, Set, Optional
import os, json
@dataclass
class HELResult:
    passed: bool
    rule: str
    reasons: List[str]
class PolicyEngine:
    def __init__(self, allowlist_hosts: List[str] | None = None, tenant_allowlists: Optional[Dict[str, List[str]]] = None):
        if allowlist_hosts is None:
            env = os.getenv("HEL_ALLOWLIST", "")
            # Decode placeholder for '/' (CIDR) if present from deploy encoding
            env = env.replace("__SL__", "/")
            allowlist_hosts = [h.strip() for h in env.split(",") if h.strip()]
        self.allowlist: Set[str] = set(allowlist_hosts)
        if tenant_allowlists is None:
            raw = os.getenv("HEL_TENANT_ALLOWLISTS", "")
            parsed: Dict[str, List[str]] = {}
            if raw.strip():
                try:
                    parsed = json.loads(raw)
                except Exception:
                    pass
            tenant_allowlists = parsed
        self.tenant_allowlists: Dict[str, Set[str]] = {k: set(v) for k, v in (tenant_allowlists or {}).items()}

    def check_http_egress(self, host: str, tenant_key: Optional[str] = None) -> HELResult:
        reasons: List[str] = []
        allowed_hosts = set(self.allowlist)
        if tenant_key and tenant_key in self.tenant_allowlists:
            allowed_hosts |= self.tenant_allowlists[tenant_key]
            reasons.append(f"tenant {tenant_key} allowlist applied")
        if host in allowed_hosts:
            reasons.append(f"host {host} allowed")
            return HELResult(True, "HEL:HTTP_EGRESS_LIMITATION", reasons)
        reasons.append(f"host {host} not in allowlist")
        return HELResult(False, "HEL:HTTP_EGRESS_LIMITATION", reasons)
