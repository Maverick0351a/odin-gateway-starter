from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Any, Callable
import os, json, subprocess, tempfile, textwrap, shutil
@dataclass
class HELResult:
    passed: bool
    rule: str
    reasons: List[str]
class PolicyEngine:
    """Legacy simple allowlist engine (HEL)."""
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


class RegoPolicyEngine:
    """Minimal external OPA Rego evaluator (optional).

    Evaluation contract:
      Rego package: odin.policy
      Rule: allow (boolean) and optionally reasons (array of strings)

    Input document fields we pass:
      host: egress host
      tenant: tenant id (if any)

    Configuration:
      ODIN_POLICY_REGO_PATH : path to a .rego file
      OPA_BIN               : custom opa binary (defaults 'opa' in PATH)

    If evaluation fails, falls back to deny (conservative) with reason."""
    def __init__(self, rego_path: str, opa_bin: str = "opa"):
        self._rego_path = rego_path
        self._opa_bin = opa_bin
        if not shutil.which(opa_bin):
            raise FileNotFoundError(f"OPA binary '{opa_bin}' not found in PATH")
        if not os.path.exists(rego_path):
            raise FileNotFoundError(f"Rego policy file not found: {rego_path}")

    def check_http_egress(self, host: str, tenant_key: Optional[str] = None) -> HELResult:
        # Build OPA eval input
        payload = {"input": {"host": host, "tenant": tenant_key}}
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                json.dump(payload, f)
                f.flush()
                cmd = [self._opa_bin, "eval", "-I", "--format=json", "-d", self._rego_path, "data.odin.policy"]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
                out = json.loads(proc.stdout)
                # Expect structure: result[0].expressions[0].value => object {allow: bool, reasons?: []}
                val = out.get("result", [{}])[0].get("expressions", [{}])[0].get("value", {})
                allow = bool(val.get("allow"))
                reasons = val.get("reasons") or []
                if not isinstance(reasons, list):
                    reasons = [str(reasons)]
                return HELResult(allow, "REGO:HTTP_EGRESS_LIMITATION", reasons)
        except Exception as e:
            return HELResult(False, "REGO:HTTP_EGRESS_LIMITATION", [f"rego_error:{e}"])


class PolicyManager:
    """Facade selecting HEL allowlist, canned profile, or Rego policy.

    Precedence:
      1. If ODIN_POLICY_PROFILE is set to one of (strict, medium, open) use built-in profile.
      2. Else if ODIN_POLICY_REGO_PATH set → RegoPolicyEngine.
      3. Else HEL allowlist.

    Canned profiles (host allowlist semantics):
      strict: only hosts in HEL_ALLOWLIST (or none if empty)
      medium: allow common finance domains + HEL_ALLOWLIST
      open: allow any host (pass-through) unless explicitly denied later.
    """
    PROFILE_FINANCE_HOSTS = {"api.bank.com", "payments.bank.com"}

    def __init__(self):
        profile = os.getenv("ODIN_POLICY_PROFILE", "").lower().strip()
        rego = os.getenv("ODIN_POLICY_REGO_PATH") if not profile else None
        self.profile = profile or None
        if profile in ("strict", "medium", "open"):
            if profile == "open":
                # open profile: trivial pass engine
                self._engine = _AlwaysAllowEngine()
            else:
                # Build allowlist: medium adds finance hosts
                allow = []
                env_allow = os.getenv("HEL_ALLOWLIST", "")
                if env_allow:
                    allow.extend([h.strip() for h in env_allow.split(",") if h.strip()])
                if profile == "medium":
                    allow.extend(sorted(self.PROFILE_FINANCE_HOSTS))
                self._engine = PolicyEngine(allowlist_hosts=allow)
            return
        if rego:
            try:
                self._engine: Any = RegoPolicyEngine(rego, opa_bin=os.getenv("OPA_BIN", "opa"))
            except Exception as e:
                self._engine = PolicyEngine()
                self._rego_error = str(e)
        else:
            self._engine = PolicyEngine()

    def check_http_egress(self, host: str, tenant_key: Optional[str] = None) -> HELResult:
        return self._engine.check_http_egress(host, tenant_key=tenant_key)

class _AlwaysAllowEngine:
    def check_http_egress(self, host: str, tenant_key: Optional[str] = None) -> HELResult:
        return HELResult(True, "OPEN:HTTP_EGRESS", ["open profile allow"])  # type: ignore

__all__ = ["HELResult", "PolicyEngine", "RegoPolicyEngine", "PolicyManager"]
