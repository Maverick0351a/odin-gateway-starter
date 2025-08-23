import os
import pytest
from odin_core.hel import PolicyManager, PolicyEngine, HELResult


def test_policy_manager_default_hel_allows_configured_host(monkeypatch):
    monkeypatch.setenv("HEL_ALLOWLIST", "example.com")
    pm = PolicyManager()
    res = pm.check_http_egress("example.com")
    assert res.passed
    res2 = pm.check_http_egress("blocked.com")
    assert not res2.passed


@pytest.mark.skipif(not os.getenv("ODIN_POLICY_REGO_PATH"), reason="rego policy not configured")
def test_policy_manager_rego_smoke():
    pm = PolicyManager()
    res = pm.check_http_egress("example.com")
    assert isinstance(res, HELResult)