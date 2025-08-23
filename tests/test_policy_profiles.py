from odin_core.hel import PolicyManager
import importlib


def _reload():
    import odin_core.hel as hel_mod  # noqa
    importlib.reload(hel_mod)
    return hel_mod.PolicyManager


def test_policy_profile_strict(monkeypatch):
    monkeypatch.setenv('ODIN_POLICY_PROFILE', 'strict')
    monkeypatch.delenv('HEL_ALLOWLIST', raising=False)
    PolicyManagerCls = _reload()
    pm = PolicyManagerCls()
    assert not pm.check_http_egress('example.com').passed
    # Add allowlist via env
    monkeypatch.setenv('HEL_ALLOWLIST', 'example.com')
    PolicyManagerCls = _reload()
    pm2 = PolicyManagerCls()
    assert pm2.check_http_egress('example.com').passed


def test_policy_profile_medium_adds_finance(monkeypatch):
    monkeypatch.setenv('ODIN_POLICY_PROFILE', 'medium')
    monkeypatch.delenv('HEL_ALLOWLIST', raising=False)
    PolicyManagerCls = _reload()
    pm = PolicyManagerCls()
    # Finance host should be allowed
    assert pm.check_http_egress('api.bank.com').passed
    # Random host denied
    assert not pm.check_http_egress('random.example').passed


def test_policy_profile_open_allows_all(monkeypatch):
    monkeypatch.setenv('ODIN_POLICY_PROFILE', 'open')
    PolicyManagerCls = _reload()
    pm = PolicyManagerCls()
    assert pm.check_http_egress('anything.really').passed


def test_tenant_allowlist_override(monkeypatch):
    # Baseline: no profile, provide tenant allowlist JSON
    monkeypatch.delenv('ODIN_POLICY_PROFILE', raising=False)
    monkeypatch.setenv('HEL_TENANT_ALLOWLISTS', '{"tenant123": ["special.example"]}')
    PolicyManagerCls = _reload()
    pm = PolicyManagerCls()
    # Without tenant key blocked
    assert not pm.check_http_egress('special.example').passed
    # With tenant key allowed
    assert pm.check_http_egress('special.example', tenant_key='tenant123').passed