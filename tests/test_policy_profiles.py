from odin_core.hel import PolicyManager


def test_policy_profile_strict(monkeypatch):
    monkeypatch.setenv('ODIN_POLICY_PROFILE', 'strict')
    monkeypatch.delenv('HEL_ALLOWLIST', raising=False)
    pm = PolicyManager()
    assert not pm.check_http_egress('example.com').passed
    # Add allowlist via env
    monkeypatch.setenv('HEL_ALLOWLIST', 'example.com')
    pm2 = PolicyManager()
    assert pm2.check_http_egress('example.com').passed

def test_policy_profile_medium_adds_finance(monkeypatch):
    monkeypatch.setenv('ODIN_POLICY_PROFILE', 'medium')
    monkeypatch.delenv('HEL_ALLOWLIST', raising=False)
    pm = PolicyManager()
    # Finance host should be allowed
    assert pm.check_http_egress('api.bank.com').passed
    # Random host denied
    assert not pm.check_http_egress('random.example').passed

def test_policy_profile_open_allows_all(monkeypatch):
    monkeypatch.setenv('ODIN_POLICY_PROFILE', 'open')
    pm = PolicyManager()
    assert pm.check_http_egress('anything.really').passed