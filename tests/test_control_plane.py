import pytest, time
from odin_core.control import ControlPlane


def test_tenant_crud_and_key_issue():
    cp = ControlPlane()
    t = cp.create_tenant("acme", name="Acme Corp")
    assert t["tenant_id"] == "acme"
    assert cp.get_tenant("acme")["name"] == "Acme Corp"
    key_rec = cp.issue_key("acme")
    assert key_rec["active"]
    resolved = cp.resolve_api_key(key_rec["key"])
    assert resolved and resolved["tenant_id"] == "acme"
    assert cp.revoke_key("acme", key_rec["key"]) is True
    assert cp.resolve_api_key(key_rec["key"]) is None
    updated = cp.update_tenant("acme", rate_limit_rpm=5, allowlist=["host"], custody_mode="byok", signer_ref={"kty":"OKP","crv":"Ed25519","x":"abc"})
    assert updated["rate_limit_rpm"] == 5 and updated["custody_mode"] == "byok"
    assert cp.delete_tenant("acme")
    assert cp.get_tenant("acme") is None


def test_rate_limiter_basic():
    cp = ControlPlane()
    cp.create_tenant("t1")
    rl = cp.rate_limiter()
    # rpm=2 allow first two in same minute, block third
    assert rl.check("t1", 2)
    assert rl.check("t1", 2)
    assert not rl.check("t1", 2)


def test_rate_limiter_new_window_allows_again(monkeypatch):
    cp = ControlPlane()
    rl = cp.rate_limiter()
    key = "k"
    assert rl.check(key, 1)
    assert not rl.check(key, 1)
    # simulate minute rollover by monkeypatching time.time
    orig = time.time
    monkeypatch.setattr(time, "time", lambda: orig() + 61)
    try:
        assert rl.check(key, 1)
    finally:
        monkeypatch.setattr(time, "time", orig)
