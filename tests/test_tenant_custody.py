from odin_core.control import ControlPlane


def test_custody_mode_update():
    cp = ControlPlane()
    cp.create_tenant('acme', 'Acme')
    # default
    t = cp.get_tenant('acme')
    assert t['custody_mode'] == 'odin'
    # update to byok
    pub_jwk = {"kty":"OKP","crv":"Ed25519","x":"A"*43,"kid":"acme-byok-1"}
    cp.update_tenant('acme', custody_mode='byok', signer_ref=pub_jwk)
    t2 = cp.get_tenant('acme')
    assert t2['custody_mode'] == 'byok'
    assert t2['signer_ref']['kid'] == 'acme-byok-1'