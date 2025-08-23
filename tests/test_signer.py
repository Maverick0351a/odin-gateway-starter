import base64
import os

from odin_core.signer import FileKeySigner


def test_file_signer_deterministic_kid_and_signature():
    # 32 byte seed (all 0x01) base64url without padding
    seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
    signer1 = FileKeySigner(seed_b64=seed)
    signer2 = FileKeySigner(seed_b64=seed)
    assert signer1.kid() == signer2.kid()
    msg = b"test-message"
    sig1 = signer1.sign(msg)
    sig2 = signer2.sign(msg)
    assert sig1 == sig2
    jwk = signer1.public_jwk()
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["kid"] == signer1.kid()


