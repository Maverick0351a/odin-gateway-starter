import base64
import os

import pytest
from odin_core.signer import FileKeySigner, load_signer


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


@pytest.mark.skipif(os.getenv("ODIN_SIGNER_BACKEND") != "gcpkms", reason="gcpkms backend not active")
def test_gcpkms_signer_smoke():
    # Requires ODIN_SIGNER_BACKEND=gcpkms and ODIN_GCP_KMS_KEY set with valid credentials.
    signer = load_signer()
    sig = signer.sign(b"probe")
    assert isinstance(sig, str) and len(sig) > 40  # base64url Ed25519 signature ~88 chars