import pytest, hashlib
from odin_core.crypto import b64u_encode, b64u_decode, load_or_create_private_key, sign_bytes, verify_with_jwk


def test_b64u_roundtrip():
    data = b"hello-odin"
    enc = b64u_encode(data)
    assert enc.endswith(('-', '_')) or enc  # basic sanity
    dec = b64u_decode(enc)
    assert dec == data


def test_load_or_create_private_key_invalid_length():
    # 31 bytes -> invalid
    bad = b64u_encode(b"0" * 31)
    with pytest.raises(ValueError):
        load_or_create_private_key(bad)


def test_sign_and_verify():
    priv, kid = load_or_create_private_key()
    msg = b"sample-message"
    sig = sign_bytes(priv, msg)
    # Build public JWK directly from private key
    from cryptography.hazmat.primitives import serialization
    pub_raw = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(pub_raw)}
    assert verify_with_jwk(jwk, msg, sig)


def test_verify_with_jwk_rejects_invalid():
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(b"0"*32)}
    assert not verify_with_jwk(jwk, b"msg", "deadbeef")
