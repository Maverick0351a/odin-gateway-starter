import base64, hashlib
from typing import Tuple, Optional, Dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64u_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def load_or_create_private_key(env_b64: Optional[str]=None) -> Tuple[Ed25519PrivateKey, str]:
    if env_b64:
        raw = b64u_decode(env_b64)
        if len(raw) != 32:
            raise ValueError("ODIN_GATEWAY_PRIVATE_KEY_B64 must be 32 raw bytes (seed) in base64url")
        priv = Ed25519PrivateKey.from_private_bytes(raw)
    else:
        priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    kid = kid_from_public_key(pub)
    return priv, kid

def kid_from_public_key(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    fp = hashlib.sha256(raw).hexdigest()[:16]
    return f"ed25519-{fp}"

def public_jwk_from_private_b64(priv_b64: str, kid: Optional[str]=None) -> Dict:
    raw = b64u_decode(priv_b64)
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key()
    pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    jwk = { "kty": "OKP", "crv": "Ed25519", "x": b64u_encode(pub_raw) }
    if kid: jwk["kid"] = kid
    return jwk

def sign_bytes(priv: Ed25519PrivateKey, message: bytes) -> str:
    return b64u_encode(priv.sign(message))

def verify_with_jwk(jwk: Dict, message: bytes, signature_b64u: str) -> bool:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        return False
    try:
        pub_raw = b64u_decode(jwk["x"])
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig = b64u_decode(signature_b64u)
        pub.verify(sig, message)
        return True
    except Exception:
        return False
