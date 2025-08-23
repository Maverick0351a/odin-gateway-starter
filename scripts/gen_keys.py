# Generate an Ed25519 keypair for ODIN (base64url raw 32-byte private, and JWKS)
import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

priv = Ed25519PrivateKey.generate()
raw = priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
kid = f"ed25519-{hashlib.sha256(pub).hexdigest()[:16]}"
print("ODIN_GATEWAY_PRIVATE_KEY_B64=", b64u(raw))
print("ODIN_GATEWAY_KID=", kid)
print("JWKS=", json.dumps({"keys":[{"kty":"OKP","crv":"Ed25519","x":b64u(pub),"kid":kid}]}, indent=2))
