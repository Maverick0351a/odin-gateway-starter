"""Signer abstraction (current implementation: local file/seed Ed25519).

Cloud KMS / HSM backends (gcpkms, awskms, azurekv) were experimental and are
temporarily removed to reduce optional dependency complexity while those
integrations are not in active use. The factory will currently only return
``FileKeySigner``. Attempting to select another backend raises ``ValueError``.

Future reinstatement can restore the previous classes (see git history).
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import b64u_decode, b64u_encode


class Signer(Protocol):
    def kid(self) -> str: ...
    def public_jwk(self) -> Dict[str, Any]: ...
    def sign(self, message: bytes) -> str: ...  # base64url


class FileKeySigner:
    """Ed25519 seed (32B) loaded from env or passed directly.

    Env vars:
      ODIN_GATEWAY_PRIVATE_KEY_B64 : base64url seed (no padding)
      ODIN_GATEWAY_KID              : optional explicit kid override
    """
    def __init__(self, seed_b64: Optional[str] = None, kid: Optional[str] = None):
        seed_b64 = seed_b64 or os.getenv("ODIN_GATEWAY_PRIVATE_KEY_B64")
        if seed_b64:
            raw = b64u_decode(seed_b64)
            if len(raw) != 32:
                raise ValueError("Ed25519 seed must be 32 bytes")
            self._priv = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            self._priv = Ed25519PrivateKey.generate()
        self._pub = self._priv.public_key()
        self._kid = kid or os.getenv("ODIN_GATEWAY_KID") or self._derive_kid()

    def _derive_kid(self) -> str:
        raw = self._pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        import hashlib
        return f"ed25519-{hashlib.sha256(raw).hexdigest()[:16]}"

    def kid(self) -> str:
        return self._kid

    def public_jwk(self) -> Dict[str, Any]:
        raw = self._pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(raw), "kid": self._kid}

    def sign(self, message: bytes) -> str:
        from .crypto import b64u_encode as _b64
        return _b64(self._priv.sign(message))


def load_signer() -> Signer:
    """Factory selecting signer backend via ``ODIN_SIGNER_BACKEND`` (only 'file')."""
    backend = os.getenv("ODIN_SIGNER_BACKEND", "file").lower()
    if backend == "file":
        return FileKeySigner()
    raise ValueError(f"Unsupported signer backend '{backend}'")
__all__ = ["Signer", "FileKeySigner", "load_signer"]
