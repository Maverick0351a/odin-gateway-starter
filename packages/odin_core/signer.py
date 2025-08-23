"""Signer abstraction for pluggable key custody backends.

Phase 2 introduces external KMS / HSM support. This initial commit only
implements the existing file/seed based Ed25519 signer behind a common
interface so the gateway code paths can be refactored without behavior
change.
"""
from __future__ import annotations
from typing import Protocol, Dict, Any, Optional
import os
from .crypto import b64u_encode, b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


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


class GCPKMSSigner:
    """Ed25519 signer using Google Cloud KMS.

    Env vars:
      ODIN_GCP_KMS_KEY   : projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<v>
      ODIN_GATEWAY_KID   : (optional) explicit kid; else derive from KMS public key

    Notes:
      - Requires service account with Cloud KMS sign permission.
      - Ed25519 keys must be created in KMS (purpose: ASYMMETRIC_SIGN, algorithm: ED25519)."""
    def __init__(self, key_name: str):
        from google.cloud import kms_v1
        self._client = kms_v1.KeyManagementServiceClient()
        self._key_name = key_name
        # Fetch public key
        pk = self._client.get_public_key(request={"name": key_name})
        # KMS returns PEM; extract raw from base64 inside header/footer for Ed25519 SubjectPublicKeyInfo
        import base64, re
        pem = pk.pem.encode()
        b64 = b"".join(line.strip() for line in pem.splitlines() if b"BEGIN" not in line and b"END" not in line)
        der = base64.b64decode(b64)
        # Parse SubjectPublicKeyInfo to raw 32 bytes (simple ASN.1 slice for Ed25519)
        # Ed25519 SPKI structure: SEQ { SEQ { OID 1.3.101.112 }, BIT STRING (raw key) }
        # Crude parse: last 32 bytes are the raw key (safe for Ed25519 SPKI minimal form)
        raw = der[-32:]
        self._raw_pub = raw
        self._kid = os.getenv("ODIN_GATEWAY_KID") or self._derive_kid()

    def _derive_kid(self) -> str:
        import hashlib
        return f"kms-ed25519-{hashlib.sha256(self._raw_pub).hexdigest()[:16]}"

    def kid(self) -> str:
        return self._kid

    def public_jwk(self) -> Dict[str, Any]:
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(self._raw_pub), "kid": self._kid}

    def sign(self, message: bytes) -> str:
        from google.cloud import kms_v1
        from .crypto import b64u_encode as _b64
        digest = {"ed25519": message}  # Raw message for Ed25519 per API (no pre-hash)
        # However google-cloud-kms python library expects 'data' not digest for ED25519 (using asymmetric_sign with data)
        req = {"name": self._key_name, "data": message}
        resp = self._client.asymmetric_sign(request=req)
        return _b64(resp.signature)


def load_signer() -> Signer:
    """Factory selecting signer backend via ODIN_SIGNER_BACKEND.

    Backends:
      file   – local seed (default)
      gcpkms – Google Cloud KMS Ed25519 key (needs ODIN_GCP_KMS_KEY)
    """
    backend = os.getenv("ODIN_SIGNER_BACKEND", "file").lower()
    if backend == "file":
        return FileKeySigner()
    if backend == "gcpkms":
        key = os.getenv("ODIN_GCP_KMS_KEY")
        if not key:
            raise ValueError("ODIN_GCP_KMS_KEY required for gcpkms backend")
        return GCPKMSSigner(key)
    if backend == "awskms":
        key_id = os.getenv("ODIN_AWS_KMS_KEY_ID")
        if not key_id:
            raise ValueError("ODIN_AWS_KMS_KEY_ID required for awskms backend")
        return AWSKMSSigner(key_id)
    if backend == "azurekv":
        key_id = os.getenv("ODIN_AZURE_KEY_ID")  # full Key Vault key identifier (versioned or not)
        if not key_id:
            raise ValueError("ODIN_AZURE_KEY_ID required for azurekv backend")
        return AzureKVSigner(key_id)
    raise ValueError(f"Unsupported signer backend '{backend}'")

class AWSKMSSigner:
    """Ed25519 signer using AWS KMS (requires a key with KEY_SPEC=ECC_ED25519 and SIGN_VERIFY)."""
    def __init__(self, key_id: str):
        import boto3, hashlib, base64
        self._client = boto3.client("kms")
        self._key_id = key_id
        desc = self._client.describe_key(KeyId=key_id)["KeyMetadata"]
        if desc.get("KeySpec") not in ("ECC_ED25519", "ED25519"):  # AWS uses ECC_ED25519
            raise ValueError("AWS KMS key must be ED25519/ECC_ED25519")
        pub = self._client.get_public_key(KeyId=key_id)
        # AWS returns DER SubjectPublicKeyInfo in 'PublicKey'
        der = pub["PublicKey"]
        raw = der[-32:]  # Ed25519 raw public key at end
        self._raw_pub = raw
        self._kid = os.getenv("ODIN_GATEWAY_KID") or f"aws-ed25519-{hashlib.sha256(raw).hexdigest()[:16]}"

    def kid(self) -> str:
        return self._kid

    def public_jwk(self) -> Dict[str, Any]:
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(self._raw_pub), "kid": self._kid}

    def sign(self, message: bytes) -> str:
        # For ED25519, KMS signs raw message; set SigningAlgorithm to EDDSA
        from .crypto import b64u_encode as _b64
        resp = self._client.sign(KeyId=self._key_id, Message=message, SigningAlgorithm="EDDSA", MessageType="RAW")
        return _b64(resp["Signature"])

class AzureKVSigner:
    """Ed25519 signer using Azure Key Vault (requires an Ed25519 key in vault)."""
    def __init__(self, key_id: str):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
        from urllib.parse import urlparse
        self._key_id = key_id
        cred = DefaultAzureCredential()
        # Derive vault URL from key id
        parsed = urlparse(key_id)
        vault_url = f"{parsed.scheme}://{parsed.netloc}"
        # Fetch key (KeyClient used for retrieval, crypto client for signing)
        kc = KeyClient(vault_url=vault_url, credential=cred)
        name = parsed.path.strip('/').split('/')[1]  # /keys/<name>/<version?>
        # If version specified in path length > 2
        parts = parsed.path.strip('/').split('/')
        version = parts[2] if len(parts) > 2 else None
        key_bundle = kc.get_key(name, version=version)  # no network if cached
        self._raw_pub = key_bundle.key.x  # Already base64url per spec for OKP? If Ed25519, azure returns 'x'
        # If azure returns only JWK form we store raw bytes after decoding
        import base64
        try:
            raw = base64.urlsafe_b64decode(self._raw_pub + '===' )
            if len(raw) == 32:
                self._raw_pub_bytes = raw
            else:
                self._raw_pub_bytes = raw[-32:]
        except Exception:
            self._raw_pub_bytes = b""  # fallback
        self._crypto = CryptographyClient(key_bundle.id, credential=cred)
        import hashlib
        self._kid = os.getenv("ODIN_GATEWAY_KID") or f"azure-ed25519-{hashlib.sha256(self._raw_pub_bytes).hexdigest()[:16]}"
        from azure.keyvault.keys.crypto import SignatureAlgorithm as _Alg
        self._alg = _Alg.ED25519

    def kid(self) -> str:
        return self._kid

    def public_jwk(self) -> Dict[str, Any]:
        # If we failed to parse raw bytes earlier, raise to avoid silent bad key exposure
        if not getattr(self, '_raw_pub_bytes', None):
            raise RuntimeError("AzureKVSigner missing raw public key bytes")
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(self._raw_pub_bytes), "kid": self._kid}

    def sign(self, message: bytes) -> str:
        from azure.keyvault.keys.crypto import SignatureAlgorithm
        from .crypto import b64u_encode as _b64
        resp = self._crypto.sign(SignatureAlgorithm.ED25519, message)
        return _b64(resp.signature)

__all__ = ["Signer", "FileKeySigner", "GCPKMSSigner", "AWSKMSSigner", "AzureKVSigner", "load_signer"]
