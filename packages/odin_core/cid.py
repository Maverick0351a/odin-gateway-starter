import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def cid_sha256(payload_bytes: bytes) -> str:
    return f"sha256:{sha256_hex(payload_bytes)}"
