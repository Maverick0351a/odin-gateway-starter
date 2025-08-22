import argparse, json, base64, hashlib, sys
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def kid_from_pub(pub_raw: bytes) -> str:
    return f"ed25519-{hashlib.sha256(pub_raw).hexdigest()[:16]}"

def main():
    ap = argparse.ArgumentParser(description="ODIN key rotation helper")
    ap.add_argument("--gw-url", default="http://127.0.0.1:8080", help="Gateway base URL to fetch current JWKS")
    ap.add_argument("--current-kid", help="Override: current KID if multiple keys present")
    args = ap.parse_args()

    try:
        jwks = requests.get(f"{args.gw_url}/.well-known/jwks.json", timeout=10).json()
        keys = jwks.get("keys", [])
        if not keys:
            print("[FAIL] Gateway returned empty JWKS"); sys.exit(2)
    except Exception as e:
        print(f"[FAIL] Could not fetch JWKS from {args.gw_url}: {e}"); sys.exit(2)

    cur = None
    if args.current_kid:
        for k in keys:
            if k.get("kid") == args.current_kid:
                cur = k; break
    if cur is None:
        cur = keys[0]

    if cur.get("kty") != "OKP" or cur.get("crv") != "Ed25519" or "x" not in cur:
        print("[FAIL] Current key is not an Ed25519 JWK"); sys.exit(2)

    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_priv_b64 = b64u(priv_raw)
    new_kid = kid_from_pub(pub_raw)
    new_pub_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub_raw), "kid": new_kid}

    legacy = dict(cur)
    legacy["status"] = "legacy"
    addl = {"keys": [legacy]}

    print("\n=== New Gateway Key (activate NEXT) ===")
    print(f"NEW_ODIN_GATEWAY_PRIVATE_KEY_B64={new_priv_b64}")
    print(f"NEW_ODIN_GATEWAY_KID={new_kid}")

    print("\n=== Additional Public JWKS (publish NOW to allow overlap) ===")
    print(json.dumps(addl, indent=2))

    print("\n--- PowerShell rotation plan ---")
    print(f"$env:ODIN_ADDITIONAL_PUBLIC_JWKS = '{json.dumps(addl).replace("'", "''")}'")
    print("# Restart gateway to publish legacy + current")
    print(f"$env:ODIN_GATEWAY_PRIVATE_KEY_B64 = '{new_priv_b64}'")
    print(f"$env:ODIN_GATEWAY_KID = '{new_kid}'")
    print("# Restart gateway again to switch active key")

    print("\n--- Bash rotation plan ---")
    print(f"export ODIN_ADDITIONAL_PUBLIC_JWKS='{json.dumps(addl)}'")
    print("# Restart gateway to publish legacy + current")
    print(f"export ODIN_GATEWAY_PRIVATE_KEY_B64='{new_priv_b64}'")
    print(f"export ODIN_GATEWAY_KID='{new_kid}'")
    print("# Restart gateway again to switch active key")

if __name__ == "__main__":
    main()
