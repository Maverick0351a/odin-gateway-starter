"""ODIN SDK CLI

Polished UX:
- Global defaults via env (ODIN_GATEWAY_URL, ODIN_SENDER_PRIV_B64, ODIN_SENDER_KID)
- Payload from --payload-file, --payload-inline, or stdin (-)
- Auto trace id if omitted; always printed (plain & JSON)
- Consistent --json output shape with ok/error and trace_id where applicable
- Subcommands: keygen, sign, send, chain, export-verify, jwks, ping
- Export verify supports --include-bundle & returns verification flags
"""

import argparse
import base64
import json
import os
import sys
import textwrap
import traceback
import uuid
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .client import OPEClient, canonical_json, cid_sha256

EXIT_OK = 0
EXIT_USER = 1
EXIT_VERIFY_FAIL = 2


def _read_stdin() -> str:
    try:
        if sys.stdin.isatty():
            return ""
        return sys.stdin.read()
    except Exception:
        return ""

def load_payload(args) -> Any:
    if args.payload_inline:
        return json.loads(args.payload_inline)
    if args.payload_file:
        if args.payload_file == '-':
            data = _read_stdin()
            if not data.strip():
                raise SystemExit("Stdin empty for payload")
            return json.loads(data)
        with open(args.payload_file, "r", encoding="utf-8") as f:
            return json.load(f)
    raise SystemExit("Provide --payload-file, --payload-inline, or pipe JSON to stdin with --payload-file -")

def ensure_client(args) -> OPEClient:
    priv = args.priv or os.getenv("ODIN_SENDER_PRIV_B64")
    kid = args.kid or os.getenv("ODIN_SENDER_KID")
    if not priv or not kid:
        raise SystemExit("Missing --priv/--kid and no ODIN_SENDER_PRIV_B64 / ODIN_SENDER_KID env vars")
    return OPEClient(args.gateway_url, priv, kid)

def cmd_keygen(args):
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    seed = base64.urlsafe_b64encode(raw).decode().rstrip('=')
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    kid = f"ed25519-{uuid.uuid4().hex[:16]}"
    jwk = {"kty":"OKP","crv":"Ed25519","x": base64.urlsafe_b64encode(pub).decode().rstrip('='),"kid": kid}
    out = {"private_key_b64": seed, "kid": kid, "jwk": jwk}
    if args.json:
        print(json.dumps(out, indent=2))
        return
    print(json.dumps(out, indent=2))

def cmd_sign(args):
    client = ensure_client(args)
    payload = load_payload(args)
    trace = args.trace_id or f"cli-{uuid.uuid4()}"
    env = client.create_envelope(payload, args.ptype, args.ttype, trace_id=trace, ts=args.ts)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(env, f, indent=2)
    if args.json:
        print(json.dumps({"ok": True, "trace_id": trace, "envelope": env}, indent=2))
    else:
        if not args.output:
            print(json.dumps(env, indent=2))
        print(f"trace_id: {trace}")

def cmd_send(args):
    client = ensure_client(args)
    payload = load_payload(args)
    trace = args.trace_id or f"cli-{uuid.uuid4()}"
    env = client.create_envelope(payload, args.ptype, args.ttype, trace_id=trace, ts=args.ts)
    try:
        data, headers = client.send_envelope(env, verify_chain=args.verify_chain)
    except Exception as e:
        _emit_error(args, f"send_failed: {e}", trace)
    out = {
        "ok": True,
        "trace_id": trace,
        "receipt_hash": headers.get("x-odin-receipt-hash"),
        "response_cid": headers.get("x-odin-response-cid"),
        "kid": headers.get("x-odin-kid"),
    }
    if args.print_body:
        out["body"] = data
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"Status: 200\ntrace_id: {trace}\nReceipt Hash: {out['receipt_hash']}\nResponse CID: {out['response_cid']}\nSignature KID: {out['kid']}")
        if args.print_body:
            print(json.dumps(data, indent=2))

def cmd_chain(args):
    client = ensure_client(args)
    chain = client.get_chain(args.trace_id)
    if args.json:
        print(json.dumps({"ok": True, "trace_id": args.trace_id, "chain": chain}, indent=2))
    else:
        print(json.dumps(chain, indent=2))

def _verify_export_bundle(bundle_resp: dict, jwks_resp: dict):  # noqa: C901
    # Minimal verification echoing scripts/verify_export.py core logic
    headers = bundle_resp.get("_headers", {})
    body = bundle_resp["body"]
    chain = body.get("chain") or body.get("hops") or body.get("bundle", {}).get("receipts")
    if not chain:
        raise SystemExit("No chain/hops in export bundle")
    # Hash linkage
    for i, r in enumerate(chain):
        r_copy = dict(r)
        r_copy.pop("receipt_signature", None)
        import hashlib
        local_hash = hashlib.sha256(canonical_json(r_copy)).hexdigest()
        if local_hash != r.get("receipt_hash"):
            raise SystemExit(f"Receipt hash mismatch at index {i}")
        if i > 0 and r.get("prev_receipt_hash") != chain[i-1].get("receipt_hash"):
            raise SystemExit(f"Chain broken at index {i}")
    # Response CID
    resp_cid_hdr = headers.get("x-odin-response-cid") or headers.get("x-odin-bundle-cid")
    if resp_cid_hdr:
        local_cid = cid_sha256(canonical_json(body))
        if local_cid != resp_cid_hdr:
            raise SystemExit("Bundle CID mismatch")
    # Signature verification (best effort)
    sig = headers.get("x-odin-signature") or headers.get("x-odin-bundle-signature")
    kid = headers.get("x-odin-kid")
    if sig and kid:
        keys = jwks_resp.get("keys", [])
        key = next((k for k in keys if k.get("kid") == kid), None)
        if key:
            from cryptography.exceptions import InvalidSignature  # noqa: I001
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: I001
            import base64  # noqa: I001

            def b64u_dec(s: str):  # local helper
                return base64.urlsafe_b64decode(s + ("=" * (-len(s) % 4)))
            pk = Ed25519PublicKey.from_public_bytes(b64u_dec(key["x"]))
            # Try message formats
            trace = body.get("trace_id") or headers.get("x-odin-trace-id")
            ts = body.get("ts") or (chain[-1].get("ts") if chain else None)
            candidates = []
            if resp_cid_hdr and trace and ts:
                candidates.append(f"{resp_cid_hdr}|{trace}|{ts}".encode())
            if resp_cid_hdr:
                candidates.append(resp_cid_hdr.encode())
            verified = False
            for m in candidates:
                try:
                    pk.verify(b64u_dec(sig), m)
                    verified = True
                    break
                except InvalidSignature:
                    continue
            if not verified:
                raise SystemExit("Signature verification failed")
    return True

def cmd_export_verify(args):
    import httpx
    client = ensure_client(args)
    r = httpx.get(f"{args.gateway_url.rstrip('/')}/v1/receipts/export/{args.trace_id}", timeout=30)
    r.raise_for_status()
    bundle = r.json()
    headers = {k.lower(): v for k, v in r.headers.items()}
    jwks = client._fetch_jwks()
    try:
        _verify_export_bundle({"body": bundle, "_headers": headers}, jwks)
        verified = True
    except SystemExit as e:
        if args.json:
            print(json.dumps({"ok": False, "trace_id": args.trace_id, "verified": False, "error": str(e)}, indent=2))
        else:
            print(f"Verification failed: {e}", file=sys.stderr)
        sys.exit(EXIT_VERIFY_FAIL)
    if args.json:
        print(json.dumps({"ok": True, "trace_id": args.trace_id, "verified": verified, "bundle": bundle if args.include_bundle else None}, indent=2))
    else:
        print("Export bundle verified")

def cmd_jwks(args):
    import httpx
    r = httpx.get(f"{args.gateway_url.rstrip('/')}/.well-known/jwks.json", timeout=10)
    if args.json:
        print(json.dumps(r.json(), indent=2))
    else:
        print(json.dumps(r.json(), indent=2))

def cmd_ping(args):
    import httpx
    r = httpx.get(f"{args.gateway_url.rstrip('/')}/healthz", timeout=5)
    ok = (r.status_code == 200)
    if args.json:
        print(json.dumps({"ok": ok, "status": r.json() if ok else r.text, "code": r.status_code}, indent=2))
    else:
        print("healthy" if ok else f"unhealthy ({r.status_code})")


def build_parser():
    env_gateway = os.getenv("ODIN_GATEWAY_URL", "http://127.0.0.1:8080")
    p = argparse.ArgumentParser(
        prog="odin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="ODIN SDK CLI",
        epilog=textwrap.dedent("""Env vars:
  ODIN_GATEWAY_URL (default gateway)
  ODIN_SENDER_PRIV_B64 / ODIN_SENDER_KID (defaults for signing commands)
"""),
    )
    p.add_argument("--gateway-url", default=env_gateway, help=f"Gateway base URL (default {env_gateway})")
    sub = p.add_subparsers(dest="cmd", required=True)

    # sign
    s_key = sub.add_parser("keygen", help="Generate Ed25519 keypair (seed + JWK)")
    s_key.add_argument("--json", action="store_true")
    s_key.set_defaults(func=cmd_keygen)

    s = sub.add_parser("sign", help="Create a signed envelope")
    s.add_argument("--priv", help="Base64url Ed25519 raw private key (32 bytes)")
    s.add_argument("--kid", help="Sender key id")
    s.add_argument("--ptype", required=True)
    s.add_argument("--ttype", required=True)
    s.add_argument("--payload-file", help="Path to JSON payload file or - for stdin")
    s.add_argument("--payload-inline", help="Inline JSON string payload")
    s.add_argument("--trace-id")
    s.add_argument("--ts")
    s.add_argument("--output")
    s.add_argument("--json", action="store_true", help="JSON output (prints trace_id and envelope)")
    s.set_defaults(func=cmd_sign)

    # send
    s2 = sub.add_parser("send", help="Sign and send an envelope")
    s2.add_argument("--priv")
    s2.add_argument("--kid")
    s2.add_argument("--ptype", required=True)
    s2.add_argument("--ttype", required=True)
    s2.add_argument("--payload-file")
    s2.add_argument("--payload-inline")
    s2.add_argument("--trace-id")
    s2.add_argument("--ts")
    s2.add_argument("--print-body", action="store_true")
    s2.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    s2.add_argument("--verify-chain", action="store_true", help="After send, fetch chain and ensure tail receipt hash matches response")
    s2.set_defaults(func=cmd_send)

    # chain
    s3 = sub.add_parser("chain", help="Fetch receipt chain")
    s3.add_argument("--priv")
    s3.add_argument("--kid")
    s3.add_argument("--trace-id", required=True)
    s3.add_argument("--json", action="store_true")
    s3.set_defaults(func=cmd_chain)

    # export-verify
    s4 = sub.add_parser("export-verify", help="Fetch and verify export bundle")
    s4.add_argument("--priv")
    s4.add_argument("--kid")
    s4.add_argument("--trace-id", required=True)
    s4.add_argument("--json", action="store_true")
    s4.add_argument("--include-bundle", action="store_true")
    s4.set_defaults(func=cmd_export_verify)

    s_j = sub.add_parser("jwks", help="Fetch JWKS")
    s_j.add_argument("--json", action="store_true")
    s_j.set_defaults(func=cmd_jwks)

    s_p = sub.add_parser("ping", help="Gateway health check")
    s_p.add_argument("--json", action="store_true")
    s_p.set_defaults(func=cmd_ping)

    return p


def _emit_error(args, message: str, trace_id: Optional[str] = None):
    if getattr(args, 'json', False):
        print(json.dumps({"ok": False, "error": message, **({"trace_id": trace_id} if trace_id else {})}, indent=2))
    else:
        print(f"Error: {message}", file=sys.stderr)
    sys.exit(EXIT_USER)

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        _emit_error(args, "aborted")
    except SystemExit:
        raise
    except Exception as e:
        tb_last = traceback.format_exc().splitlines()[-1]
        _emit_error(args, f"{e} ({tb_last})")

if __name__ == "__main__":
    main()
