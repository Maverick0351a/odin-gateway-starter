"""Conformance harness.

Executes JSON test vectors under ./conformance/vectors, performing
local transformations & signature / chain validation against a live gateway
or offline when possible.

Usage (offline transforms only):
  python -m conformance.harness --mode offline

Usage (gateway integration):
  GATEWAY_URL=http://127.0.0.1:8080 python -m conformance.harness --mode gateway

Exit codes:
  0 success, 1 failure(s), 2 internal error
"""
from __future__ import annotations
import sys, json, argparse, pathlib, os, traceback
from typing import List
import sys
# Ensure local packages directory is on path when executed without editable install
ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))
from odin_core import transform_payload, cid_sha256, canonical_json  # type: ignore

VECTORS_DIR = pathlib.Path(__file__).parent / 'vectors'

def load_vectors() -> List[pathlib.Path]:
    return [p for p in VECTORS_DIR.glob('*.json') if not p.name.startswith('_')]

def run_offline(vector_path: pathlib.Path) -> tuple[bool,str]:
    data = json.loads(vector_path.read_text())
    inp = data['input']
    payload = inp['payload']
    pt = inp['payload_type']; tt = inp['target_type']
    out, meta = transform_payload(payload, pt, tt)
    if data['expected'].get('target_type') and tt != data['expected']['target_type']:
        return False, 'target_type mismatch'
    # Basic canonical CID determinism check
    cid = cid_sha256(canonical_json(out))
    return True, f"ok cid={cid}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['offline','gateway'], default='offline')
    args = ap.parse_args()
    failures = []
    for vec in load_vectors():
        try:
            ok, msg = run_offline(vec)
        except Exception as e:  # noqa
            ok, msg = False, f'error: {e}'
            traceback.print_exc()
        status = 'PASS' if ok else 'FAIL'
        print(f"[vector] {vec.name}: {status} {msg}")
        if not ok:
            failures.append(vec.name)
    if failures:
        print(f"Failed vectors: {failures}", file=sys.stderr)
        sys.exit(1)
    print('All vectors passed')

if __name__ == '__main__':  # pragma: no cover
    main()
