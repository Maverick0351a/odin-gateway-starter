"""Pytest configuration ensuring local packages and service modules are importable.

Some CI environments (or certain pytest invocation patterns) may omit the
repository root from sys.path early enough for our implicit namespace
imports (e.g. `services.gateway.main`). This file force-adds the repo
root and the `packages` directory to sys.path before tests collect.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "packages"

def _ensure(p: Path):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

_ensure(ROOT)
if PKG_DIR.exists():
    _ensure(PKG_DIR)

# Optional: quick debug hook (disabled by default)
# print("[conftest] sys.path=", sys.path)
