# Auto-added to ensure local 'packages' directory is importable (CI + local)
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent
pkg = root / 'packages'
if pkg.exists():
    p = str(pkg)
    if p not in sys.path:
        sys.path.insert(0, p)
