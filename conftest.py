# Ensure local 'packages' directory is importable in test and CI environments
import pathlib
import sys

pkg_dir = pathlib.Path(__file__).resolve().parent / 'packages'
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))
