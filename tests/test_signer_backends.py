import importlib
import os

import pytest

# We only test factory selection + error surfaces without invoking real cloud APIs.
# Real KMS integration tests would be added behind environment flags.
from packages.odin_core import signer as signer_mod  # type: ignore


def reload_signer():
    import sys
    if 'packages.odin_core.signer' in sys.modules:
        del sys.modules['packages.odin_core.signer']
    return importlib.import_module('packages.odin_core.signer')


def test_load_signer_file_default(monkeypatch):
    monkeypatch.delenv('ODIN_SIGNER_BACKEND', raising=False)
    s = signer_mod.load_signer()
    assert s.kid()
    jwk = s.public_jwk()
    assert jwk['kty'] == 'OKP'


def test_load_signer_unknown_backend(monkeypatch):
    monkeypatch.setenv('ODIN_SIGNER_BACKEND', 'nope')
    with pytest.raises(ValueError):
        signer_mod.load_signer()


## Removed cloud backend tests (gcpkms, awskms, azurekv) while those implementations are disabled.
