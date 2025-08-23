import os, sys, pathlib, hashlib

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

from odin_core.transparency import TransparencyLog  # noqa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_add_and_root_and_audit_path(tmp_path):
    log_path = tmp_path / 'transparency.log'
    tlog = TransparencyLog(str(log_path))
    # Add a few leaves
    leaves = [hashlib.sha256(f"leaf{i}".encode()).hexdigest() for i in range(5)]
    indices = [tlog.add_leaf(l) for l in leaves]
    assert indices == list(range(5))
    root1 = tlog.root()
    assert root1 is not None
    # Root cached reuse
    assert tlog.root() == root1
    # Audit path for third leaf
    path = tlog.audit_path(2)
    assert isinstance(path, list) and path
    # Inclusion verification
    # Build a fake signer for checkpoint
    priv = Ed25519PrivateKey.generate()
    ckpt = tlog.checkpoint(lambda msg: priv.sign(msg))
    assert ckpt['size'] == 5
    # Adding another leaf mutates root
    tlog.add_leaf(hashlib.sha256(b'leaf5').hexdigest())
    assert tlog.root() != root1


def test_add_leaf_invalid():
    tlog = TransparencyLog()
    try:
        tlog.add_leaf('nothex')
    except Exception as e:
        assert 'leaf_hash must be 64-char' in str(e)
    else:
        assert False, 'expected ValueError'


def test_audit_path_bounds():
    tlog = TransparencyLog()
    h = hashlib.sha256(b'x').hexdigest()
    tlog.add_leaf(h)
    try:
        tlog.audit_path(5)
    except IndexError:
        pass
    else:
        assert False, 'expected IndexError'
