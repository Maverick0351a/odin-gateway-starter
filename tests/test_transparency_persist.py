import os, tempfile, json
from odin_core.transparency import TransparencyLog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_transparency_persistence_and_checkpoint(tmp_path):
    path = tmp_path / "tlog.log"
    log1 = TransparencyLog(str(path))
    # generate leaves
    import hashlib
    for i in range(5):
        leaf = hashlib.sha256(f"leaf-{i}".encode()).hexdigest()
        log1.add_leaf(leaf)
    root1 = log1.root()
    size1 = log1.size()

    # Reload
    log2 = TransparencyLog(str(path))
    assert log2.size() == size1
    assert log2.root() == root1

    # Checkpoint unsigned
    ckpt = log2.checkpoint()
    assert ckpt["root"] == root1
    assert ckpt["size"] == size1

    # Signed checkpoint
    priv = Ed25519PrivateKey.generate()
    def signer(msg: bytes):
        return priv.sign(msg)
    sckpt = log2.checkpoint(signer)
    assert sckpt["signature"] is not None

