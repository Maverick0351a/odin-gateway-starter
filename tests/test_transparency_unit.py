import hashlib
from odin_core.transparency import TransparencyLog


def test_transparency_log_basic_inclusion():
    log = TransparencyLog()
    leaf_hashes = []
    for i in range(6):
        cid = f"sha256:demo{i}"
        h = hashlib.sha256(cid.encode()).hexdigest()
        idx = log.add_leaf(h)
        leaf_hashes.append((idx, h))
    # verify each inclusion
    root = log.root()
    assert root
    for idx, h in leaf_hashes:
        path = log.audit_path(idx)
        assert TransparencyLog.verify_inclusion(h, idx, log.size(), path, root)