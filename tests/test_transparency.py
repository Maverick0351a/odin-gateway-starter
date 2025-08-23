from odin_core.transparency import TransparencyLog

def test_transparency_merkle_root_progression():
    tl = TransparencyLog()
    assert tl.root() is None
    # Add one leaf
    leaf1 = '0'*64
    tl.add_leaf(leaf1)
    r1 = tl.root()
    assert r1 == leaf1
    # Add second leaf distinct, root should change and not equal either leaf directly necessarily
    leaf2 = '1'*64
    tl.add_leaf(leaf2)
    r2 = tl.root()
    assert r2 is not None and r2 != r1
    # Size reflects two leaves
    snap = tl.snapshot()
    assert snap['size'] == 2