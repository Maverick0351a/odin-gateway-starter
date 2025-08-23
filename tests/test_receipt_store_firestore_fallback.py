import os, sys, pathlib, json

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

# Force environment such that Firestore module appears absent
os.environ.pop('FIRESTORE_PROJECT_ID', None)
os.environ.pop('GOOGLE_CLOUD_PROJECT', None)

from odin_core.firestore_log import ReceiptStore  # noqa


def test_local_mode_health_and_add(tmp_path):
    local_file = tmp_path / 'test_local_receipts_fallback.jsonl'
    os.environ['ODIN_LOCAL_RECEIPTS'] = str(local_file)
    # Ensure no google-cloud-firestore import by simulating absence even if installed
    store = ReceiptStore()
    assert store.health()['mode'] == 'local'
    rec = {"trace_id": "fsfb", "receipt_hash": "h1", "ts": "2024-01-01T00:00:00+00:00"}
    hop = store.add_receipt(rec)
    # First hop should be 0 in a fresh file
    assert hop == 0
    chain = store.get_chain('fsfb')
    assert len(chain) == 1


def test_local_mode_retention_line_cap(tmp_path, monkeypatch):
    monkeypatch.setenv('ODIN_RETENTION_MAX_LOCAL_LINES', '2')
    path = tmp_path / 'receipts_cap.jsonl'
    monkeypatch.setenv('ODIN_LOCAL_RECEIPTS', str(path))
    store = ReceiptStore()
    for i in range(5):
        store.add_receipt({"trace_id": "cap", "receipt_hash": f"h{i}", "ts": f"2024-01-01T00:00:0{i}+00:00"})
    chain = store.get_chain('cap')
    # Hops should still be monotonic even if earlier lines pruned
    hops = [c['hop'] for c in chain]
    assert hops == sorted(hops)
    assert max(hops) >= 4  # we inserted 5
