import os, json, time, pathlib
from odin_core.firestore_log import ReceiptStore

def _make_receipt(trace_id: str, hop: int, ts: str):
    return {"trace_id": trace_id, "hop": hop, "ts": ts, "created_at": ts, "receipt_hash": f"h{hop}"}

def test_retention_line_cap(tmp_path):
    path = tmp_path / 'receipts.jsonl'
    os.environ['ODIN_LOCAL_RECEIPTS'] = str(path)
    os.environ['ODIN_RETENTION_MAX_LOCAL_LINES'] = '5'
    store = ReceiptStore()
    # Add 10 receipts same trace
    import datetime
    for i in range(10):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        r = _make_receipt('t1', i, ts)
        store.add_receipt(r)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 5  # only last 5 kept
    # Ensure hops are the last 5
    hops = [json.loads(l)['hop'] for l in lines]
    assert hops == [5,6,7,8,9]


def test_retention_age_cap(tmp_path):
    path = tmp_path / 'receipts_age.jsonl'
    os.environ['ODIN_LOCAL_RECEIPTS'] = str(path)
    os.environ['ODIN_RETENTION_MAX_LOCAL_LINES'] = '0'
    os.environ['ODIN_RETENTION_MAX_AGE_SECONDS'] = '1'
    store = ReceiptStore()
    import datetime
    old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)).isoformat()
    # old receipt
    store.add_receipt(_make_receipt('t2', 0, old_ts))
    time.sleep(0.2)
    new_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    store.add_receipt(_make_receipt('t2', 1, new_ts))
    # After pruning only new receipt should remain
    lines = [l for l in path.read_text().strip().splitlines() if l]
    assert len(lines) == 1
    doc = json.loads(lines[0])
    # After pruning hop may reset to 0 because prior entry aged out before assignment
    assert doc['hop'] in (0,1)
