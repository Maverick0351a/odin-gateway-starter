import os
import json
import pathlib
import time
from datetime import datetime, timezone, timedelta

from packages.odin_core.firestore_log import ReceiptStore


def _mk_receipt(trace_id: str, hop: int, ts: datetime) -> dict:
    return {
        "trace_id": trace_id,
        "hop": hop,
        "ts": ts.isoformat(),
        "receipt_hash": f"rh{hop}-{trace_id}",
        "prev_receipt_hash": f"rh{hop-1}-{trace_id}" if hop else None,
    }


def test_local_retention_line_cap(tmp_path, monkeypatch):
    path = tmp_path / 'receipts.jsonl'
    monkeypatch.setenv('ODIN_LOCAL_RECEIPTS', str(path))
    monkeypatch.setenv('ODIN_RETENTION_MAX_LOCAL_LINES', '3')
    store = ReceiptStore(project_id=None)  # force local
    for i in range(5):
        r = _mk_receipt('t1', i, datetime.now(timezone.utc))
        store.add_receipt(r)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 3  # capped
    # Remaining hops should be last 3
    hops = [json.loads(l)['hop'] for l in lines]
    assert hops == [2,3,4]


def test_local_retention_age(tmp_path, monkeypatch):
    path = tmp_path / 'receipts_age.jsonl'
    monkeypatch.setenv('ODIN_LOCAL_RECEIPTS', str(path))
    monkeypatch.setenv('ODIN_RETENTION_MAX_AGE_SECONDS', '1')
    store = ReceiptStore(project_id=None)
    old_ts = datetime.now(timezone.utc) - timedelta(seconds=5)
    store.add_receipt(_mk_receipt('t2', 0, old_ts))
    time.sleep(1.2)  # ensure cutoff passed
    store.add_receipt(_mk_receipt('t2', 1, datetime.now(timezone.utc)))
    lines = [json.loads(l) for l in path.read_text().strip().splitlines()]
    # Old hop pruned
    hops = [l['hop'] for l in lines]
    assert hops == [1]
