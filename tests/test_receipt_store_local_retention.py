import os, json, time, tempfile, pathlib
from datetime import datetime, timedelta, timezone
from odin_core.firestore_log import ReceiptStore


def _mk_receipt(trace="t1", ts=None, hop=None):
    return {"trace_id": trace, "ts": ts or datetime.now(timezone.utc).isoformat(), "receipt_hash": f"h{hop or 0}"}


def test_local_add_and_monotonic_hops(tmp_path, monkeypatch):
    fp = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("ODIN_LOCAL_RECEIPTS", str(fp))
    store = ReceiptStore(project_id=None)  # force local
    r0 = _mk_receipt(hop=0)
    h0 = store.add_receipt(r0)
    assert h0 == 0
    r1 = _mk_receipt(hop=1)
    h1 = store.add_receipt(r1)
    assert h1 == 1
    chain = store.get_chain(r0["trace_id"])
    assert [c["hop"] for c in chain] == [0,1]


def test_retention_line_cap(tmp_path, monkeypatch):
    fp = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("ODIN_LOCAL_RECEIPTS", str(fp))
    monkeypatch.setenv("ODIN_RETENTION_MAX_LOCAL_LINES", "3")
    store = ReceiptStore(project_id=None)
    for i in range(5):
        store.add_receipt(_mk_receipt(trace="cap", hop=i))
    # File should only keep last 3 lines
    text = fp.read_text()
    lines = [l for l in text.strip().splitlines() if l]
    assert len(lines) == 3
    hops = [json.loads(l)["hop"] for l in lines]
    assert hops == [2,3,4]


def test_retention_age_filter(tmp_path, monkeypatch):
    fp = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("ODIN_LOCAL_RECEIPTS", str(fp))
    monkeypatch.setenv("ODIN_RETENTION_MAX_AGE_SECONDS", "1")
    store = ReceiptStore(project_id=None)
    old_ts = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    store.add_receipt(_mk_receipt(trace="age", hop=0, ts=old_ts))
    time.sleep(1.2)
    store.add_receipt(_mk_receipt(trace="age", hop=1))
    # After prune, only newer receipt should remain in file
    text = fp.read_text()
    lines = [l for l in text.strip().splitlines() if l]
    parsed = [json.loads(l) for l in lines]
    hops = [p["hop"] for p in parsed]
    assert hops == [1]


def test_health_local_mode(tmp_path, monkeypatch):
    fp = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("ODIN_LOCAL_RECEIPTS", str(fp))
    store = ReceiptStore(project_id=None)
    store.add_receipt(_mk_receipt())
    h = store.health()
    assert h["mode"] == "local" and h["healthy"] is False
