import datetime
import json
import uuid


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def now_ts_iso() -> str:
    # Use timezone-aware UTC datetime (avoids deprecation warnings)
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
def gen_trace_id() -> str:
    return str(uuid.uuid4())
