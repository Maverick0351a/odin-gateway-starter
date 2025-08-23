"""Structured audit logging helpers.

Provides a minimal append-only JSONL audit log capturing security-relevant
events (admin operations, exports, transparency checkpoints, policy blocks).

Environment:
  ODIN_AUDIT_LOG_PATH : path to JSONL file (default: audit.log). If set to '-' logs go to stdout.
"""
from __future__ import annotations
from typing import Dict, Any, Optional
import os, json, threading, datetime, sys

_PATH = os.getenv("ODIN_AUDIT_LOG_PATH", "audit.log")
_LOCK = threading.RLock()

def _ts() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

def audit(event: str, **fields: Any) -> None:
    rec: Dict[str, Any] = {"ts": _ts(), "event": event}
    rec.update(fields)
    line = json.dumps(rec, separators=(",", ":"))
    with _LOCK:
        if _PATH == "-":
            print(line, file=sys.stdout, flush=True)
        else:
            try:
                with open(_PATH, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                # swallow errors (audit must not break primary path)
                pass

__all__ = ["audit"]
