import json
import logging
import os
import pathlib
import random
import time
from typing import Any, Callable, Dict, List, Optional

try:  # runtime import; types optionally ignored via mypy config section
    from google.cloud import firestore  # type: ignore
except Exception:  # pragma: no cover - import guard
    firestore = None  # type: ignore
logger = logging.getLogger("odin.firestore")

class ReceiptStore:
    def __init__(self, project_id: Optional[str] = None, collection: Optional[str] = None):
        # Project resolution order: explicit arg > FIRESTORE_PROJECT_ID > GOOGLE_CLOUD_PROJECT
        self.project_id = project_id or os.getenv("FIRESTORE_PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.collection_name = collection or os.getenv("FIRESTORE_COLLECTION", "receipts")
        # Use repo/workdir-local fallback instead of /mnt (which may require root in CI runners)
        self._local_path = pathlib.Path(os.getenv("ODIN_LOCAL_RECEIPTS", "odin_receipts.jsonl"))
        self._client = None
        self._healthy = False
        self._last_error: Optional[str] = None
        self._last_write_ts: Optional[str] = None
        if firestore and self.project_id:
            try:
                self._client = firestore.Client(project=self.project_id)
                # simple ping: list collections (may raise if perms missing)
                _ = list(self._client.collections())
                self._healthy = True
                logger.info(f"Initialized Firestore client for project={self.project_id} collection={self.collection_name}")
            except Exception as e:
                logger.warning(f"Firestore init failed, fallback to local JSONL: {e}")
                self._last_error = str(e)
                self._client = None
        else:
            if not firestore:
                logger.info("google-cloud-firestore not installed; using local JSONL store")
            else:
                logger.info("No FIRESTORE_PROJECT_ID/GOOGLE_CLOUD_PROJECT set; using local JSONL store")
        # Retention configuration (local mode only)
        def _get_int(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)))
            except Exception:
                return default
        self._retention_max_lines = _get_int("ODIN_RETENTION_MAX_LOCAL_LINES", 0)  # 0 = unlimited
        self._retention_max_age_sec = _get_int("ODIN_RETENTION_MAX_AGE_SECONDS", 0)  # 0 = unlimited
        # Firestore TTL: If FIRESTORE_TTL_DAYS set, users should configure a TTL policy on field 'created_at'.
        # We record the config for health visibility but do not enforce deletes client-side (let Firestore TTL do it).
        self._firestore_ttl_days = _get_int("FIRESTORE_TTL_DAYS", 0)
        # Local hop counters to preserve monotonic hop numbering even if earlier receipts are pruned.
        self._hop_counters: Dict[str, int] = {}

    # ---------------- Retention (local mode) ----------------
    def _prune_local(self):
        """Apply age and line-count retention to the local JSONL file.

        Broken into helper steps to keep complexity low. Firestore mode returns immediately.
        """
        if self._client:
            return
        if self._retention_max_lines <= 0 and self._retention_max_age_sec <= 0:
            return
        if not self._local_path.exists():
            return
        try:
            lines = self._local_path.read_text(encoding='utf-8').splitlines()
            lines = self._filter_age(lines)
            lines = self._enforce_line_cap(lines)
            tmp = self._local_path.with_suffix('.tmp')
            tmp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding='utf-8')
            tmp.replace(self._local_path)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"Retention prune failed: {e}")

    def _filter_age(self, lines: List[str]) -> List[str]:
        if self._retention_max_age_sec <= 0:
            return lines
        import datetime
        import json
        cutoff = datetime.datetime.now(datetime.timezone.utc).timestamp() - self._retention_max_age_sec
        kept: List[str] = []
        for ln in lines:
            try:
                doc = json.loads(ln)
                ts_raw = doc.get('ts') or doc.get('created_at')
                if not ts_raw:
                    continue
                # Normalize common formats; accept trailing 'Z'
                if ts_raw.endswith('Z'):
                    ts_norm = ts_raw[:-1] + '+00:00'
                else:
                    ts_norm = ts_raw
                try:
                    dt = datetime.datetime.fromisoformat(ts_norm)
                except Exception:
                    # Fallback: attempt parsing without microseconds or timezone
                    try:
                        dt = datetime.datetime.strptime(ts_raw.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                        dt = dt.replace(tzinfo=datetime.timezone.utc)
                    except Exception:
                        continue
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                if dt.timestamp() >= cutoff:
                    kept.append(ln)
            except Exception:
                continue
        return kept

    def _enforce_line_cap(self, lines: List[str]) -> List[str]:
        if self._retention_max_lines > 0 and len(lines) > self._retention_max_lines:
            return lines[-self._retention_max_lines:]
        return lines
    def _write_local(self, doc: Dict[str, Any]):
        self._local_path.parent.mkdir(parents=True, exist_ok=True)
        with self._local_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(doc) + "\n")
    def _retry(self, fn: Callable[[], Any], attempts: int = 3, base_delay: float = 0.2) -> Any:
        for i in range(attempts):
            try:
                return fn()
            except Exception as e:
                self._last_error = str(e)
                if i == attempts - 1:
                    raise
                time.sleep(base_delay * (2 ** i) + random.random() * 0.05)

    def add_receipt(self, receipt: Dict[str, Any]) -> int:
        """Add a receipt to Firestore or local store, returning assigned hop index."""
        trace_id_any: Any = receipt.get("trace_id")
        if not isinstance(trace_id_any, str) or not trace_id_any:
            raise ValueError("receipt.trace_id must be a non-empty string")
        trace_id: str = trace_id_any
        if self._client:
            return self._add_firestore(trace_id, receipt)
        return self._add_local(trace_id, receipt)

    # --- Firestore helpers ---
    def _add_firestore(self, trace_id: str, receipt: Dict[str, Any]) -> int:
        if firestore is None:
            raise RuntimeError("Firestore library not available")
        if self._client is None:
            raise RuntimeError("Firestore client not initialized")
        client = self._client  # treat as firestore.Client
        coll = client.collection(self.collection_name).document(trace_id).collection("hops")
        base_ref = client.collection(self.collection_name).document(trace_id)
        try:
            @firestore.transactional
            def _tx(transaction, base_ref_inner):
                snap = base_ref_inner.get(transaction=transaction)
                meta = snap.to_dict() if snap.exists else {}
                current = int(meta.get("count", 0))
                meta["count"] = current + 1
                transaction.set(base_ref_inner, meta)
                return current
            transaction = client.transaction()
            hop = self._retry(lambda: _tx(transaction, base_ref))
            receipt["hop"] = hop
            self._retry(lambda: coll.document(f"{hop}").set(receipt))
            self._last_write_ts = receipt.get("ts") or receipt.get("created_at")
            return hop
        except Exception as e:  # pragma: no cover - rare fallback
            logger.warning(f"Firestore hop transaction failed, fallback to query method: {e}")
            try:
                snap = coll.stream()
                hop = sum(1 for _ in snap)
            except Exception:
                hop = 0
            receipt["hop"] = hop
            try:
                coll.document(f"{hop}").set(receipt)
                self._last_write_ts = receipt.get("ts") or receipt.get("created_at")
            except Exception as ee:
                self._last_error = str(ee)
            return hop

    # --- Local helpers ---
    def _add_local(self, trace_id: str, receipt: Dict[str, Any]) -> int:
        # Prune first so aged / excess lines are removed before determining hop.
        # Hop numbering remains monotonic via _hop_counters.
        self._prune_local()
        hop = self._next_local_hop(trace_id)
        receipt["hop"] = hop
        self._write_local(receipt)
        self._last_write_ts = receipt.get("ts") or receipt.get("created_at")
        # Apply pruning after writing.
        self._prune_local()
        return hop

    def _next_local_hop(self, trace_id: str) -> int:
        # Fast path: if we've already assigned hops for this trace_id, advance counter.
        if trace_id in self._hop_counters:
            nxt = self._hop_counters[trace_id]
            self._hop_counters[trace_id] = nxt + 1
            return nxt
        # Initial scan: determine max existing hop (if any) for this trace.
        max_hop = -1
        if self._local_path.exists():
            try:
                with self._local_path.open('r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            doc = json.loads(line)
                        except Exception:
                            continue
                        if doc.get('trace_id') == trace_id:
                            h = doc.get('hop')
                            if isinstance(h, int) and h > max_hop:
                                max_hop = h
            except Exception:
                max_hop = -1
        # Next hop is max_hop + 1 (starts at 0 if none found)
        nxt = max_hop + 1
        self._hop_counters[trace_id] = nxt + 1  # store next assignment value
        return nxt
    def get_chain(self, trace_id: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if self._client:
            base = self._client.collection(self.collection_name).document(trace_id)
            hops_coll = base.collection("hops")
            try:
                snap_iter = hops_coll.stream()
                for doc in snap_iter:
                    results.append(doc.to_dict())
            except Exception as e:
                logger.warning(f"Firestore read error: {e}")
            results.sort(key=lambda d: d.get("hop", 0))
        else:
            if self._local_path.exists():
                with self._local_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            doc = json.loads(line)
                        except Exception:
                            continue
                        if doc.get("trace_id") == trace_id:
                            results.append(doc)
                results.sort(key=lambda d: d.get("hop", 0))
        return results

    def health(self) -> Dict[str, Any]:
        return {
            "mode": "firestore" if self._client else "local",
            "project": self.project_id,
            "collection": self.collection_name,
            "healthy": bool(self._client and self._healthy),
            "last_write": self._last_write_ts,
            "last_error": self._last_error,
            "firestore_ttl_days": getattr(self, "_firestore_ttl_days", 0),
        }
