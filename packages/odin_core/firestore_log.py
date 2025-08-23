from typing import Dict, Any, List, Optional
import os, json, pathlib, time, logging, random
try:
    from google.cloud import firestore
except Exception:
    firestore = None
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

    # ---------------- Retention (local mode) ----------------
    def _prune_local(self):
        if self._client:
            return  # Firestore pruning not implemented
        if self._retention_max_lines <= 0 and self._retention_max_age_sec <= 0:
            return
        try:
            if not self._local_path.exists():
                return
            raw_lines = self._local_path.read_text(encoding='utf-8').splitlines()
            # Preserve chronological order as written
            lines = raw_lines
            # Age filtering
            if self._retention_max_age_sec > 0:
                import json, datetime
                cutoff = datetime.datetime.now(datetime.timezone.utc).timestamp() - self._retention_max_age_sec
                kept = []
                for ln in lines:
                    try:
                        doc = json.loads(ln)
                        ts_raw = doc.get('ts') or doc.get('created_at')
                        if not ts_raw:
                            continue
                        try:
                            dt = datetime.datetime.fromisoformat(ts_raw)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=datetime.timezone.utc)
                            if dt.timestamp() >= cutoff:
                                kept.append(ln)
                        except Exception:
                            continue
                    except Exception:
                        continue
                lines = kept
            # Line count pruning (keep newest)
            if self._retention_max_lines > 0 and len(lines) > self._retention_max_lines:
                # Keep newest by original order
                lines = lines[-self._retention_max_lines:]
            tmp = self._local_path.with_suffix('.tmp')
            tmp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding='utf-8')
            tmp.replace(self._local_path)
        except Exception as e:
            logger.warning(f"Retention prune failed: {e}")
    def _write_local(self, doc: Dict[str, Any]):
        self._local_path.parent.mkdir(parents=True, exist_ok=True)
        with self._local_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(doc) + "\n")
    def _retry(self, fn, attempts=3, base_delay=0.2):
        for i in range(attempts):
            try:
                return fn()
            except Exception as e:
                self._last_error = str(e)
                if i == attempts - 1:
                    raise
                time.sleep(base_delay * (2 ** i) + random.random() * 0.05)

    def add_receipt(self, receipt: Dict[str, Any]) -> int:
        trace_id = receipt.get("trace_id")
        if self._client:
            coll = self._client.collection(self.collection_name).document(trace_id).collection("hops")
            # Atomic hop: create placeholder doc with server timestamp then count existing docs once
            base = self._client.collection(self.collection_name).document(trace_id)
            try:
                # Use a transaction to assign hop index
                @firestore.transactional
                def _tx(transaction, base_ref):
                    snap = base_ref.get(transaction=transaction)
                    meta = {}
                    if snap.exists:
                        meta = snap.to_dict() or {}
                        current = int(meta.get("count", 0))
                    else:
                        current = 0
                    hop_index = current
                    meta["count"] = current + 1
                    transaction.set(base_ref, meta)
                    return hop_index
                transaction = self._client.transaction()
                hop = self._retry(lambda: _tx(transaction, self._client.collection(self.collection_name).document(trace_id)))
                receipt["hop"] = hop
                self._retry(lambda: coll.document(f"{hop}").set(receipt))
                self._last_write_ts = receipt.get("ts") or receipt.get("created_at")
                return hop
            except Exception as e:
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
        else:
            # Prune first so hop assignment only considers retained entries
            self._prune_local()
            hop = 0
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
                                if isinstance(h, int) and h >= hop:
                                    hop = h + 1
                except Exception:
                    hop = 0
            receipt["hop"] = hop
            self._write_local(receipt)
            self._last_write_ts = receipt.get("ts") or receipt.get("created_at")
            # Final prune to enforce line count if needed
            self._prune_local()
            return hop
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
