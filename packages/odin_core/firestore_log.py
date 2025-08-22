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
        self._local_path = pathlib.Path(os.getenv("ODIN_LOCAL_RECEIPTS", "/mnt/data/odin_receipts.jsonl"))
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
            existing = self.get_chain(trace_id)
            hop = len(existing)
            receipt["hop"] = hop
            self._write_local(receipt)
            self._last_write_ts = receipt.get("ts") or receipt.get("created_at")
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
        }
