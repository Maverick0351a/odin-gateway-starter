import os, sys, pathlib

PKG_DIR = pathlib.Path(__file__).resolve().parents[1] / 'packages'
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

import types
import importlib

import odin_core.firestore_log as fs_mod  # noqa
from odin_core.firestore_log import ReceiptStore  # noqa

# ---------------- Mock Firestore primitives -----------------
class MockTransaction:
    pass

class MockDocumentSnapshot:
    def __init__(self, meta):
        self._meta = meta
        self.exists = bool(meta)
    def to_dict(self):
        return dict(self._meta)

class MockHopDoc:
    def __init__(self, trace_store, trace_id, hop_id):
        self._trace_store = trace_store
        self._trace_id = trace_id
        self._hop_id = hop_id
    def set(self, receipt):
        self._trace_store.setdefault(self._trace_id, {})[self._hop_id] = dict(receipt)

class MockHopCollection:
    def __init__(self, trace_store, trace_id):
        self._trace_store = trace_store
        self._trace_id = trace_id
    def document(self, hop):
        return MockHopDoc(self._trace_store, self._trace_id, int(hop))
    def stream(self):
        # Return in insertion order by hop id
        for hop in sorted(self._trace_store.get(self._trace_id, {}).keys()):
            rec = self._trace_store[self._trace_id][hop]
            yield types.SimpleNamespace(to_dict=lambda r=rec: r)

class MockDocumentRef:
    def __init__(self, parent, trace_store, trace_id):
        self._parent = parent
        self._trace_store = trace_store
        self._trace_id = trace_id
        self._meta = {}
    def get(self, transaction=None):
        return MockDocumentSnapshot(self._meta)
    def collection(self, name):
        if name == 'hops':
            return MockHopCollection(self._parent._trace_store, self._trace_id)
        raise KeyError(name)

class MockCollectionRoot:
    def __init__(self, trace_store, name):
        self._trace_store = trace_store
        self._name = name
    def document(self, trace_id):
        return MockDocumentRef(self, self._trace_store, trace_id)

class MockFirestoreClient:
    def __init__(self, project=None):
        self._trace_store = {}
    def collections(self):
        return []
    def collection(self, name):
        return MockCollectionRoot(self._trace_store, name)
    def transaction(self):
        return MockTransaction()

# transactional decorator just executes function with transaction and docref
class MockFirestoreModule(types.SimpleNamespace):
    def transactional(self, fn):  # acts like decorator factory
        def decorated(inner_fn):
            def wrapper(transaction, base_ref_inner):
                return inner_fn(transaction, base_ref_inner)
            return wrapper
        # our code uses @firestore.transactional on inline fn, so emulate by returning fn itself
        def passthrough(inner_fn):
            return inner_fn
        return passthrough
    Client = MockFirestoreClient

# Failing variant to trigger fallback in _add_firestore
class FailingMockFirestoreModule(MockFirestoreModule):
    def transactional(self, fn):
        def passthrough(inner_fn):
            def wrapper(transaction, base_ref_inner):
                raise RuntimeError('tx failure')
            return wrapper
        return passthrough

# ---------------- Tests -----------------

def test_firestore_happy_path(monkeypatch):
    monkeypatch.setenv('FIRESTORE_PROJECT_ID', 'test-proj')
    monkeypatch.setattr(fs_mod, 'firestore', MockFirestoreModule())
    store = ReceiptStore()
    assert store.health()['mode'] == 'firestore'
    hop = store.add_receipt({'trace_id': 't1', 'receipt_hash': 'h1', 'ts': '2024-01-01T00:00:00+00:00'})
    assert hop == 0
    hop2 = store.add_receipt({'trace_id': 't1', 'receipt_hash': 'h2', 'ts': '2024-01-01T00:01:00+00:00'})
    assert hop2 == 1
    chain = store.get_chain('t1')
    assert {c['hop'] for c in chain} == {0,1}


def test_firestore_transaction_fallback(monkeypatch):
    monkeypatch.setenv('FIRESTORE_PROJECT_ID', 'test-proj2')
    monkeypatch.setattr(fs_mod, 'firestore', FailingMockFirestoreModule())
    store = ReceiptStore()
    assert store.health()['mode'] == 'firestore'
    hop = store.add_receipt({'trace_id': 'tf', 'receipt_hash': 'hA', 'ts': '2024-01-01T00:00:00+00:00'})
    assert hop == 0
    hop2 = store.add_receipt({'trace_id': 'tf', 'receipt_hash': 'hB', 'ts': '2024-01-01T00:05:00+00:00'})
    assert hop2 == 1
