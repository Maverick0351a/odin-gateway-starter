"""Transparency Log (experimental)

Maintains an in-memory Merkle tree of receipt hashes (hex strings) to allow
auditors to verify append-only integrity independently from receipt chaining.

Design (v0):
  * Leaves are the 64-hex-character sha256 receipt_hash values (already hex).
  * Internal node hashing: sha256( bytes.fromhex(left) + bytes.fromhex(right) ).hexdigest()
  * For an odd number of nodes at a level, the last node is promoted upward unchanged.
  * Root for 0 leaves is None.
  * This minimal implementation does not yet provide inclusion proofs; only the root.

Future:
  * Persist leaves (e.g., JSONL) for reproducible proof generation.
  * Generate inclusion / consistency proofs (RFC6962-style) on demand.
  * Optionally embed the transparency root in signed receipts (would require
    computing root pre-sign or a two-phase receipt signature design).
"""
from __future__ import annotations
from typing import List, Optional, Callable
import threading, hashlib, os
from datetime import datetime, timezone

class TransparencyLog:
    def __init__(self, path: Optional[str] = None):
        """Create a transparency log.

        Args:
            path: Optional file path for persistence. When provided the file is a
                  newline-delimited list of 64-hex-character leaves. On startup
                  the file (if present) is replayed to rebuild the in-memory tree.
        """
        self._leaves: List[str] = []  # hex sha256 leaf values
        self._lock = threading.RLock()
        self._cached_root: Optional[str] = None
        self._dirty = True
        self._path = path
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        h = line.strip()
                        if h:
                            if len(h) == 64:
                                int(h, 16)  # validate
                                self._leaves.append(h)
                self._dirty = True
            except Exception:
                # Corruption or partial write; safest is to ignore (tree can continue from valid subset)
                self._dirty = True

    def add_leaf(self, leaf_hash: str) -> int:
        """Append a new leaf (hex sha256) and return its index."""
        if not isinstance(leaf_hash, str) or len(leaf_hash) != 64:
            raise ValueError("leaf_hash must be 64-char hex sha256")
        int(leaf_hash, 16)
        with self._lock:
            self._leaves.append(leaf_hash)
            self._dirty = True
            if self._path:
                try:
                    with open(self._path, 'a', encoding='utf-8') as f:
                        f.write(leaf_hash + '\n')
                except Exception:
                    # Persistence failure should not block append-only property in-memory
                    pass
            return len(self._leaves) - 1

    def size(self) -> int:
        with self._lock:
            return len(self._leaves)

    def root(self) -> Optional[str]:
        with self._lock:
            if not self._dirty:
                return self._cached_root
            if not self._leaves:
                self._cached_root = None
                self._dirty = False
                return None
            level = self._leaves[:]
            while len(level) > 1:
                nxt: List[str] = []
                it = iter(level)
                for left in it:
                    try:
                        right = next(it)
                    except StopIteration:
                        # odd count, promote
                        nxt.append(left)
                        break
                    h = hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
                    nxt.append(h)
                level = nxt
            self._cached_root = level[0]
            self._dirty = False
            return self._cached_root

    # Inclusion proof (audit path) generation using same pairing logic (RFC6962-like variant with promotion semantics)
    def audit_path(self, index: int) -> List[dict]:
        with self._lock:
            if index < 0 or index >= len(self._leaves):
                raise IndexError("leaf index out of range")
            path: List[dict] = []
            level = self._leaves[:]
            idx = index
            while len(level) > 1:
                nxt: List[str] = []
                for i in range(0, len(level), 2):
                    left = level[i]
                    if i + 1 < len(level):
                        right = level[i + 1]
                        node_hash = hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
                        nxt.append(node_hash)
                        if i == idx or i + 1 == idx:
                            if i == idx:  # current is left
                                path.append({"sibling": right, "side": "right"})
                                idx = len(nxt) - 1
                            else:
                                path.append({"sibling": left, "side": "left"})
                                idx = len(nxt) - 1
                    else:
                        # promotion
                        nxt.append(left)
                        if i == idx:
                            idx = len(nxt) - 1
                level = nxt
            return path

    @staticmethod
    def verify_inclusion(leaf_hash: str, index: int, tree_size: int, path: List[dict], expected_root: str) -> bool:
        # Rebuild root from leaf and path
        try:
            int(leaf_hash, 16)
            int(expected_root, 16)
        except Exception:
            return False
        h = leaf_hash
        idx = index
        for entry in path:
            sib = entry.get("sibling")
            side = entry.get("side")
            if not sib or not side:
                return False
            try:
                int(sib, 16)
            except Exception:
                return False
            if side == "right":  # current is left
                h = hashlib.sha256(bytes.fromhex(h) + bytes.fromhex(sib)).hexdigest()
            elif side == "left":  # current is right
                h = hashlib.sha256(bytes.fromhex(sib) + bytes.fromhex(h)).hexdigest()
            else:
                return False
            idx //= 2
        return h == expected_root

    def snapshot(self) -> dict:
        with self._lock:
            return {"size": len(self._leaves), "root": self.root()}

    # --- Checkpointing ---
    def checkpoint(self, signer: Optional[Callable[[bytes], bytes]] = None) -> dict:
        """Produce a signed checkpoint (root, size, ts, signature pattern root|size|ts).

        Args:
            signer: Callable returning signature bytes for provided message; if None, no signature included.
        Returns:
            dict with root, size, ts, pattern, signature (base64url if signer given) and signing_kid when available.
        """
        from .crypto import b64u_encode  # local import to avoid cycle
        root = self.root()
        size = self.size()
        ts = datetime.now(timezone.utc).isoformat()
        pattern = f"{root or ''}|{size}|{ts}"
        sig_b64 = None
        kid = None
        if signer:
            try:
                sig = signer(pattern.encode('utf-8'))
                if isinstance(sig, tuple):  # allow (sig_bytes, kid)
                    sig, kid = sig
                sig_b64 = b64u_encode(sig)
            except Exception:
                sig_b64 = None
        data = {"root": root, "size": size, "ts": ts, "pattern": pattern, "signature": sig_b64, "kid": kid}
        return data

    @staticmethod
    def verify_checkpoint(checkpoint: dict, jwk: dict) -> bool:
        """Verify a checkpoint signature with a provided JWK.

        Expects signature over pattern root|size|ts using Ed25519.
        """
        try:
            from . import verify_with_jwk
            sig = checkpoint.get("signature")
            pattern = checkpoint.get("pattern")
            if not sig or not pattern:
                return False
            return verify_with_jwk(jwk, pattern.encode('utf-8'), sig)
        except Exception:
            return False

__all__ = ["TransparencyLog"]
