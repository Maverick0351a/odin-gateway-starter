# Transparency Log

Gateway maintains a Merkle tree of `sha256(<bundle_cid>)` leaves appended per export.

Checkpoint signing string:
```
<root>|<size>|<ts>
```
Empty tree: root = "", size = 0.

Inclusion proof `audit_path` entries:
```json
{"side": "left|right", "sibling": "<hex>"}
```

Verification (leaf inclusion): iteratively hash combining sibling per side until candidate == checkpoint root.

Roadmap (future work):
* Consistency proofs between checkpoints (`from_size`→`to_size`)
* External anchoring (timestamping service / blockchain)
