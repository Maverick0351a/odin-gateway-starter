# Export Bundles

An **Export Bundle** captures an ordered, contiguous sequence of receipts for a single `trace_id` plus integrity metadata.

Bundle signing string:
```
<bundle_cid>|<trace_id>|<exported_at>
```
`bundle_cid` = `sha256:<hex>` over canonical JSON of the bundle object (excluding gateway signature field itself).

Verification steps:
1. Canonicalize bundle JSON, hash → matches `bundle_cid`.
2. Recompute receipt linkage: each `prev_receipt_hash` matches previous `receipt_hash`.
3. Verify Ed25519 signature against gateway JWKS.
4. (Optional) Validate inclusion proof in transparency log (see transparency section).
