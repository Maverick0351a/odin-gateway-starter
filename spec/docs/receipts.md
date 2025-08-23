# Receipts

A **Receipt** attests to normalization + policy evaluation of an accepted envelope.

Minimal fields:
```jsonc
{
  "trace_id": "...",
  "cid": "sha256:...",         // original payload CID
  "normalized_cid": "sha256:...", // post-transform CID
  "payload_type": "vendor.event.v1",
  "target_type": "canonical.event.v1",
  "ts": "2025-08-23T12:34:56Z",
  "prev_receipt_hash": "sha256:..." ,
  "policy_engine": "hel|rego",
  "allow": true,
  "signature": "b64u...",      // gateway Ed25519 over canonical receipt json hash pattern
  "receipt_hash": "sha256:..."  // hash(canonical_receipt_json)
}
```

Optional extensions (additive only): `policy_reason`, `transform_meta`, `tenant_id`, `tenant_signatures`.

`tenant_signatures` array entries (BYOK dual-sign):
```
<request_cid>|<normalized_cid>|<trace_id>|<prev_receipt_hash?>
```
Ed25519 signatures by tenant key over the above string.
