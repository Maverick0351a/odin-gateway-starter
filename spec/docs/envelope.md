# Envelope

An **OPE Envelope** wraps a vendor payload with provenance metadata and an Ed25519 signature.

Signing string pattern:
```
<cid>|<trace_id>|<ts>
```
Where:
* `cid` = `sha256:<hex>` of canonical JSON payload
* `trace_id` = end-to-end correlation id (client-chosen UUID-like)
* `ts` = ISO8601 UTC timestamp (second precision)

Client MUST produce canonical JSON (UTF-8, sorted ascending by key, no insignificant whitespace). Implementations SHOULD reject clocks too far skewed from gateway (`ODIN_MAX_SKEW_SECONDS`).
