# ODIN OPE (Open Proof Envelope) v1.0 Specification

Status: v1.0 (REFERENCE IMPLEMENTATION: this repository)
Tag: `ope-v1.0`

## 1. Canonicalization & Content Identifier (CID)

Canonical JSON serialization rules:
1. UTF-8 encoding without BOM.
2. JSON objects serialized with lexicographic key ordering (Python `sort_keys=True` semantics; byte-wise comparison of Unicode code points).
3. No additional whitespace: item separator `,` and key separator `:` only (Python `json.dumps(..., separators=(",", ":"))`).
4. Ensure ASCII disabled (`ensure_ascii=False`) so UTF-8 multibyte characters preserved.
5. No canonicalization applied to numbers beyond host JSON library standard (integers preserved; floats SHOULD avoid representation instability).
6. Excluded fields: (a) In receipt hashing the `receipt_signature` field is excluded prior to hashing; all other object members included.

Content Identifier (CID) format:
```
sha256:<hex_sha256_of_canonical_json_bytes>
```
Example: `sha256:2a7c43b5...` (64 lowercase hex chars after `sha256:`).

## 2. Envelope Signing Context

Signing string pattern (verbatim):
```
"{cid}|{trace_id}|{ts}"
```
Where:
- `cid`: CID of the canonical JSON payload submitted by the sender.
- `trace_id`: UUIDv4 (producer MAY generate; gateway MAY accept externally supplied trace id or generate if absent).
- `ts`: Sender timestamp in RFC 3339 / ISO-8601 with UTC offset (e.g. `2025-08-22T04:18:05.123456+00:00`).

Acceptable clock skew: Gateways SHOULD accept envelopes whose `ts` is within ±300 seconds (5 minutes) of the gateway's current UTC. Future timestamps beyond this window SHOULD be rejected or flagged; past timestamps beyond the window MAY be accepted but SHOULD be flagged for replay risk. (Current reference implementation does NOT yet enforce skew – future hardening.)

## 3. Receipt Schema (Per Hop)

Minimal receipt object (gateway implementation):
```jsonc
{
  "trace_id": "<uuid4>",
  "hop": 0,
  "ts": "<iso-utc>",
  "created_at": "<iso-utc>",
  "gateway_kid": "ed25519-<fingerprint16>",
  "request_cid": "sha256:<hex>",
  "normalized_cid": "sha256:<hex>",
  "policy": { /* policy evaluation result object */ },
  "prev_receipt_hash": null,                // or hex string
  "receipt_signature": "<base64url(ed25519_sig)>",  // signature over canonical JSON w/out this field
  "receipt_hash": "<sha256_hex_of_receipt_without_signature_field>"
}
```
Notes:
- `hop` increments for each processing hop (0-based).
- `prev_receipt_hash` links to previous `receipt_hash` forming a linear hash-linked chain per `trace_id`.
- `receipt_signature` is Ed25519 over canonical JSON BYTES of the receipt object *without* the `receipt_signature` member present (i.e. field omitted entirely before serialization for signing & hashing).
- `receipt_hash` is `sha256` of canonical JSON BYTES of the same signature-stripped object.

## 4. Export Bundle Schema

Export endpoint returns a bundle object for a `trace_id`:
```jsonc
{
  "trace_id": "<uuid4>",
  "exported_at": "<iso-utc>",
  "receipts": [ { ...receipt objects... } ],
  "bundle_cid": "sha256:<hex>",          // CID of canonical JSON of `receipts` array only OR entire bundle? (v1 decision below)
  "bundle_signature": "<base64url(ed25519_sig)>"
}
```
Decision (v1):
- `bundle_cid` = `sha256:` + sha256_hex(canonical JSON of **the entire bundle without `bundle_signature`**). (Implementations MUST verify which variant a peer uses; this spec fixes the meaning for v1.)
- `bundle_signature` = Ed25519 over signing string pattern:
```
"{bundle_cid}|{trace_id}|{exported_at}"
```

## 5. HTTP Headers (Gateway Response Provenance)

Gateways SHOULD emit the following headers on envelope submission responses:
- `X-ODIN-Receipt-Hash`: last appended `receipt_hash`.
- `X-ODIN-Response-CID`: CID of normalized response body (if any).
- `X-ODIN-Signature`: base64url Ed25519 signature over response pattern (implementation specific; MAY mirror request pattern for symmetry).
- `X-ODIN-KID`: Key ID used to sign response / receipts.

## 6. Cryptography

- Key Algorithm: Ed25519 (RFC 8032).
- Private key representation: 32-byte seed (base64url, no padding).
- Public key exposure: JWK (`{"kty":"OKP","crv":"Ed25519","x":"<b64u>","kid":"<kid>"}`) via JWKS endpoint `/.well-known/jwks.json`.
- Signatures base64url encoded without padding.

## 7. Test Vectors

### 7.1 Deterministic Payload Example
Payload JSON (object):
```json
{"message":"hello","value":42}
```
Canonical bytes (UTF-8) -> `{"message":"hello","value":42}` (already ordered) =>
CID:
```
sha256:9b0e1ca5230d7c6e1f8e2b6c1fcf21a5b9eb364f2db6e1b635c1e9c8d1f5e6d4
```
(Example hex placeholder – replace with actual when generating.)

Signing string example (ts=`2025-08-22T00:00:00+00:00`, trace=`11111111-1111-1111-1111-111111111111`):
```
sha256:...|11111111-1111-1111-1111-111111111111|2025-08-22T00:00:00+00:00
```

### 7.2 Receipt Hash Stripping
Given receipt object (pre-signature):
```json
{"trace_id":"t","hop":0,"ts":"T","created_at":"T","gateway_kid":"k","request_cid":"sha256:aaa","normalized_cid":"sha256:bbb","policy":{},"prev_receipt_hash":null}
```
Canonicalization unchanged; signing & hashing that bytes => receipt_hash = sha256_hex(bytes). After adding `receipt_signature`, hash remains stable because excluded.

### 7.3 Bundle Signing
Bundle (without signature field):
```json
{"trace_id":"t","exported_at":"E","receipts":[ { /* r1 */ }, { /* r2 */ } ],"bundle_cid":"PENDING"}
```
Compute canonical JSON -> cid -> sign string:
```
{bundle_cid}|t|E
```

(Implementations SHOULD recompute `bundle_cid` after populating `receipts` before signing.)

### 7.4 Edge Case: Key Rotation
If `gateway_kid` changes mid-trace, subsequent receipts simply carry the new `gateway_kid`. Chain validity only depends on receipt_hash linkage; mixed KIDs are allowed.

### 7.5 Timestamp Skew
Envelope with ts 10 minutes ahead SHOULD be flagged (implementation MAY reject). 2 minutes ahead SHOULD be accepted.

## 8. Minimal Conformance Test Script (Pseudo-Python)

```python
from odin_core.cid import cid_sha256
from odin_core.utils import canonical_json
from odin_core.receipts import hash_receipt

payload = {"message":"hello","value":42}
expected_cid = cid_sha256(canonical_json(payload))
assert expected_cid.startswith("sha256:")

receipt_core = {
  "trace_id":"trace-1",
  "hop":0,
  "ts":"2025-08-22T00:00:00+00:00",
  "created_at":"2025-08-22T00:00:00+00:00",
  "gateway_kid":"ed25519-test",
  "request_cid":expected_cid,
  "normalized_cid":expected_cid,
  "policy":{},
  "prev_receipt_hash":None,
}
# Simulate signature addition after hashing
h = hash_receipt({**receipt_core, "receipt_signature":"IGNORED"})
assert len(h) == 64
print("OPE v1.0 basic conformance PASS")
```

Implementers SHOULD extend this script to verify signature authenticity using a known test key.

## 9. Versioning & Forward Compatibility
- Additive fields allowed (MUST NOT change semantics of existing fields).
- Breaking changes (altering signing string or canonicalization) require new major version (e.g., `v2.0`) and MUST NOT retroactively redefine v1 semantics.

---
End of Specification.
