# Threat Model (Draft)

Scope: Gateway + Relay + Control Plane + Transparency Log (in‑memory) + Receipt Export.

Assets:
1. Signing keys (Ed25519 gateway seed or KMS handles)
2. Receipt log integrity (hash chain + transparency Merkle root)
3. API key secrets (+ HMAC secrets)
4. Tenant metadata (allowlists, custody refs)
5. Export bundles (verifiability artifacts)

Trust Boundaries:
* Client → Gateway: network boundary; authenticate via optional API key + signature.
* Gateway → Relay: controlled egress; policy enforced.
* Gateway ↔ KMS (GCP/AWS/Azure): remote signing; key material confined to provider.
* Admin API: privileged; separated by admin token and (recommended) network controls.

Threats & Mitigations (STRIDE slice):
| Threat | Vector | Impact | Mitigation |
|--------|--------|--------|------------|
| Spoofing | Fake sender JWK | Unauthorized envelopes | Ed25519 verification + KID tracking; optional HMAC layer |
| Tampering | Receipt log edit | Break integrity/audit | Hash chaining + export signature + transparency root |
| Repudiation | Sender denies action | Dispute of operation | Signed envelopes + receipt timestamp + trace_id |
| Information Disclosure | Key leak | Signature forgery | KMS / env isolation; rotate KIDs; minimize seed exposure |
| DoS | High rate tenant | Service exhaustion | Per-tenant RPM rate limits + future global limiter |
| Elevation | Admin token theft | Full control plane takeover | Rotate token; restrict network; plan mTLS / OIDC |

Open Items:
* Persistence for transparency log (currently memory only)
* Replay protection (nonce / timestamp skew enforcement)
* Dual-sign BYOK receipts (currently metadata only)
* Structured audit logging for admin actions

Roadmap Mitigations:
* Add monotonic timestamp + max age check
* Persist transparency log to append-only storage (e.g. Cloud Storage + signed checkpoint)
* Implement BYOK co-sign flow & JWKS per tenant
* Integrate structured logging → SIEM
