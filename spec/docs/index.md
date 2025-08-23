# Open Proof Envelope (OPE) Protocol

Draft v1.0 specification. This site defines wire formats, signing semantics, and verification procedures for ODIN OPE.

## Goals
* Cryptographically bound, machine-verifiable envelopes
* Deterministic canonical JSON CIDs
* Hash-linked receipts for append-only lineage
* Export bundles enabling offline attestation
* Transparency log (Merkle) to detect equivocation

## Non-Goals
* Transport encryption (use HTTPS)
* Confidential payload protection (encryption layer may be profiled later)

## Document Status
> draft – feedback welcome. Breaking changes possible until `v1.0.0` tag.

---
