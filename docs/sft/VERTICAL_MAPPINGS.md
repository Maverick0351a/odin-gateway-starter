# SFT Vertical Mappings

This document catalogs the domain specific schema normalization (SFT) mappings currently implemented.
Each mapping is versioned using the canonical *target type* (e.g. `fhir.observation.v1`). Additive
fields result in a new target version (e.g. `...v2`) rather than mutating existing semantics.

## Conventions
* Input (payload) type → Target type (normalized)
* Deterministic canonical JSON: callers MUST produce sorted-key JSON for hashing / CIDs.
* All transforms are pure functions (no network I/O) and must never raise except via `SFTError`.

## Healthcare
| Input | Target | Notes |
|-------|--------|-------|
| `health.observation.vendor.v1` | `fhir.observation.v1` | Maps observation id, code, value/unit, patient id → FHIR minimal Observation. |
| `health.patient.vendor.v1` | `fhir.patient.v1` | Maps patient id, name, gender, birth date → FHIR minimal Patient. |

## Insurance
| Input | Target | Notes |
|-------|--------|-------|
| `insurance.claim_notice.vendor.v1` | `acord.claim_notice.v1` | Simplified ACORD Claim Notice subset (claim number, loss date, insured, description). |

## Procurement
| Input | Target | Notes |
|-------|--------|-------|
| `procurement.match.vendor.v1` | `procurement.match.v1` | 3-way match skeleton (PO, goods receipt, invoice) plus `amounts_consistent` boolean. |

## Finance (Existing)
| Input | Target | Notes |
|-------|--------|-------|
| `openai.tooluse.invoice.v1` | `invoice.iso20022.v1` | Tool-use invoice → minimal ISO 20022 subset. |
| `anthropic.tooluse.invoice.v1` | `invoice.iso20022.v1` | Claude tool-use invoice mapping. |
| `invoice.vendor.v1` | `invoice.iso20022.v1` | Generic vendor invoice mapping. |
| `invoice.iso20022.v1` | `openai.tooluse.invoice.v1` | Reverse mapping (ISO 20022 → OpenAI style). |

## Testing Guarantees
All mappings have pytest coverage asserting:
* Key field placement and renamed paths
* Deterministic boolean computation where applicable (e.g. 3-way match consistency)
* Presence of mapping metadata (`fields_mapped`, `consistency`)

## Roadmap
Planned additions (subject to versioning):
* `fhir.observation.v2` – richer coding (LOINC), status, performer.
* `acord.claim_notice.v2` – policy number, line of business, adjuster contact.
* `procurement.match.v2` – line item array reconciliation + tolerance thresholds.
* `payments.iso20022.pain001.v1` – outbound payment initiation normalization.

Contributions welcome—add new transforms in `odin_core/sft.py`, register with the `@sft` decorator, and extend tests.
