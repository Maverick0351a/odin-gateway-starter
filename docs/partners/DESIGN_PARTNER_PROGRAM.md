# ODIN Design Partner Program (Draft)

Goals (Phase 3):
* Validate Open Proof Envelope (OPE) spec across regulated verticals.
* Capture real policy + SFT requirements early (finance ops, healthcare, insurance).
* Produce 2 public case studies + 1 conference talk.

Cohort Targets:
| Vertical | Profiles | Initial Focus |
|----------|----------|---------------|
| FinOps / Payments | B2B SaaS, treasury | ISO 20022 invoices, payment initiation traces |
| Healthcare | Digital health platforms | FHIR Observation/Patient provenance |
| Insurance | Claims automation vendors | ACORD claim notice verifiable exchange |

Partner Benefits:
* Hosted Control Plane + Hosted Verify sandbox (early multi‑tenant UI)
* Priority schema transform (SFT) additions & policy profile tuning
* Dual‑sign (BYOK) custody enablement & per‑tenant JWKS exposure
* Early access to conformance harness & "ODIN Verified" badge
* Optional SIEM feed (audit + transparency checkpoints)

Participation Expectations:
* Bi‑weekly feedback call (30 min) during pilot (≈ 8 weeks)
* Provide at least one anonymized real-world trace for test vectors
* Review draft case study for publication approval

Success Metrics:
* >=3 active partners; >=2 publishable case studies
* Reduction in custom integration time (anecdotal + measured) vs baseline
* Zero unresolved critical cryptographic verification issues in pilot period

Timeline (Tentative):
1. Weeks 1–2: Onboarding, key custody setup, initial envelope flows
2. Weeks 3–4: Policy tuning + SFT gap fill
3. Weeks 5–6: Transparency monitoring + export automation
4. Weeks 7–8: Case study drafting & conformance badge issuance

Security & Data Handling:
* Only deterministic metadata & hashes retained long-term; payload bodies optional (partner opt-in)
* Partner may request data purge at any time (retention controls executed + transparency checkpoint notarized)

Contact: partners@odinprotocol.dev (PGP preferred for sensitive artifacts)
