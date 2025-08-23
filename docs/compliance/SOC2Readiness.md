# SOC 2 Readiness Checklist (Starter)

| Control Area | Current State | Gap | Planned Action |
|--------------|---------------|-----|----------------|
| Access Control | Admin token + optional API keys | No RBAC/OIDC | Add OIDC-backed admin auth, scoped roles |
| Change Management | PR + CI tests | No audit trail export | Persist PR metadata + automate changelog |
| Logging & Monitoring | Basic health/metrics | No central log agg | Add structured logs + export to SIEM |
| Incident Response | Manual process | No runbooks | Draft runbook + on-call rotation doc |
| Risk Assessment | Threat model draft | Needs periodic review | Schedule quarterly review task |
| Encryption | Ed25519 signatures; TLS assumed | No at-rest encryption doc | Document storage encryption (Firestore, GCS) |
| Availability | Single instance | No redundancy | Add horizontal scaling + health-based restart policy |
| Integrity | Hash chain + Merkle root | Root not persisted | Persist root + publish signed checkpoints |
| Vendor Management | Dependencies pinned | No review cadence log | Automate monthly dependency report |
| Confidentiality | Limited data stored | No data classification | Introduce data classification policy |

Short-Term Focus:
1. Persist transparency log + checkpoint signing
2. Introduce structured audit log for admin + export
3. Implement BYOK dual-sign receipts (integrity & custody evidence)

Evidence Artifacts (to collect):
* CI logs, test reports
* Dependency scan outputs
* Transparency checkpoint signatures
* Key rotation records (KID history)
