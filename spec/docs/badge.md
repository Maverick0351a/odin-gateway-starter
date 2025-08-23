# ODIN Verified Badge (Draft)

Projects may display the **ODIN Verified** badge once they pass the automated conformance suite.

Badge URL (static draft):
```
![ODIN Verified](https://img.shields.io/badge/odin-verified-brightgreen)
```

Planned Conformance Checks:
1. Envelope canonicalization (CID stability across implementations)
2. Signature verification (gateway ↔ client parity)
3. Receipt chain integrity & prev hash linkage
4. Export bundle CID + signature pattern correctness
5. Transparency inclusion proof verification
6. Negative cases: tampered receipt, replay, timestamp skew rejection
7. Optional BYOK dual-sign pattern validation

Issuance Flow:
* GitHub Action runs `odin-conformance` workflow
* Produces signed attestation JSON + hash
* Repository adds badge pointing to published attestation artifact

Revocation:
* Critical spec deviation or security issue triggers badge revocation advisory (partners notified)

Roadmap:
* Machine-readable SBOM of conformance test vectors
* Public directory of verified projects
