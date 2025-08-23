# Secure Development Policy (Draft)

Principles:
1. Least Privilege: service accounts limited to signing + read public key.
2. Defense in Depth: signatures + optional HMAC + policy allowlist.
3. Immutable Audit: receipt hash chain + export bundle signature + transparency root.
4. Secure Defaults: deny on Rego engine errors; policy profile explicit.

Practices:
* Code Review: All changes via PR with at least one reviewer; security-relevant changes require explicit ACK.
* Testing: CI runs pytest (unit/integration). Future: coverage + static analysis (ruff, mypy).
* Secrets: No plaintext keys in repo. Use env vars; encourage secret manager in production.
* Dependency Management: `requirements.txt` pins versions; monthly review for CVEs.
* Cryptography: Ed25519 via widely used library; no home‑rolled crypto.
* Logging: Minimal PII; avoid payload secrets; structured logs planned.
* Incident Response: On suspected key compromise rotate KID, revoke API keys, re-issue transparency checkpoint.

Release Process:
1. Feature branch → PR
2. CI: tests pass
3. Reviewer sign-off
4. Merge → tag (semantic-ish) → optional publish (PyPI/npm)

Roadmap Enhancements:
* Add SAST (Bandit) and dependency scanning (pip-audit)
* Add secret scanning pre-commit hook
* Add provenance attestation (SLSA build metadata) for container images
