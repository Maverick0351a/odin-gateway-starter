# Security Considerations

Threat categories mitigated:
* Tampering: hash-linked receipts + signed bundles + transparency roots
* Replay: timestamp skew limits + replay cache (`ODIN_REPLAY_CACHE_SIZE`)
* Key compromise: KID rotation + additional JWKS
* Policy bypass: deny-on-error Rego, HEL allowlist

Operators SHOULD:
* Rotate gateway signing key at least quarterly
* Export & archive transparency checkpoints
* Monitor for root divergence at fixed sizes
