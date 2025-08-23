# ODIN Secure AI to AI Utility Stack

[![CI](https://github.com/Maverick0351a/odin-gateway-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/Maverick0351a/odin-gateway-starter/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/odin-sdk.svg)](https://pypi.org/project/odin-sdk/)
[![npm (next)](https://img.shields.io/npm/v/@maverick0351a/odin-sdk-js/next.svg)](https://www.npmjs.com/package/@maverick0351a/odin-sdk-js)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey)](LICENSE)

> Production‑ready starter for governed, verifiable AI→AI communication using the **ODIN OPE (Open Proof Envelope)** protocol.

Core capabilities:
* Gateway + Relay services (FastAPI) with policy enforcement (HEL), schema transformation (SFT), cryptographic receipts
* ODIN Core: Ed25519 key management + JWKS, CID hashing, canonical JSON, receipt chaining (Firestore or JSONL), policy + transform engines
* Control Plane (MVP): multi-tenant API key issuance, allowlists, rate limiting, admin endpoints
* Test suite (pytest) covering health, JWKS, end-to-end envelope, export bundle, control plane, SDK flows
* Container builds (Dockerfiles) for gateway, relay, dashboard
* Dashboard (FastAPI + Jinja2) to inspect chains and verify export bundles
* SDK / CLI: Python (editable) plus early JavaScript preview
* Cloud Run deployment scripts + smoke checks
* Optional API key + HMAC layer (defense in depth)

Start by opening **`AGENT.md`** and telling Copilot Chat:
> Follow AGENT.md from Task 0. Ask me for any missing env vars.

**Quick Links:**
[Quick Start](#quick-start-python-sdk--gateway) · [CLI (Py)](#cli-reference-python-sdk) · [JS SDK](#js--typescript-sdk) · [Export Verification](#export--verification-manual) · [Security](#security-notes) · [Roadmap](#roadmap)

---

## Table of Contents

1. [Architecture Snapshot](#-architecture-snapshot)
2. [Key Environment Variables](#-key-environment-variables)
3. [Control Plane & Admin API](#-control-plane--admin-api)
4. [Verification Surfaces](#-verification-surfaces)
5. [Quick Start](#-quick-start-python-sdk--gateway)
6. [Cloud Run Deployment](#-cloud-run-deployment)
7. [CLI Reference (Python)](#-cli-reference-python-sdk)
8. [JS / TypeScript SDK](#-js--typescript-sdk)
9. [Tests / CI](#-tests--ci)
10. [Project Layout](#-project-layout)
11. [Export & Verification (Manual)](#-export--verification-manual)
12. [Hosted Verify](#-hosted-verify)
13. [Recipes](#-recipes)
14. [Contributing](#-contributing)
15. [License](#-license)

---

## Architecture Snapshot

High-level flow (summary): Signed envelopes in, transformed + policy‑checked, hash‑linked receipts out, optional relay, verifiable export bundles.

<details>
<summary>Detailed step-by-step (click to expand)</summary>

1. Sender builds payload, canonicalizes JSON (sorted keys), computes CID (`sha256:<hex>`), signs `<cid>|<trace_id>|<ts>` (Ed25519).
2. Gateway resolves sender JWK (inline or cache) & verifies signature.
3. SFT maps vendor schema → canonical target (e.g. `openai.tooluse.invoice.v1` → `invoice.iso20022.v1`).
4. HEL policy validates optional `forward_url` host (per API key allowlist).
5. Receipt formed: includes normalized CID, linkage (`prev_receipt_hash`), policy result, gateway signature.
6. Receipt persisted (Firestore or JSONL) forming an append‑only, tamper‑evident chain.
7. (Optional) Relay forwards normalized payload externally.
8. Gateway signs response `<response_cid>|<trace_id>|<receipt_ts>`; provenance headers returned.
9. Export endpoint bundles receipts, signs `<bundle_cid>|<trace_id>|<exported_at>` enabling off‑box verification.

</details>

Export endpoint: `/v1/receipts/export/{trace_id}` returns a signed bundle; clients recompute bundle CID & verify signature via JWKS.

---

## Key Environment Variables

| Var | Purpose | Example / Notes |
|-----|---------|-----------------|
| `ODIN_SIGNER_BACKEND` | Signer backend selector (`file`) | `file` (default) – options: `gcpkms`, `awskms`, `azurekv` (experimental) |
| `ODIN_GCP_KMS_KEY` | Full resource name of Ed25519 KMS key version (gcpkms backend) | `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/1` |
| `ODIN_AWS_KMS_KEY_ID` | AWS KMS key id or ARN for ED25519 key (awskms backend) | `arn:aws:kms:us-east-1:123456789012:key/uuid` |
| `ODIN_AZURE_KEY_ID` | Azure Key Vault key identifier (versioned) for Ed25519 key | `https://<vault>.vault.azure.net/keys/<name>/<version>` |
| `ODIN_POLICY_REGO_PATH` | Path to Rego policy file (enables Rego engine) | `policies/egress.rego` |
| `OPA_BIN` | OPA binary name/path (when using Rego) | `opa` |
| `ODIN_GATEWAY_PRIVATE_KEY_B64` | Base64url Ed25519 32‑byte seed for gateway signing (file backend) | Generated via `scripts/gen_keys.py` |
| `ODIN_GATEWAY_KID` | Key ID exposed in JWKS and headers (can be auto‑derived) | Any unique string (e.g. `gw-2025-01`) |
| `ODIN_ADDITIONAL_PUBLIC_JWKS` | JSON string of legacy/extra JWKs for verification | `{"keys":[...]}` |
| `RELAY_URL` | If set, gateway will POST normalized payloads to relay | `http://relay:8090` |
| `ODIN_API_KEY_SECRETS` | JSON map of API key → HMAC secret (legacy static mode) | `{"demo":"supersecret"}` |
| `CONTROL_PLANE_PATH` | Path to JSON state file for tenants/keys | `control_plane.json` |
| `ODIN_REQUIRE_API_KEY` | Force API key auth even if no static map set | `1` / `true` |
| `ODIN_ADMIN_TOKEN` | Enables admin endpoints when set (required token) | random strong string |
| `FIRESTORE_PROJECT` / ADC | Enables Firestore receipt backend (otherwise JSONL) | GCP project id |
| `RECEIPT_LOG_PATH` | Override JSONL receipt log path | Defaults under working dir |

Set API key + MAC: client includes `X-ODIN-API-Key` + `X-ODIN-API-MAC` = base64url(HMAC_SHA256(secret, `<cid>|<trace_id>|<ts>`)).

---

## Control Plane & Admin API

Multi-tenant governance (MVP) enabling dynamic API key issuance, allowlists, and rate limiting. Backed by a simple JSON file (atomic rewrite) suitable for local / prototype; swap with DB later.

Admin authentication: provide header `X-Admin-Token: <ODIN_ADMIN_TOKEN>`.

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/admin/tenants` | List tenants (key secrets hidden) |
| POST | `/v1/admin/tenants` | Create tenant `{tenant_id,name}` |
| GET | `/v1/admin/tenants/{tenant_id}` | Fetch tenant summary |
| PATCH | `/v1/admin/tenants/{tenant_id}` | Update fields: `name`, `allowlist`, `rate_limit_rpm`, `status` |
| DELETE | `/v1/admin/tenants/{tenant_id}` | Delete tenant |
| POST | `/v1/admin/tenants/{tenant_id}/keys` | Issue API key (returns secret once) |
| POST | `/v1/admin/tenants/{tenant_id}/keys/{key}/revoke` | Revoke key |

### Request / Response Samples
Create tenant:
```bash
curl -s -X POST http://127.0.0.1:8080/v1/admin/tenants \
	-H "X-Admin-Token: $ODIN_ADMIN_TOKEN" \
	-H 'Content-Type: application/json' \
	-d '{"tenant_id":"acme","name":"Acme Corp"}' | jq
```

Issue key:
```bash
curl -s -X POST http://127.0.0.1:8080/v1/admin/tenants/acme/keys \
	-H "X-Admin-Token: $ODIN_ADMIN_TOKEN" | jq
```
Response (example):
```json
{ "key": "k_abcd...", "secret": "s_xyz...", "active": true, "created_at": "2025-08-22T12:34:56Z" }
```
Store `key` & `secret` securely; secret is not retrievable later.

### Using an Issued Key
For each envelope:
1. Build canonical message `<cid>|<trace_id>|<ts>` (same as signature payload)
2. Compute `mac = base64url( HMAC_SHA256(secret, message) )`
3. Add headers:
	 * `X-ODIN-API-Key: <key>`
	 * `X-ODIN-API-MAC: <mac>`

Python snippet (manual HMAC):
```python
import hmac, hashlib, base64
def b64u(b: bytes): return base64.urlsafe_b64encode(b).rstrip(b'=')
message = f"{cid}|{trace_id}|{ts}".encode()
mac = b64u(hmac.new(secret.encode(), message, hashlib.sha256).digest()).decode()
headers = {"X-ODIN-API-Key": key, "X-ODIN-API-MAC": mac}
```

Rate limiting: if `rate_limit_rpm > 0`, requests above that per-minute threshold return HTTP 429.

Allowlist: set `allowlist` array (hosts) via PATCH to enable per-tenant egress overrides even if global HEL would block.

Fallback static mode: if `ODIN_API_KEY_SECRETS` is set, those keys are accepted alongside dynamic keys.

Security notes:
* Always send Admin API calls over HTTPS.
* Rotate `ODIN_ADMIN_TOKEN` periodically; treat like a master credential.
* Consider isolating admin surface behind a VPN / internal ingress in production.

---

## Verification Surfaces
* JWKS: `/.well-known/jwks.json`
* Response headers: `X-ODIN-Receipt-Hash`, `X-ODIN-Response-CID`, `X-ODIN-Signature`, `X-ODIN-KID`
* Export bundle: signed pattern assures integrity + ordering
* Chain validation: each receipt's `prev_receipt_hash` must match prior's `receipt_hash`
* Policy attestation (future): expose which engine (HEL or Rego) evaluated egress decision in receipt metadata.

---

## Quick Start (Python SDK + Gateway)

### 0. Environment Setup (optional but recommended)
```powershell
python -m venv .venv
./.venv/Scripts/Activate.ps1
pip install -r requirements.txt
```

### 1. Generate Gateway Keys
```powershell
python scripts/gen_keys.py
$env:ODIN_GATEWAY_PRIVATE_KEY_B64="<printed>"
$env:ODIN_GATEWAY_KID="<printed>"
```

### 2. Run Gateway
```powershell
uvicorn services.gateway.main:app --host 127.0.0.1 --port 8080
```

### 3. Install & Use SDK / CLI

```powershell
# 1. Editable install (Python SDK + CLI)
pip install -e .\packages\odin_sdk

# 2. Generate gateway signing keypair (Ed25519 seed)
python .\scripts\gen_keys.py
# Copy printed ODIN_GATEWAY_PRIVATE_KEY_B64 and ODIN_GATEWAY_KID values
$env:ODIN_GATEWAY_PRIVATE_KEY_B64="<paste>"
$env:ODIN_GATEWAY_KID="<paste>"

# 3. Run the gateway locally
uvicorn services.gateway.main:app --host 127.0.0.1 --port 8080

# 4. (Optional) Start dashboard in a second terminal
$env:GATEWAY_URL="http://127.0.0.1:8080"
uvicorn services.dashboard.main:app --host 127.0.0.1 --port 8081 --reload

# 5. Prepare a payload (example OpenAI tool-use -> ISO20022 invoice)
#    Create .\examples\openai_invoice.json then send it:
odin send --gateway-url http://127.0.0.1:8080 `
	--priv <seed> --kid demo-sender `
	--ptype openai.tooluse.invoice.v1 `
	--ttype invoice.iso20022.v1 `
	--payload-file .\examples\openai_invoice.json --print-body --json

# 6. Inspect chain + verify export
odin chain --gateway-url http://127.0.0.1:8080 --priv <seed> --kid demo-sender --trace-id <trace_id> --json
odin export-verify --gateway-url http://127.0.0.1:8080 --priv <seed> --kid demo-sender --trace-id <trace_id> --json
```

### Command Shortcut (using env defaults)
If you export `ODIN_GATEWAY_URL`, `ODIN_SENDER_PRIV_B64`, and `ODIN_SENDER_KID`, you can omit them:
```powershell
odin send --ptype openai.tooluse.invoice.v1 `
		  --ttype invoice.iso20022.v1 `
		  --payload-file .\examples\openai_invoice.json `
		  --print-body --json
```

JSON output (automation): add `--json` to CLI commands.

### 4. Run Dashboard (optional)
```powershell
uvicorn services.dashboard.main:app --port 8081 --reload
# open http://127.0.0.1:8081
```
Routes:
* `/` enter trace id
* `/trace/{trace_id}` chain integrity (hash + link)
* `/export/{trace_id}` bundle + signature banner, copy CID button

## Cloud Run Deployment
Prereqs:
1. Install & auth gcloud: `gcloud auth login` / `gcloud auth application-default login`
2. Enable services (once): `gcloud services enable run.googleapis.com artifactregistry.googleapis.com firestore.googleapis.com`
3. (Optional) Create Artifact Registry repo (Docker):
	```powershell
	gcloud artifacts repositories create odin --repository-format=docker --location=us-central1 --description "ODIN images"
	```

### Required Env Vars (before deploy)
```powershell
$env:ODIN_GATEWAY_PRIVATE_KEY_B64="<seed32b64u>"
$env:ODIN_GATEWAY_KID="gw-<id>"
```
Optional:
```powershell
$env:ODIN_API_KEY_SECRETS='{"demo":"supersecret"}'
$env:ODIN_ADDITIONAL_PUBLIC_JWKS='{"keys":[...]}'
$env:FIRESTORE_PROJECT="<gcp-project-id>"   # Enables Firestore backend
```

### Deploy (build + deploy gateway only)
```powershell
./scripts/deploy_cloud_run.ps1 -Project <gcp-project-id> -Region us-central1 -Build
```

### Deploy gateway + dashboard
```powershell
./scripts/deploy_cloud_run.ps1 -Project <gcp-project-id> -Region us-central1 -Build -DeployDashboard
```

Flags:
* `-Build` – run Cloud Build for images (omit to reuse existing images)
* `-DeployDashboard` – also build/deploy dashboard service
* `-Repo` – Artifact Registry repo name (default `odin`)
* `-GatewayService` / `-DashboardService` – override service names

Script outputs:
* Deployed service URL(s)
* Smoke health check result (`/healthz`)

After deploy you can test:
```powershell
Invoke-RestMethod "$env:GATEWAY_URL/healthz"
```

Export & verify remotely (example):
```powershell
odin export-verify --gateway-url <GatewayURL> --priv <seed> --kid <kid> --trace-id <trace_id> --json
```

---

## CLI Reference (Python SDK)

The Python package installs three interchangeable entry points: `odin`, `odinpy`, and `odin-sdk` (use whichever is on your PATH). Examples below use `odinpy` for clarity.

Set common env defaults (optional):
```powershell
$env:ODIN_GATEWAY_URL="http://127.0.0.1:8080"
$env:ODIN_SENDER_PRIV_B64="<sender_seed_b64url>"
$env:ODIN_SENDER_KID="sender-demo"
```

### Generate a keypair
```powershell
odinpy keygen --json
```
Outputs JSON containing: `private_key_b64`, `kid`, and a JWK (`kty=OKP, crv=Ed25519`).

### Sign (produce an envelope only)
```powershell
odinpy sign --ptype vendor.event.v1 --ttype canonical.event.v1 `
	--payload-inline '{"foo":1}' --priv $env:ODIN_SENDER_PRIV_B64 --kid $env:ODIN_SENDER_KID --json
```
Returns envelope JSON + trace_id (auto‑generated if omitted).

### Send (sign + POST to gateway)
```powershell
odinpy send --ptype vendor.event.v1 --ttype canonical.event.v1 `
	--payload-inline '{"foo":1}' --priv $env:ODIN_SENDER_PRIV_B64 --kid $env:ODIN_SENDER_KID --print-body --json
```
JSON fields:
* `trace_id` – correlate future queries
* `receipt_hash` – last appended receipt hash
* `response_cid` – CID of normalized response body

### Fetch receipt chain
```powershell
odinpy chain --trace-id <trace_id> --priv $env:ODIN_SENDER_PRIV_B64 --kid $env:ODIN_SENDER_KID --json
```
Returns ordered receipts (each includes `receipt_hash`, `prev_receipt_hash`, and normalization / policy metadata).

### Export + verify bundle
```powershell
odinpy export-verify --trace-id <trace_id> --priv $env:ODIN_SENDER_PRIV_B64 --kid $env:ODIN_SENDER_KID --json --include-bundle
```
Performs client‑side checks: hash linkage, bundle CID, Ed25519 signature (`<bundle_cid>|<trace_id>|<exported_at>`). Exit code 0 on success; 2 on verification failure.

### Fetch JWKS
```powershell
odinpy jwks --json
```

### Ping gateway
```powershell
odinpy ping --json
```

### Using stdin for payloads
```powershell
Get-Content .\examples\openai_invoice.json | odinpy send --ptype openai.tooluse.invoice.v1 `
	--ttype invoice.iso20022.v1 --payload-file - --priv $env:ODIN_SENDER_PRIV_B64 --kid $env:ODIN_SENDER_KID --json
```

### Exit codes
* 0 = success
* 1 = user / usage error
* 2 = verification failure (export-verify)

### Troubleshooting
* Command not found: ensure the Python Scripts path is on `PATH`, or invoke via `python -m odin_sdk.cli ...`
* Signature errors: confirm `--priv` matches the `kid` the gateway has in its sender JWK set (or supplied inline).
* Hash mismatch on export: verify no manual edits to receipt log; re‑request export to confirm reproducibility.

---

## JS / TypeScript SDK

Located in `packages/odin_sdk_js` (early preview). Provides `OPEClient` plus a minimal Node CLI (`bin/odin.js`).

### Install & Build
```powershell
cd packages/odin_sdk_js
npm install
npm run build
```

### Programmatic Use
```typescript
import { OPEClient } from 'odin-sdk-js';

const gateway = 'http://127.0.0.1:8080';
const seed = '<sender_seed_b64url>';      // 32‑byte Ed25519 seed (base64url, no padding)
const kid  = 'demo-sender';

const client = new OPEClient(gateway, seed, kid);
const payload = { foo: 1 };
const env = client.buildEnvelope(payload, 'vendor.event.v1', 'canonical.event.v1');
const { data, headers } = await client.sendEnvelope(env);

console.log('Trace:', env.trace_id);
console.log('Receipt Hash:', headers['x-odin-receipt-hash']);
console.log('Response CID verified:', headers['x-odin-response-cid']);
```

### Node CLI
After build:
```powershell
node bin/odin.js
```
Usage output:
```
odin JS CLI
Commands:
	sign --gateway <url> --key <b64u_seed> --kid <kid> --payload <json> [--payload-type <t>] [--target-type <t>] [--trace <id>]
	send --gateway <url> --key <b64u_seed> --kid <kid> --payload <json> [--payload-type <t>] [--target-type <t>] [--trace <id>] [--api-key <k>] [--hmac-secret <s>]
```

Examples:
```powershell
# Sign only
node bin/odin.js sign --gateway http://127.0.0.1:8080 `
	--key <seed> --kid demo-sender `
	--payload '{"foo":1}' `
	--payload-type vendor.event.v1 `
	--target-type canonical.event.v1

# Sign + send
node bin/odin.js send --gateway http://127.0.0.1:8080 `
	--key <seed> --kid demo-sender `
	--payload '{"foo":1}' `
	--payload-type vendor.event.v1 `
	--target-type canonical.event.v1
```

HMAC / API key (optional): add `--api-key <key>` and `--hmac-secret <secret>`; client will compute `x-odin-mac` over `<cid>|<trace>|<ts>`.

Planned additions: chain fetch, export verification parity with Python CLI.

## Tests / CI
```powershell
python -m pytest -q
```

GitHub Actions runs these on pushes & PRs (see badge above). Python 3.11 & 3.12 matrix. Separate workflow `npm-publish.yml` handles JS package publishing (manual dispatch or tag `js-v*`).

### JS SDK Publish
1. Set repository secret `NPM_TOKEN` (automation token with publish rights).
2. Manual prerelease:
	* GitHub UI → Actions → `npm-publish` → Run workflow (dist_tag=`next`).
3. Promote to latest:
	* Update `package.json` version.
	* Tag push: `git tag js-v0.2.0 && git push origin js-v0.2.0` (workflow auto uses `latest`).
4. Verify: `npm view @maverick0351a/odin-sdk-js dist-tags`.


Health endpoint: `/healthz` (alias `/health`). Metrics: `/metrics` (Prometheus exposition).

---

## Project Layout

```
├─ AGENT.md                     # Playbook for autonomous agent (Copilot) to operate repo
├─ README.md                    # You are here
├─ LICENSE                      # Apache 2.0
├─ requirements.txt             # Runtime + test dependencies (gateway, relay, SDK)
├─ Dockerfile.gateway           # Gateway container (FastAPI + receipts + metrics)
├─ Dockerfile.relay             # Relay container (egress proxy/policy target)
├─ Dockerfile.dashboard         # Dashboard container (UI for chains / bundles)
├─ debug_openai_mapping.py      # Utility for mapping OpenAI tool payloads
├─ scripts/
│  ├─ gen_keys.py               # Generates Ed25519 seed + KID (exports env var values)
│  └─ demo_send_envelope.py     # Example envelope submission script
├─ services/
│  ├─ __init__.py
│  ├─ gateway/
│  │  ├─ __init__.py
│  │  └─ main.py                # Gateway API implementation
│  ├─ relay/
│  │  ├─ __init__.py
│  │  └─ main.py (future / placeholder)
│  └─ dashboard/
│     ├─ __init__.py
│     └─ main.py (future / placeholder UI)
├─ packages/
│  ├─ odin_core/                # Core primitives (crypto, cid, sft, hel, receipts)
│  │  ├─ __init__.py
│  │  ├─ cid.py
│  │  ├─ crypto.py
│  │  ├─ firestore_log.py       # Firestore / JSONL receipt store abstraction
│  │  ├─ hel.py                 # Policy (HEL) allowlist checks
│  │  ├─ sft.py                 # Schema transform (SFT) logic
│  │  ├─ receipts.py            # Receipt build & chain helpers
│  │  └─ utils.py               # Canonical JSON, time helpers, etc.
│  └─ odin_sdk/                 # Python SDK + CLI (editable install)
├─ tests/
│  ├─ conftest.py               # Ensures repo root & packages on sys.path for CI
│  ├─ test_gateway.py           # Health, JWKS, envelope E2E
│  ├─ test_export.py            # Export bundle & chain integrity
│  └─ test_sdk_basic.py         # SDK client signing & verification workflow
├─ tools/
│  └─ repl/odin_repl.py         # ODIN-aware REPL leveraging OpenAI responses
└─ .github/workflows/ci.yml     # Pytest matrix (3.11 / 3.12)
```

Legend:
* Core flow lives in `services/gateway/main.py` + `packages/odin_core/`.
* The SDK depends only on the stable core primitives (no service internals).
* Adding new schema transforms: implement in `sft.py` and register mapping.
* Adding new policy rules: extend `PolicyEngine` in `hel.py`.

---

## Export & Verification (Manual)
1. POST envelope(s) to gateway (collect a `trace_id`).
2. GET `/v1/receipts/export/{trace_id}` → obtain `bundle`, `bundle_cid`, `bundle_signature`.
3. Recompute canonical JSON of `bundle`, sha256 → must equal `bundle_cid`.
4. Verify Ed25519 signature over `<bundle_cid>|<trace_id>|<exported_at>` using JWKS active key.
5. Inspect `chain_valid` and `receipts` link hashes.

---

## Hosted Verify

The dashboard now exposes a public verification utility.

> Deployment: After deploying the dashboard (e.g. Cloud Run) set `HOSTED_VERIFY_BASE_URL` (optional) and update docs/packages to point users here. Example: `https://odin-verify.example.com`.

Set `HOSTED_VERIFY_BASE_URL` during deployment to advertise a canonical URL (e.g. Cloud Run custom domain).

### Recommended Domain Layout

| Purpose | Suggested Domain | Notes |
|---------|------------------|-------|
| Gateway API | `api.odinprotocol.dev` | Primary ingestion & export endpoints |
| Hosted Verify | `verify.odinprotocol.dev` | Dashboard + `/verify/*` JSON APIs |
| (Optional) Marketing | `www.odinprotocol.dev` | Static site / docs redirect |
| (Optional) Relay | `relay.odinprotocol.dev` | Outbound normalization/egress service |

### Deploy & Map Domains (Cloud Run)

1. Build & deploy services (gateway + dashboard):
```powershell
./scripts/deploy_cloud_run.ps1 -Project <gcp-project> -Region us-central1 -Build -DeployDashboard -MapDomains `
	-ApiDomain api.odinprotocol.dev -VerifyDomain verify.odinprotocol.dev
```
2. Script attempts domain mappings; fetch required DNS records:
```powershell
gcloud run domain-mappings list --region us-central1 --format json | ConvertTo-Json -Depth 6
```
3. Create DNS records at your registrar (A/AAAA or CNAME targets as instructed).
4. Wait for certificate provisioning (5–15 min). Test:
```powershell
Invoke-RestMethod https://verify.odinprotocol.dev/healthz
```
5. Update SDK / README references to final URLs.

### CORS Configuration
If browser JS or cross-origin verification needed, set:
```powershell
$env:CORS_ALLOW_ORIGINS="https://verify.odinprotocol.dev,https://www.odinprotocol.dev"
```
The deploy script passes this to Cloud Run when present.

Example (PowerShell):
```powershell
$env:HOSTED_VERIFY_BASE_URL="https://verify.example.com"
```

Placeholder public URL (replace after deploy): `https://YOUR-VERIFY-DOMAIN/`.

Routes:
* `/verify/{trace_id}` – JSON API: fetches export bundle from the gateway, recomputes bundle CID, validates receipt chain, and verifies signature variants ( `<bundle_cid>|<trace_id>|<exported_at>` or CID‑only fallback ).
* `POST /verify/bundle` – Upload a bundle JSON file (optionally supply `gateway_url` + `kid`) to verify offline.
* `/verify` (HTML) – UI page with trace lookup + bundle upload.

JSON response fields:
```jsonc
{
	"trace_id": "...",
	"bundle_cid": "sha256:...",    // recomputed locally
	"chain_ok": true,              // receipt hashes + linkage valid
	"sig_ok": true,                // signature verified against JWKS
	"sig_variant": "cid|trace|exported_at", // matched signing pattern
	"count": 3,                    // receipt count
	"gateway_kid": "gw-2025-01"
}
```

Usage (PowerShell examples):
```powershell
# Trace verification (JSON)
Invoke-RestMethod "http://127.0.0.1:8081/verify/$trace_id?gateway_url=http://127.0.0.1:8080" | ConvertTo-Json -Depth 5

# Bundle upload
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8081/verify/bundle?gateway_url=http://127.0.0.1:8080&kid=$env:ODIN_GATEWAY_KID" -InFile .\bundle.json -ContentType application/json
```

Integrators can embed these endpoints in CI to attest chain integrity for compliance or auditing pipelines.

---

## Recipes

### Quick Connect (Python SDK + Control Plane)
```python
from odin_sdk.client import OPEClient
import os, requests

# Fetch tenant API key from control plane admin endpoint (example)
tenant_id = 'demo'
cp_url = os.environ['CONTROL_PLANE_URL']
api_key_info = requests.post(f"{cp_url}/admin/tenants/{tenant_id}/issue-key", headers={'x-admin-token': os.environ['ADMIN_TOKEN']}).json()
os.environ['ODIN_API_KEY'] = api_key_info['key']
os.environ['ODIN_API_SECRET'] = api_key_info['secret']

client = OPEClient(os.getenv('ODIN_GATEWAY_URL','http://127.0.0.1:8080'), os.environ['ODIN_SENDER_PRIV_B64'], os.environ['ODIN_SENDER_KID'])
resp = client.send_inline({'foo':1}, payload_type='openai.tooluse.invoice.v1', target_type='invoice.iso20022.v1')
print(resp.trace_id, resp.receipt_hash)
```

### OpenAI Tool-use → ODIN Envelope (Python)
```python
tool_payload = { 'invoice_id':'INV-1','amount': 100.25, 'currency':'USD' }
env = client.build_envelope(tool_payload, 'openai.tooluse.invoice.v1', 'invoice.iso20022.v1')
client.send_envelope(env)
```

### Claude Tool-use → ODIN (Python)
```python
claude_payload = { 'tool':'create_invoice','args':{'invoice_id':'INV-2','amount':55,'currency':'EUR'} }
env = client.build_envelope(claude_payload, 'anthropic.tooluse.invoice.v1', 'invoice.iso20022.v1')
client.send_envelope(env)
```

### Vendor → ISO 20022 (JS SDK)
```bash
node bin/odin.js send --gateway http://127.0.0.1:8080 \
	--key $SEED --kid sender-demo \
	--payload '{"invoice_id":"INV-99","amount":42.5,"currency":"USD"}' \
	--payload-type invoice.vendor.v1 \
	--target-type invoice.iso20022.v1
```

---

## Security Notes
* Keys: Gateway Ed25519 private key (seed) is a 32‑byte secret; store outside repo (env / secret manager). Rotate by issuing a new `KID` and keeping the old public key in `ODIN_ADDITIONAL_PUBLIC_JWKS` during migration.
* KMS: When using `ODIN_SIGNER_BACKEND=gcpkms`, the private key material never leaves Cloud KMS; only signatures are returned. Ensure the service account has `cloudkms.cryptoKeyVersions.useToSign`.
* AWS KMS: With `ODIN_SIGNER_BACKEND=awskms` the gateway signs via AWS KMS (key spec `ECC_ED25519`). IAM role needs `kms:Sign` and `kms:GetPublicKey`.
* Azure KV: With `ODIN_SIGNER_BACKEND=azurekv` the gateway uses Key Vault (Ed25519 key) via `DefaultAzureCredential`; assign `keys/sign` and `keys/get` permissions.
* Policy: Rego evaluation failures fall back to deny with a `rego_error` reason (fail closed). Keep policy minimal and test with `opa eval` before deployment.
* Signed Contexts: Envelopes sign `<cid>|<trace_id>|<ts>`; export bundles sign `<bundle_cid>|<trace_id>|<exported_at>` binding content + lineage + freshness.
* Tamper Evidence: Receipts are hash‑linked (`prev_receipt_hash`); altering history breaks the chain.
* Defense in Depth: Optional API key + HMAC (`X-ODIN-API-Key` / `X-ODIN-API-MAC`) mitigates spoofing and simple replay.
* Replay Hardening (future): Enforce max age / skew on `ts` and optional nonce cache.
* Separation: Relay isolates egress allowing stricter network controls.

## Versioning & Stability
Stable fields: `trace_id`, `cid`, `payload_type`, `target_type`, `signature`, `receipt_hash`, `prev_receipt_hash`.

Extensible (additive only): policy metadata, normalization annotations, export bundle wrapper keys.

Breaking changes introduce a new versioned target type (e.g. `invoice.iso20022.v2`) or additive receipt field rather than mutating existing ones.

## Roadmap
* Relay retry/backoff & dead‑letter
* JS CLI parity: chain + export verify
* Lint & type checks (ruff / mypy) in CI
* Coverage + badge
* Manual `workflow_dispatch` trigger
* Publish to PyPI / npm
* Pluggable policy modules
* Merkle aggregation for batch proofs
* Additional signer backends (GCP KMS, AWS KMS, Azure Key Vault) using the new abstraction

## Contributing
PRs & issues welcome. Run tests (`python -m pytest -q`) before submitting. Please keep receipts & cryptographic semantics backwards‑compatible; if you need to break them, add a new versioned target type or receipt field while preserving old behavior.

---

## License
[Apache 2.0](LICENSE)

---

> Have feedback? Open an issue describing your use case or desired extension (policy module, new transform, verification surface). Fast iteration welcome.

