# ODIN Agent Starter (v2)

[![CI](https://github.com/Maverick0351a/odin-gateway-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/Maverick0351a/odin-gateway-starter/actions/workflows/ci.yml)

License: Apache-2.0 (see `LICENSE`)

This repo contains:
- Gateway + Relay FastAPI services
- Shared ODIN Core package (crypto/JWKS, CID, SFT, HEL, receipts, Firestore/JSONL)
- Tests (pytest) for health, JWKS, and end-to-end envelope
- Dockerfiles for both services
- **AGENT.md** — a step-by-step playbook an LLM agent (Copilot) can follow in your terminal
- Optional ODIN-aware terminal REPL using OpenAI Responses API

Start by opening **AGENT.md** and telling Copilot Chat:
> Follow AGENT.md from Task 0. Ask me for any missing env vars.

## ODIN SDK (Python) — Quick Start

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

## Python SDK & CLI

Editable install:
```powershell
pip install -e .\packages\odin_sdk
```

Generate gateway key & run gateway:
```powershell
python .\scripts\gen_keys.py   # copy ODIN_GATEWAY_PRIVATE_KEY_B64 & ODIN_GATEWAY_KID
$env:ODIN_GATEWAY_PRIVATE_KEY_B64="<seed>"
$env:ODIN_GATEWAY_KID="<kid>"
uvicorn services.gateway.main:app --host 127.0.0.1 --port 8080
```

Create example payload (`examples/openai_invoice.json`) then send:
```powershell
odin send --gateway-url http://127.0.0.1:8080 \` 
	--priv <seed> --kid demo-sender \` 
	--ptype openai.tooluse.invoice.v1 \` 
	--ttype invoice.iso20022.v1 \` 
	--payload-file .\examples\openai_invoice.json --print-body
```

Fetch chain & export:
```powershell
odin chain --gateway-url http://127.0.0.1:8080 --priv <seed> --kid demo-sender --trace-id <trace_id>
odin export-verify --gateway-url http://127.0.0.1:8080 --priv <seed> --kid demo-sender --trace-id <trace_id>
```

JSON output (automation): add `--json`.

## Dashboard
Run read‑only dashboard (new tab):
```powershell
$env:GATEWAY_URL="http://127.0.0.1:8080"
uvicorn services.dashboard.main:app --host 127.0.0.1 --port 8081 --reload
```
Browser:
- `/` enter trace id
- `/trace/{trace_id}` chain integrity (hash + link)
- `/export/{trace_id}` bundle + signature banner, copy CID button

## Cloud Run Deployment
Prereqs: gcloud auth login, set project.
```powershell
./scripts/deploy_cloud_run.ps1 -Project <gcp-project-id> -Region us-central1 -Build
```
Outputs gateway & dashboard URLs plus smoke checks.

## Tests / CI
```powershell
python -m pytest -q
```

GitHub Actions runs these on pushes & PRs (see badge above). Python 3.11 & 3.12 matrix.

Health endpoint: `/healthz` (alias `/health`).
