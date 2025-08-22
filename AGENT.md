# AGENT.md — ODIN Agent Playbook (Copilot/LLM Agent)

You are a terminal-capable coding agent working in this repository. Your job is to **set up, test, run, debug, containerize, and deploy** the ODIN Gateway and Relay, then verify end-to-end functionality with signed receipts.

Always follow these rules:
- **Ask for missing values** (keys, project IDs, URLs) and wait for answers.
- **Echo each command before running it**, then run it.
- **Stop on errors**, show the full traceback/output, and propose a fix. Re-run after fixing.
- Prefer **Windows PowerShell** commands if the environment is Windows; otherwise use Bash equivalents.
- Never modify secrets in files. Use environment variables.

---

## Task 0 — Preflight

1. Detect OS/shell. If Windows, use PowerShell; else Bash.
2. Check tools:
   - `python --version` (>= 3.10)
   - `pip --version`
   - `gcloud --version` (optional for deploy)
   - `docker --version` (optional for container builds)
3. If any tool is missing, ask the user to install it.

---

## Task 1 — Python environment & dependencies

**Windows PowerShell**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Bash**
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify:
```powershell
python -c "import fastapi, uvicorn, cryptography, requests, openai, pytest; print('deps-ok')"
```

---

## Task 2 — Generate keys and export env vars

Run:
```powershell
python scripts\gen_keys.py
```
Ask the user to paste:
- `ODIN_GATEWAY_PRIVATE_KEY_B64=` (base64url 32 bytes)
- `ODIN_GATEWAY_KID=` (like `ed25519-xxxxxxxxxxxxxxxx`)

Then export:
```powershell
$env:ODIN_GATEWAY_PRIVATE_KEY_B64 = "<paste>"
$env:ODIN_GATEWAY_KID = "<paste>"
$env:HEL_ALLOWLIST = "api.openai.com,postman-echo.com"
$env:RELAY_ALLOWLIST = "api.openai.com,postman-echo.com"
```

*(Bash equivalents use `export VAR=value`)*

---

## Task 3 — Run tests

```powershell
pytest -q
```
- Ensure tests pass: health, JWKS, and end-to-end envelope.
- If they fail, inspect tracebacks and propose fixes. Re-run until green.

---

## Task 4 — Run Gateway (and Relay) locally

**Gateway**
```powershell
uvicorn services.gateway.main:app --reload --port 8080
```
Health: `http://localhost:8080/healthz`  
JWKS: `http://localhost:8080/.well-known/jwks.json`

**Relay** (optional)
```powershell
uvicorn services.relay.main:app --reload --port 9090
```

---

## Task 5 — Smoke test (signed OPE)

In a new terminal with venv active:
```powershell
python scripts\demo_send_envelope.py
```
Expect:
- HTTP `200`
- `X-ODIN-*` provenance headers
- Response JSON with `receipt.receipt_hash` and `normalized_payload`

If forwarding is needed, set:
```powershell
$env:RELAY_URL = "http://localhost:9090"
```
Then add `"forward_url": "https://postman-echo.com/post"` to the OPE in `demo_send_envelope.py` and rerun.

---

## Task 6 — Containerize

**Gateway**
```powershell
docker build -f Dockerfile.gateway -t odin-gateway:dev .
```

**Relay**
```powershell
docker build -f Dockerfile.relay -t odin-relay:dev .
```

Run locally (optional):
```powershell
docker run --rm -p 8080:8080 -e ODIN_GATEWAY_PRIVATE_KEY_B64=$env:ODIN_GATEWAY_PRIVATE_KEY_B64 -e ODIN_GATEWAY_KID=$env:ODIN_GATEWAY_KID -e HEL_ALLOWLIST=$env:HEL_ALLOWLIST odin-gateway:dev
```

---

## Task 7 — Deploy to Cloud Run (if user confirms)

Ask user for:
- `GCP_PROJECT_ID`
- `GCP_REGION` (e.g., `us-central1`)

Build & push:
```powershell
gcloud builds submit --tag gcr.io/$env:GCP_PROJECT_ID/odin-gateway .
gcloud builds submit --tag gcr.io/$env:GCP_PROJECT_ID/odin-relay .
```

Deploy:
```powershell
gcloud run deploy odin-gateway `
  --image gcr.io/$env:GCP_PROJECT_ID/odin-gateway `
  --region $env:GCP_REGION `
  --allow-unauthenticated `
  --set-env-vars ODIN_GATEWAY_PRIVATE_KEY_B64=$env:ODIN_GATEWAY_PRIVATE_KEY_B64,ODIN_GATEWAY_KID=$env:ODIN_GATEWAY_KID,HEL_ALLOWLIST=$env:HEL_ALLOWLIST

gcloud run deploy odin-relay `
  --image gcr.io/$env:GCP_PROJECT_ID/odin-relay `
  --region $env:GCP_REGION `
  --allow-unauthenticated `
  --set-env-vars RELAY_ALLOWLIST=$env:RELAY_ALLOWLIST
```

Capture the URLs printed by Cloud Run.

---

## Task 8 — Post-deploy verification

Replace `<GATEWAY_URL>` with the deployed URL:
```powershell
Invoke-WebRequest "<GATEWAY_URL>/healthz" -UseBasicParsing
Invoke-WebRequest "<GATEWAY_URL>/.well-known/jwks.json" -UseBasicParsing
```

Update `scripts/demo_send_envelope.py` base URL to `<GATEWAY_URL>` and run the smoke test again:
```powershell
python scripts\demo_send_envelope.py
```

---

## Task 9 — Debug cookbook

- **Signature fails**: Ensure the message string is exactly `"cid|trace_id|ts"`, Ed25519 keys match, and `sender.jwk` is in the request.
- **CID mismatch**: Payload must be canonical JSON sorted with `(",", ":")` separators. Don’t mutate after signing.
- **HEL block**: Add the target host to `HEL_ALLOWLIST`/`RELAY_ALLOWLIST` env vars.
- **SSRF block**: Relay denies private/reserved IPs by design.
- **Receipts not visible**: Without Firestore, receipts go to `/mnt/data/odin_receipts.jsonl` in container/local FS.

---

## Task 10 — Optional REPL

If the user provides `OPENAI_API_KEY`, start the REPL:
```powershell
$env:OPENAI_API_KEY="<paste>"
python tools\repl\odin_repl.py
```
Try:
```
/open services/gateway/main.py
/ask How do I add a route to export a receipt chain as a signed bundle?
/edit services/gateway/main.py :: Add GET /v1/receipts/export/{trace_id} returning JSON bundle
/run "pytest -q"
```

**End of Playbook.**
