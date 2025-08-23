# odin-sdk

Python SDK for ODIN (Open Provenance Envelope) gateway.

Features:
- Create signed envelopes (Ed25519) using pattern `{cid}|{trace_id}|{ts}`
- Post to gateway `/v1/odin/envelope`
- Automatic JWKS fetch & response signature verification (`X-ODIN-Signature`, `X-ODIN-Response-CID`)
- Optional immediate chain integrity check (`client.send_envelope(..., verify_chain=True)`)
- Receipt chain retrieval & export bundle fetch / verification helpers (`client.verify_export_bundle`)
- CLI (`odin`) with subcommands: `sign`, `send`, `chain`, `export-verify`

## Install (editable for development)
```bash
pip install -e ./packages/odin_sdk
```

## CLI Examples
```bash
odin sign \
  --gateway-url http://127.0.0.1:8080 \
  --priv <b64u_ed25519_seed> --kid demo-sender \
  --ptype openai.tooluse.invoice.v1 --ttype invoice.iso20022.v1 \
  --payload-file examples/openai_invoice.json

odin send --gateway-url http://127.0.0.1:8080 \
  --priv <b64u_ed25519_seed> --kid demo-sender \
  --ptype openai.tooluse.invoice.v1 --ttype invoice.iso20022.v1 \
  --payload-file examples/openai_invoice.json --print-body

odin chain --gateway-url http://127.0.0.1:8080 --priv <seed> --kid demo-sender --trace-id <trace_id>
odin export-verify --gateway-url http://127.0.0.1:8080 --priv <seed> --kid demo-sender --trace-id <trace_id>
```

## Programmatic Usage
```python
from odin_sdk.client import OPEClient
client = OPEClient(gateway_url="http://127.0.0.1:8080", sender_priv_b64=<seed>, sender_kid="demo")
payload = {...}
env = client.create_envelope(payload, "openai.tooluse.invoice.v1", "invoice.iso20022.v1")
body, headers = client.send_envelope(env, verify_chain=True)
chain = client.get_chain(body["receipt"]["trace_id"])
export = client.export_bundle(body["receipt"]["trace_id"])
```

## Development
```bash
python -m build
python -m twine check dist/*
```

## License
MIT
