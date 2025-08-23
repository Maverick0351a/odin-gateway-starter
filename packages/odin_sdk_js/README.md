## ODIN JS / TypeScript SDK

Early preview SDK for interacting with an ODIN Gateway (OPE envelopes, receipts, export bundles) in Node / browser (fetch polyfill required for browser bundlers).

Features:
* Build & sign envelopes (`<cid>|<trace_id>|<ts>` Ed25519)
* Send with optional API key + HMAC (`X-ODIN-API-Key`, `X-ODIN-API-MAC`)
* Automatic response CID + signature verification
* Receipt chain fetch + integrity check (hash + link + hop index)
* Export bundle fetch + verification (chain, bundle CID, signature pattern)
* CLI (`odin`) parity commands: `sign`, `send`, `chain`, `export-verify`

### Install
```bash
npm install @maverick0351a/odin-sdk-js
```

### Quick Start
```typescript
import { OPEClient } from '@maverick0351a/odin-sdk-js';

const gateway = 'https://api.odinprotocol.dev'; // replace with your gateway URL
const seed = process.env.SENDER_SEED_B64U!;    // 32-byte Ed25519 seed (base64url w/out padding)
const kid  = 'demo-sender';

const client = new OPEClient(gateway, seed, kid, { apiKey: process.env.ODIN_API_KEY, hmacSecret: process.env.ODIN_API_SECRET });
const payload = { invoice_id: 'INV-100', amount: 42, currency: 'USD' };
const env = client.buildEnvelope(payload, 'invoice.vendor.v1', 'invoice.iso20022.v1');
const { data, headers } = await client.sendEnvelope(env);
console.log('Trace', data.trace_id, 'Receipt Hash', headers['x-odin-receipt-hash']);
```

### HMAC Auth
If your gateway enforces API key + HMAC, supply `apiKey` + `hmacSecret` in the `OPEClient` options. The SDK computes:
```
mac = base64url( HMAC_SHA256(secret, `${cid}|${trace_id}|${ts}`) )
```
Header: `X-ODIN-API-MAC: <mac>`

### CLI Usage
After `npm install` (or linking this package locally):
```bash
node ./node_modules/.bin/odin send \
  --gateway https://api.odinprotocol.dev \
  --key $SENDER_SEED_B64U --kid demo-sender \
  --payload '{"foo":1}' --payload-type vendor.event.v1 --target-type canonical.event.v1
```

Commands:
* `sign` – build envelope only
* `send` – sign + POST + verify response signature
* `chain` – fetch + verify receipt chain
* `export-verify` – fetch export bundle + verify hash linkage, bundle CID & signature

Exit codes: `0` success, `2` verification failure.

### Hosted Verify
Public verification UI & JSON APIs (once deployed):
```
Trace JSON  GET https://verify.odinprotocol.dev/verify/<trace_id>?gateway_url=https://api.odinprotocol.dev
Bundle POST https://verify.odinprotocol.dev/verify/bundle
```

### Browser Notes
The package uses `cross-fetch`; for bundlers ensure Node crypto polyfills if targeting the browser, or expose a WebCrypto-based path (future enhancement).

### Roadmap
* WebCrypto fallback (browser native Ed25519 once widely available)
* Replay defense helper (nonce cache)
* Incremental Merkle proofs for large chains

### License
MIT
