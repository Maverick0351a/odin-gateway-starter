import json, base64, hashlib, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
import os, sys, pathlib
os.environ.pop('ODIN_REQUIRE_API_KEY', None)
pkg_dir = pathlib.Path(__file__).resolve().parents[1] / 'packages'
sys.path.insert(0, str(pkg_dir))
if 'services.gateway.main' in sys.modules:
    del sys.modules['services.gateway.main']

# Ensure packages path
import pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "packages"))

from services.gateway.main import app
from odin_sdk.client import OPEClient, b64u

def test_sdk_send_and_verify():
    # Generate sender key
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    priv_b64 = b64u(priv_raw)
    client = OPEClient("http://testserver", priv_b64, "sdk-sender")

    # Build OpenAI tool-use style payload
    import json as _json
    payload = {
        "tool_calls": [{"type":"function","function":{"name":"create_invoice","arguments": _json.dumps({
            "invoice_id":"INV-SDK-1","amount": 12.34, "currency":"USD","customer_name":"SDK Co","description":"SDK test"})}}],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    env = client.create_envelope(payload, "openai.tooluse.invoice.v1", "invoice.iso20022.v1")

    # In-process FastAPI TestClient (no network). We'll patch JWKS fetch to use it.
    test_client = TestClient(app)
    client._fetch_jwks = lambda: test_client.get("/.well-known/jwks.json").json()
    r = test_client.post("/v1/odin/envelope", json=env)
    assert r.status_code == 200
    data = r.json()
    # Verify gateway signature using client internal method (expose _verify_response for test)
    headers = {k.lower(): v for k,v in r.headers.items()}
    client._verify_response(data, headers)
    assert data["receipt"]["receipt_hash"] == headers["x-odin-receipt-hash"]
    assert data["normalized_payload"]["Document"]["FIToFICstmrCdtTrf"]["GrpHdr"]["MsgId"] == "INV-SDK-1"
