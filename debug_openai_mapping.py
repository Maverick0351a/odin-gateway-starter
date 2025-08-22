import json, hashlib, base64, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
if 'services.gateway.main' in sys.modules: del sys.modules['services.gateway.main']
from services.gateway.main import app
client = TestClient(app)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=') .decode('ascii')

payload = {
 'tool_calls':[{'type':'function','function':{'name':'create_invoice','arguments':json.dumps({'invoice_id':'INV-OAI-1','amount':321.5,'currency':'USD','customer_name':'OpenAI Co','description':'Tool use'})}}],
 'created_at': datetime.now(timezone.utc).isoformat()
}
priv = Ed25519PrivateKey.generate()
pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
payload_bytes = json.dumps(payload, sort_keys=True, separators=(',',':')).encode()
cid = 'sha256:' + hashlib.sha256(payload_bytes).hexdigest()
trace_id = 'debug-trace'
ts = datetime.now(timezone.utc).isoformat()
msg = f"{cid}|{trace_id}|{ts}".encode()
sig = priv.sign(msg)
sender_jwk={'kty':'OKP','crv':'Ed25519','x':b64u(pub),'kid':'debug'}
body={'trace_id':trace_id,'ts':ts,'sender':{'kid':'debug','jwk':sender_jwk},'payload':payload,'payload_type':'openai.tooluse.invoice.v1','target_type':'invoice.iso20022.v1','cid':cid,'signature':b64u(sig)}
resp=client.post('/v1/odin/envelope', json=body)
print('STATUS', resp.status_code)
print('RESP', resp.text)
