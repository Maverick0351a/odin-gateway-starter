#!/usr/bin/env node
import { OPEClient, b64u } from '../dist/index.js';
import crypto from 'node:crypto';

function usage(){
  console.log(`odin JS CLI\nCommands:\n  sign --gateway <url> --key <b64u_seed> --kid <kid> --payload <json> [--payload-type <t>] [--target-type <t>] [--trace <id>]\n  send --gateway <url> --key <b64u_seed> --kid <kid> --payload <json> [--payload-type <t>] [--target-type <t>] [--trace <id>] [--api-key <k>] [--hmac-secret <s>]`);
}

async function main(){
  const args = process.argv.slice(2);
  if(!args.length) { usage(); process.exit(1); }
  const cmd = args.shift();
  const get = (flag, def) => { const i = args.indexOf(flag); return i>=0 ? args[i+1] : def; };
  const gateway = get('--gateway');
  const key = get('--key');
  const kid = get('--kid');
  const payloadRaw = get('--payload');
  const payloadType = get('--payload-type','application/json');
  const targetType = get('--target-type','gateway');
  const trace = get('--trace') || crypto.randomUUID();
  const apiKey = get('--api-key');
  const hmacSecret = get('--hmac-secret');
  if(!gateway || !key || !kid || !payloadRaw){ usage(); process.exit(1); }
  let payload;
  try { payload = JSON.parse(payloadRaw); } catch { console.error('Invalid JSON'); process.exit(1); }
  const client = new OPEClient(gateway, key, kid, { apiKey, hmacSecret });
  if(cmd === 'sign') {
    const env = client.buildEnvelope(payload, payloadType, targetType, trace);
    console.log(JSON.stringify(env, null, 2));
  } else if(cmd === 'send') {
    const env = client.buildEnvelope(payload, payloadType, targetType, trace);
    const res = await client.sendEnvelope(env);
    console.log(JSON.stringify(res.data, null, 2));
  } else {
    usage(); process.exit(1);
  }
}
main().catch(e=>{ console.error(e); process.exit(1); });
