import crypto from 'node:crypto';
import fetch from 'cross-fetch';
import nacl from 'tweetnacl';

export interface Envelope {
  trace_id: string;
  ts: string;
  sender: { kid: string; jwk: any };
  payload: any;
  payload_type: string;
  target_type: string;
  cid: string;
  signature: string;
}

export function b64u(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
export function b64uDecode(s: string): Buffer {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/') + pad, 'base64');
}
export function canonical(obj: any): Buffer { return Buffer.from(JSON.stringify(sortKeys(obj))); }
function sortKeys(obj: any): any {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeys);
  const out: any = {};
  for (const k of Object.keys(obj).sort()) out[k] = sortKeys(obj[k]);
  return out;
}
export function cidSha256(buf: Buffer | Uint8Array): string {
  const h = crypto.createHash('sha256').update(buf).digest('hex');
  return 'sha256:' + h;
}
export function nowIso(): string { return new Date().toISOString(); }
export function genTraceId(): string { return crypto.randomUUID(); }

interface ClientOptions { apiKey?: string; hmacSecret?: string; }

export class OPEClient {
  constructor(readonly gatewayUrl: string, privateKeyB64u: string, readonly senderKid: string, readonly opts: ClientOptions = {}) {
    const seed = b64uDecode(privateKeyB64u);
    if (seed.length !== 32) throw new Error('Ed25519 raw private key must be 32 bytes');
    const kp = nacl.sign.keyPair.fromSeed(seed);
    this.seed = seed;
    this.pub = kp.publicKey;
    this.secret = kp.secretKey; // 64 bytes
  }
  private seed: Buffer;
  private pub: Uint8Array;
  private secret: Uint8Array;

  publicJwk(): any {
    return { kty: 'OKP', crv: 'Ed25519', x: b64u(this.pub), kid: this.senderKid };
  }

  buildEnvelope(payload: any, payloadType: string, targetType: string, traceId?: string, ts?: string): Envelope {
    traceId = traceId || genTraceId();
    ts = ts || nowIso();
    const payloadBytes = Buffer.from(JSON.stringify(sortKeys(payload)));
    const cid = cidSha256(payloadBytes);
    const msg = Buffer.from(`${cid}|${traceId}|${ts}`);
    const signature = b64u(nacl.sign.detached(msg, this.secret));
    return {
      trace_id: traceId,
      ts,
      sender: { kid: this.senderKid, jwk: this.publicJwk() },
      payload,
      payload_type: payloadType,
      target_type: targetType,
      cid,
      signature,
    };
  }

  async sendEnvelope(env: Envelope): Promise<{ data: any; headers: Record<string,string> }> {
    const r = await fetch(this.gatewayUrl.replace(/\/$/,'') + '/v1/odin/envelope', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(this.opts.apiKey ? { 'x-odin-api-key': this.opts.apiKey } : {}), ...(this.opts.hmacSecret ? this.hmacHeaders(env) : {}) },
      body: JSON.stringify(env)
    });
    const headers: Record<string,string> = {};
    r.headers.forEach((v,k)=> headers[k.toLowerCase()] = v);
    const data = await r.json().catch(()=>({}));
    if (!r.ok) throw new Error(`Gateway error ${r.status}: ${JSON.stringify(data)}`);
    // Basic verification: response CID integrity
    const bodyBytes = Buffer.from(JSON.stringify(sortKeys(data)));
    const localCid = cidSha256(bodyBytes);
    if (headers['x-odin-response-cid'] && headers['x-odin-response-cid'] !== localCid) {
      throw new Error('Response CID mismatch');
    }
    return { data, headers };
  }

  private hmacHeaders(env: Envelope): Record<string,string> {
    if(!this.opts.hmacSecret) return {};
    const ts = Date.now().toString();
    const msg = `${env.cid}|${env.trace_id}|${ts}`;
    const mac = crypto.createHmac('sha256', this.opts.hmacSecret).update(msg).digest('base64url');
    return { 'x-odin-ts': ts, 'x-odin-mac': mac };
  }
}
