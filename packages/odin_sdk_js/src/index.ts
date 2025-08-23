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
interface JwksCache { keys: any[]; fetchedAt: number; }

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
  private jwks?: JwksCache;
  private jwksTtlMs = 5 * 60 * 1000;

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
    // Optional signature verification
    if (headers['x-odin-signature'] && headers['x-odin-kid']) {
      const receiptTs = data?.receipt?.ts || data?.receipt?.created_at || data?.receipt?.timestamp;
      const msg = Buffer.from(`${localCid}|${data.trace_id}|${receiptTs}`);
      const ok = await this.verifySignature(headers['x-odin-kid'], headers['x-odin-signature'], msg);
      if (!ok) {
        throw new Error('Response signature verification failed');
      }
    }
    return { data, headers };
  }

  private hmacHeaders(env: Envelope): Record<string,string> {
    if(!this.opts.hmacSecret) return {};
    const msg = `${env.cid}|${env.trace_id}|${env.ts}`;
    const mac = crypto.createHmac('sha256', this.opts.hmacSecret).update(msg).digest('base64url');
    return { 'x-odin-api-mac': mac };
  }

  private async loadJwks(force = false): Promise<any[]> {
    const now = Date.now();
    if (!force && this.jwks && now - this.jwks.fetchedAt < this.jwksTtlMs) {
      return this.jwks.keys;
    }
    const r = await fetch(this.gatewayUrl.replace(/\/$/,'') + '/.well-known/jwks.json');
    const data = await r.json();
    const keys = Array.isArray(data?.keys) ? data.keys : [];
    this.jwks = { keys, fetchedAt: now };
    return keys;
  }

  private async verifySignature(kid: string, sigB64u: string, message: Buffer): Promise<boolean> {
    const keys = await this.loadJwks();
    const jwk = keys.find(k => k.kid === kid && k.kty === 'OKP' && k.crv === 'Ed25519');
    if (!jwk?.x) return false;
    try {
      const sig = b64uDecode(sigB64u);
      const pub = b64uDecode(jwk.x);
      return nacl.sign.detached.verify(message, sig, pub);
    } catch { return false; }
  }

  private receiptHash(r: any): string {
    const clone: any = {}; // build with sorted keys minus signature
    for (const k of Object.keys(r).sort()) {
      if (k === 'receipt_signature') continue;
      clone[k] = sortKeys(r[k]);
    }
    const bytes = Buffer.from(JSON.stringify(clone));
    return crypto.createHash('sha256').update(bytes).digest('hex');
  }

  async fetchChain(traceId: string, verify = true): Promise<{ receipts: any[]; verified: boolean; }> {
    const r = await fetch(this.gatewayUrl.replace(/\/$/,'') + `/v1/receipts/hops/chain/${traceId}`);
    const data = await r.json();
    const receipts = data.hops || [];
    if (!verify) return { receipts, verified: true };
    let prev: any = null;
    let ok = true;
    receipts.forEach((rcp: any, idx: number) => {
      if (this.receiptHash(rcp) !== rcp.receipt_hash) ok = false;
      if (idx && rcp.prev_receipt_hash !== prev.receipt_hash) ok = false;
      if (rcp.hop !== idx) ok = false;
      prev = rcp;
    });
    return { receipts, verified: ok };
  }

  async exportVerify(traceId: string): Promise<{ bundle: any; verified: boolean; details: any; }> {
    const r = await fetch(this.gatewayUrl.replace(/\/$/,'') + `/v1/receipts/export/${traceId}`);
    const data = await r.json();
    const bundle = data.bundle || data;
    const receipts = bundle.receipts || [];
    // recompute chain
    let chainOk = true; let prev: any = null;
    for (let i=0;i<receipts.length;i++) {
      const rcp = receipts[i];
      if (this.receiptHash(rcp) !== rcp.receipt_hash) { chainOk = false; break; }
      if (i && rcp.prev_receipt_hash !== prev.receipt_hash) { chainOk = false; break; }
      if (rcp.hop !== i) { chainOk = false; break; }
      prev = rcp;
    }
    // bundle CID: spec uses entire bundle excluding signature field when computing initial cid (gateway stores separately)
    const bundleClone: any = { ...bundle };
    delete bundleClone.bundle_signature;
    const bundleCidLocal = cidSha256(Buffer.from(JSON.stringify(sortKeys(bundle))));
    const cidMatch = data.bundle_cid === bundleCidLocal || bundle.bundle_cid === bundleCidLocal;
    let sigOk = false; let variant: string | null = null;
    if (data.bundle_signature) {
      const msg = Buffer.from(`${bundleCidLocal}|${bundle.trace_id}|${bundle.exported_at}`);
      sigOk = await this.verifySignature(bundle.gateway_kid, data.bundle_signature, msg);
      variant = sigOk ? 'cid|trace|exported_at' : null;
    }
    const verified = chainOk && cidMatch && sigOk;
    return { bundle, verified, details: { chainOk, cidMatch, sigOk, variant, bundleCidLocal } };
  }
}
