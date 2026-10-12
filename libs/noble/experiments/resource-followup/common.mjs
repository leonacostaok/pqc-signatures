import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
export const specifications = [
  ...[44, 65, 87].map((n) => ({ parameter: `ML-DSA-${n}`, module: 'ml-dsa.js', export: `ml_dsa${n}`, affected: true })),
  ...['sha2', 'shake'].flatMap((h) => [128, 192, 256].flatMap((n) => ['f', 's'].map((s) => ({ parameter: `SLH-DSA-${h.toUpperCase()}-${n}${s}`, module: 'slh-dsa.js', export: `slh_dsa_${h}_${n}${s}`, affected: false })))),
  ...[512, 1024].map((n) => ({ parameter: `Falcon-${n}`, module: 'falcon.js', export: `falcon${n}`, affected: false, falcon: true }))
];
export const hex = (x) => Buffer.from(x).toString('hex');
export const bytes = (x) => Uint8Array.from(Buffer.from(x, 'hex'));
export const eq = (a, b) => { if (a.length !== b.length) return false; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; };
export async function algorithm(root, parameter) {
  const spec = specifications.find((x) => x.parameter === parameter); assert(spec);
  const api = await import(pathToFileURL(`${root}/${spec.module}`)); return { spec, alg: api[spec.export] };
}
export const decode = (r) => Object.fromEntries(Object.entries(r).map(([k,v]) => ['seed','message','context','entropy','publicKey','secretKey','signature'].includes(k) ? [k, bytes(v)] : [k,v]));
export function prepare(alg, spec, c, op) {
  const seed = c.seed.slice(), message = c.message.slice(), context = c.context.slice();
  const pk = c.publicKey.slice(), sk = c.secretKey.slice(), sig = c.signature.slice(), entropy = c.entropy.slice();
  const opts = spec.falcon ? { extraEntropy: entropy } : { context, extraEntropy: false };
  const verOpts = spec.falcon ? {} : { context };
  return {
    call: () => op === 'keygen' ? alg.keygen(seed) : op === 'getPublicKey' ? alg.getPublicKey(sk)
      : op === 'sign' ? alg.sign(message, sk, opts) : alg.verify(sig, message, pk, verOpts),
    check: (r) => {
      if (op === 'keygen') assert(eq(r.publicKey,c.publicKey) && eq(r.secretKey,c.secretKey));
      else if (op === 'verify') assert.equal(r,true);
      else assert(eq(r,op === 'sign' ? c.signature : c.publicKey));
      for (const [a,b] of [[seed,c.seed],[message,c.message],[context,c.context],[pk,c.publicKey],[sk,c.secretKey],[sig,c.signature],[entropy,c.entropy]]) assert(eq(a,b));
      return op === 'keygen' ? [r.publicKey,r.secretKey] : op === 'verify' ? [Uint8Array.of(1)] : [r];
    }
  };
}
