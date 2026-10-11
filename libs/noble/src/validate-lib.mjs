// Shared by validate-one.mjs and validate-worker.mjs.
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { loadAlg } from './algs.mjs';
import { stageSets, pipelineVerify } from './stage-lib.mjs';
const hx = (h) => hexToBytes(h || '');
// one case -> { pass, got, error }
export async function runCase(c, v, algCache) {
  const isStage = v.id.startsWith('stages.');
  const key = c.param;
  if (!algCache.has(key)) algCache.set(key, await loadAlg(v.backend, c.param));
  const alg = algCache.get(key);
  try {
    if (c.kind === 'keygen') {
      const { publicKey, secretKey } = alg.keygen(hx(c.seed_hex));
      const got = bytesToHex(publicKey) === c.expect_pk_hex && bytesToHex(secretKey) === c.expect_sk_hex;
      return { pass: got, got, error: null };
    }
    if (c.kind === 'siggen') {
      const sk = hx(c.sk_hex);
      const msg = hx(c.msg_hex);
      const ctx = hx(c.ctx_hex);
      let sig;
      if (v.mode === 'precomputed') sig = alg.signPrecomputedCtx(msg, alg.expandSk(sk), ctx);
      else sig = alg.signCtx(msg, sk, ctx);
      const got = bytesToHex(sig) === c.expect_sig_hex;
      return { pass: got, got, error: null };
    }
    // sigver: exceptions count as false
    const pk = hx(c.pk_hex);
    const msg = hx(c.msg_hex);
    const ctx = hx(c.ctx_hex);
    const sig = hx(c.sig_hex);
    let got;
    try {
      if (isStage) {
        if (!algCache.has('sets:' + key)) algCache.set('sets:' + key, await stageSets(c.param));
        const sets = algCache.get('sets:' + key);
        got = pipelineVerify(sets.fam, v.mode === 'total' ? sets.vendor : sets.best, sig, msg, pk, ctx);
      } else if (v.mode === 'precomputed') got = alg.verifyPrecomputedCtx(sig, msg, alg.expandPk(pk), ctx) === true;
      else got = alg.verifyCtx(sig, msg, pk, ctx) === true;
    } catch (e) {
      got = false;
    }
    return { pass: got === c.expect, got, error: null };
  } catch (e) {
    return { pass: false, got: null, error: String(e && e.message ? e.message : e) };
  }
}

