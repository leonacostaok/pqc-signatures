// Builds common/validation/validation.json(.gz): the shared validation suite every library runs.
//  1. NIST ACVP (usnistgov/ACVP-Server gen-val/json-files) FIPS 204/205 vectors, pure/external interface:
//     keyGen (all), deterministic sigGen (subset), sigVer (positive and negative cases, every NIST "reason").
//  2. A negative/edge suite derived from common/vectors.json: wrong message, wrong context, wrong key,
//     bit flips in every signature region, truncated/extended/zeroed signatures, ML-DSA z-norm and hint
//     malformations, plus positive controls (empty and non-empty context).
// Usage: node common/gen-validation.mjs <path to ACVP-Server/gen-val/json-files>
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import * as slh from '@noble/post-quantum/slh-dsa.js';
import { bytesToHex as hex, hexToBytes as unhex } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { join } from 'node:path';

const ACVP = process.argv[2];
if (!ACVP) throw new Error('usage: gen-validation.mjs <ACVP json-files dir>');
const load = (d) => JSON.parse(readFileSync(join(ACVP, d, 'internalProjection.json')));
const cases = [];
const add = (c) => cases.push({ id: `${c.source}/${c.kind}/${c.param}/${cases.length}`, ...c });

// --- ACVP keyGen
for (const g of load('ML-DSA-keyGen-FIPS204').testGroups) for (const t of g.tests)
  add({ source: 'acvp', kind: 'keygen', param: g.parameterSet, tcId: t.tcId, seed_hex: t.seed.toLowerCase(), expect_pk_hex: t.pk.toLowerCase(), expect_sk_hex: t.sk.toLowerCase() });
for (const g of load('SLH-DSA-keyGen-FIPS205').testGroups) for (const t of g.tests)
  add({ source: 'acvp', kind: 'keygen', param: g.parameterSet, tcId: t.tcId, seed_hex: (t.skSeed + t.skPrf + t.pkSeed).toLowerCase(), expect_pk_hex: t.pk.toLowerCase(), expect_sk_hex: t.sk.toLowerCase() });

// --- ACVP sigGen: deterministic, pure, external interface (with context). Limit per param to keep slow SLH "s" sets sane.
const SIGGEN_PER_PARAM = { 'ML-DSA': 15, 'SLH-DSA': 2 };
for (const f of ['ML-DSA-sigGen-FIPS204', 'SLH-DSA-sigGen-FIPS205']) {
  const fam = f.slice(0, f.indexOf('-sig'));
  for (const g of load(f).testGroups) {
    if (!g.deterministic || g.signatureInterface !== 'external' || g.preHash !== 'pure' || g.externalMu) continue;
    for (const t of g.tests.slice(0, SIGGEN_PER_PARAM[fam]))
      add({ source: 'acvp', kind: 'siggen', param: g.parameterSet, tcId: t.tcId, sk_hex: t.sk.toLowerCase(), pk_hex: t.pk.toLowerCase(), msg_hex: t.message.toLowerCase(), ctx_hex: t.context.toLowerCase(), expect_sig_hex: t.signature.toLowerCase() });
  }
}
// --- ACVP sigVer: pure, external. ML-DSA: all. SLH-DSA: one case per (param, reason).
for (const f of ['ML-DSA-sigVer-FIPS204', 'SLH-DSA-sigVer-FIPS205']) {
  const seen = new Set();
  for (const g of load(f).testGroups) {
    if (g.signatureInterface !== 'external' || g.preHash !== 'pure' || g.externalMu) continue;
    for (const t of g.tests) {
      const k = `${g.parameterSet}/${t.reason}`;
      if (f.startsWith('SLH') && seen.has(k)) continue;
      seen.add(k);
      add({ source: 'acvp', kind: 'sigver', param: g.parameterSet, tcId: t.tcId, reason: t.reason, pk_hex: t.pk.toLowerCase(), msg_hex: t.message.toLowerCase(), ctx_hex: t.context.toLowerCase(), sig_hex: t.signature.toLowerCase(), expect: t.testPassed });
    }
  }
}

// --- Negative / edge suite from our own vectors
const V = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url)));
const impl = (name) => name.startsWith('ML-DSA') ? { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 }[name]
  : slh[`slh_dsa_${name.split('-')[2].toLowerCase()}_${name.split('-')[3]}`];
const MLDSA = { 'ML-DSA-44': { k: 4, l: 4, g1bits: 18, omega: 80, ctil: 32 }, 'ML-DSA-65': { k: 6, l: 5, g1bits: 20, omega: 55, ctil: 48 }, 'ML-DSA-87': { k: 8, l: 7, g1bits: 20, omega: 75, ctil: 64 } };
for (const [k, m] of Object.entries(MLDSA)) if (m.ctil + m.l * 32 * m.g1bits + m.omega + m.k !== { 'ML-DSA-44': 2420, 'ML-DSA-65': 3309, 'ML-DSA-87': 4627 }[k]) throw new Error('sig layout ' + k);
const msg = unhex(V.message_hex);
const flip = (b, i) => { const c = b.slice(); c[i] ^= 1; return c; };
for (const p of V.params.filter((p) => p.byte_match_expected)) {
  const alg = impl(p.name);
  const { publicKey: pk, secretKey: sk } = alg.keygen(unhex(p.seed_hex));
  const other = alg.keygen(new Uint8Array(p.name.startsWith('ML') ? 32 : unhex(p.seed_hex).length).fill(7)).publicKey;
  const sig = alg.sign(msg, sk, { extraEntropy: false });
  const ctx = new TextEncoder().encode('pqc-signatures context');
  const sigCtx = alg.sign(msg, sk, { extraEntropy: false, context: ctx });
  const neg = (reason, o, expect = false) => add({ source: 'negative', kind: 'sigver', param: p.name, reason, pk_hex: hex(o.pk ?? pk), msg_hex: hex(o.msg ?? msg), ctx_hex: hex(o.ctx ?? new Uint8Array()), sig_hex: hex(o.sig ?? sig), expect });
  neg('positive control (empty context)', {}, true);
  neg('positive control (non-empty context)', { sig: sigCtx, ctx }, true);
  neg('wrong message (1 bit flipped)', { msg: flip(msg, 0) });
  neg('empty message', { msg: new Uint8Array() });
  neg('wrong context (context given, signed without)', { ctx });
  neg('wrong context (signed with context, verified without)', { sig: sigCtx });
  neg('wrong public key (other key, same param)', { pk: other });
  neg('public key bit flipped', { pk: flip(pk, pk.length - 1) });
  neg('signature truncated by 1 byte', { sig: sig.slice(0, -1) });
  neg('signature extended by 1 byte', { sig: Uint8Array.from([...sig, 0]) });
  neg('all-zero signature', { sig: new Uint8Array(sig.length) });
  neg('signature first bit flipped', { sig: flip(sig, 0) });
  neg('signature middle bit flipped', { sig: flip(sig, sig.length >> 1) });
  neg('signature last bit flipped', { sig: flip(sig, sig.length - 1) });
  if (MLDSA[p.name]) {
    const m = MLDSA[p.name];
    const zLen = m.l * 32 * m.g1bits; // each z coefficient packs into g1bits bits
    // z starts after c~. Packed value 0 decodes to z = gamma1 which violates ||z||inf < gamma1 - beta.
    const zbad = sig.slice(); zbad.fill(0, m.ctil, m.ctil + 3);
    neg('ML-DSA: z coefficient out of range (= gamma1)', { sig: zbad });
    const hOff = m.ctil + zLen;
    // hint section: omega index bytes followed by k cumulative counts. Make counts decreasing -> malformed.
    const h1 = sig.slice(); h1[hOff + m.omega] = 0xff;
    neg('ML-DSA: hint count exceeds omega', { sig: h1 });
    const h2 = sig.slice(); const cnt = sig[hOff + m.omega + m.k - 1];
    if (cnt >= 2) { const a = h2[hOff], b = h2[hOff + 1]; h2[hOff] = b; h2[hOff + 1] = a; if (a !== b) neg('ML-DSA: hint indices not strictly increasing', { sig: h2 }); }
    const h3 = sig.slice(); if (cnt < m.omega) { h3[hOff + m.omega - 1] = 1; neg('ML-DSA: nonzero padding after last hint index', { sig: h3 }); }
  } else {
    const n = pk.length / 2;
    neg('SLH-DSA: randomizer R flipped', { sig: flip(sig, n - 1) });
    neg('SLH-DSA: FORS section flipped', { sig: flip(sig, n + 5) });
    neg('SLH-DSA: last hypertree layer flipped', { sig: flip(sig, sig.length - n - 1) });
  }
}

const out = { version: 1, generated: new Date().toISOString().slice(0, 10), source: 'usnistgov/ACVP-Server gen-val/json-files + negative suite (common/gen-validation.mjs)', cases };
const counts = {}; for (const c of cases) counts[`${c.source}/${c.kind}`] = (counts[`${c.source}/${c.kind}`] ?? 0) + 1;
console.log(counts, 'total', cases.length);
writeFileSync(new URL('./validation/validation.json.gz', import.meta.url), gzipSync(JSON.stringify(out)));
