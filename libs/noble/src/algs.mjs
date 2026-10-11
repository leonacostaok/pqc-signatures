// Algorithm registry: maps (backend, param) to a uniform {keygen, sign, verify, ...} object.
//   backend 'pkg'    = @noble/post-quantum 0.7.1 exactly as installed (baseline)
//   backend 'vendor' = build/vendor/*.js: noble sources + patches/ (pluggable hash layer, cache APIs)
//   backend 'fast'   = src/fast-*.mjs rewrites (ML-DSA, SLH-DSA only)
// The hash layer of 'vendor' and 'fast' is chosen by env NOBLE_PQ_HASH (noble | native).
import { readFileSync } from 'node:fs';
import { hexToBytes } from '@noble/hashes/utils.js';

export const ROOT = new URL('../../../', import.meta.url);
export const LIB = 'noble';
export const LIB_VERSION = JSON.parse(readFileSync(new URL('node_modules/@noble/post-quantum/package.json', ROOT))).version;
export const VECTORS = JSON.parse(readFileSync(new URL('common/vectors.json', ROOT)));
export const REFERENCE = JSON.parse(readFileSync(new URL('common/reference.json', ROOT)));
export const MESSAGE = hexToBytes(VECTORS.message_hex);
export const PARAM_NAMES = VECTORS.params.map((p) => p.name);
export const familyOf = (name) => (name.startsWith('ML-DSA') ? 'ml-dsa' : name.startsWith('SLH-DSA') ? 'slh-dsa' : 'falcon');
export const seedOf = (name) => hexToBytes(VECTORS.params.find((p) => p.name === name).seed_hex);
export const isByteMatch = (name) => VECTORS.params.find((p) => p.name === name).byte_match_expected === true;

const slhKey = (name) => {
  const [, , h, s] = name.split('-');
  return `slh_dsa_${h.toLowerCase()}_${s}`;
};
const mlKey = (name) => ({ 'ML-DSA-44': 'ml_dsa44', 'ML-DSA-65': 'ml_dsa65', 'ML-DSA-87': 'ml_dsa87' })[name];
const falconKey = (name) => ({ 'Falcon-512': 'falcon512', 'Falcon-1024': 'falcon1024' })[name];

export function supports(backend, param) {
  if (backend === 'fast' && familyOf(param) === 'falcon') return false;
  return true;
}

export async function loadAlg(backend, param) {
  const fam = familyOf(param);
  let mod;
  if (backend === 'pkg') {
    mod = await import(fam === 'ml-dsa' ? '@noble/post-quantum/ml-dsa.js' : fam === 'slh-dsa' ? '@noble/post-quantum/slh-dsa.js' : '@noble/post-quantum/falcon.js');
  } else if (backend === 'vendor') {
    mod = await import(fam === 'ml-dsa' ? '../build/vendor/ml-dsa.js' : fam === 'slh-dsa' ? '../build/vendor/slh-dsa.js' : '../build/vendor/falcon.js');
  } else if (backend === 'fast') {
    if (fam === 'falcon') throw new Error('fast backend: Falcon not supported');
    mod = fam === 'ml-dsa' ? await import('./fast-ml-dsa.mjs') : (await import('./fast-slh-dsa.mjs')).slh;
  } else throw new Error(`unknown backend ${backend}`);
  const alg = mod[fam === 'ml-dsa' ? mlKey(param) : fam === 'slh-dsa' ? slhKey(param) : falconKey(param)];
  if (!alg) throw new Error(`no implementation for ${param} in backend ${backend}`);
  const det = { extraEntropy: false }; // deterministic: rnd = 0^32 (ML-DSA) / opt_rand = PK.seed (SLH-DSA) / zero DRBG seed (Falcon)
  return {
    family: fam,
    keygen: (seed) => alg.keygen(seed),
    sign: (msg, sk) => alg.sign(msg, sk, det),
    verify: (sig, msg, pk) => alg.verify(sig, msg, pk),
    expandSk: alg.expandSk ? (sk) => alg.expandSk(sk) : null,
    signPrecomputed: alg.signPrecomputed ? (msg, exp) => alg.signPrecomputed(msg, exp, det) : null,
    expandPk: alg.expandPk ? (pk) => alg.expandPk(pk) : null,
    verifyPrecomputed: alg.verifyPrecomputed ? (sig, msg, exp) => alg.verifyPrecomputed(sig, msg, exp) : null,
  };
}
