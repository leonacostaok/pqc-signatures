// Hash layer selector for the vendored (patched) noble sources and the fast forks.
// NOBLE_PQ_HASH=native -> node:crypto (OpenSSL) SHAKE/SHA-2; anything else -> @noble/hashes (pure JS).
import * as nobleSha3 from '@noble/hashes/sha3.js';
import * as nobleSha2 from '@noble/hashes/sha2.js';
import * as nobleHmac from '@noble/hashes/hmac.js';
import * as nobleXof from '@noble/post-quantum/_crystals.js';
import * as native from './native-hash.mjs';

export const HASH_BACKEND = process.env.NOBLE_PQ_HASH === 'native' ? 'native' : 'noble';
const N = HASH_BACKEND === 'native';

export const shake128 = N ? native.shake128 : nobleSha3.shake128;
export const shake256 = N ? native.shake256 : nobleSha3.shake256;
export const sha256 = N ? native.sha256 : nobleSha2.sha256;
export const sha512 = N ? native.sha512 : nobleSha2.sha512;
export const hmac = N ? native.hmac : nobleHmac.hmac;
export const XOF128 = N ? native.XOF128 : nobleXof.XOF128;
export const XOF256 = N ? native.XOF256 : nobleXof.XOF256;
