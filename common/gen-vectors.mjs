// Generates common/vectors.json: the fixed, shared inputs every library uses.
// Seeds are derived from SHAKE256(label) so anyone can reproduce them.
import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { writeFileSync } from 'node:fs';

const derive = (label, len) => bytesToHex(shake256(utf8ToBytes(`pqc-signatures/v1/${label}`), { dkLen: len }));

const params = [
  ['ML-DSA-44', 'ml-dsa', 32], ['ML-DSA-65', 'ml-dsa', 32], ['ML-DSA-87', 'ml-dsa', 32],
];
for (const h of ['SHA2', 'SHAKE']) for (const n of [128, 192, 256]) for (const v of ['s', 'f'])
  params.push([`SLH-DSA-${h}-${n}${v}`, 'slh-dsa', 3 * (n / 8)]);
const falcon = [['Falcon-512', 'falcon', 48], ['Falcon-1024', 'falcon', 48]];

const message = derive('message', 64);
const out = {
  version: 1,
  message_hex: message,
  context_hex: '',
  notes: [
    'ML-DSA: seed = xi (32 bytes) for ML-DSA.KeyGen_internal (FIPS 204 Alg 6). Pure ML-DSA, empty context, deterministic signing (rnd = 32 zero bytes).',
    'SLH-DSA: seed = SK.seed || SK.prf || PK.seed (3n bytes) for slh_keygen_internal (FIPS 205 Alg 18). Pure SLH-DSA, empty context, deterministic signing (opt_rand = PK.seed).',
    'Falcon: not standardized yet (FN-DSA draft); seed formats differ per library, so Falcon is cross-verify only (no byte match expected).',
  ],
  params: [...params, ...falcon].map(([name, family, len]) => ({
    name, family, seed_hex: derive(`seed/${name}`, len), byte_match_expected: family !== 'falcon',
  })),
};
writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.params.length} params`);
