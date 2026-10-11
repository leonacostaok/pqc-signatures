// fast-keccak.mjs: a generated, fully unrolled Keccak-f[1600] permutation on noble's state32
// layout (50 little-endian u32 words, lane i = words 2i (low) and 2i+1 (high)). All 50 state words
// live in local variables for the whole 24 rounds (one load and one store per word per permutation)
// and every theta/rho/pi/chi/iota step is emitted as straight-line code, so there are no
// table lookups or loop counters in the permutation. Verified against @noble/hashes keccakP at
// module load; used by the SHAKE lane of fast-slh-dsa.mjs.
import { keccakP as nobleKeccakP } from '@noble/hashes/sha3.js';

const RC = [
  '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000', '000000000000808b', '0000000080000001',
  '8000000080008081', '8000000000008009', '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
  '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003', '8000000000008002', '8000000000000080',
  '000000000000800a', '800000008000000a', '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
];
// rotation offsets r[x][y]
const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

const RCL = Int32Array.from(RC, (h) => parseInt(h.slice(8), 16) | 0);
const RCH = Int32Array.from(RC, (h) => parseInt(h.slice(0, 8), 16) | 0);

function generate() {
  const L = [];
  const lane = (x, y) => x + 5 * y;
  for (let i = 0; i < 25; i++) L.push(`let s${i}l = s[${2 * i}] | 0, s${i}h = s[${2 * i + 1}] | 0;`);
  L.push('let c0l, c0h, c1l, c1h, c2l, c2h, c3l, c3h, c4l, c4h, dl, dh;');
  for (let i = 0; i < 25; i++) L.push(`let b${i}l, b${i}h;`);
  // rotate (h, l) by n -> expression strings for [low, high]
  const rot = (l, h, n) => {
    if (n === 0) return [l, h];
    if (n < 32) return [`((${l} << ${n}) | (${h} >>> ${32 - n}))`, `((${h} << ${n}) | (${l} >>> ${32 - n}))`];
    if (n === 32) return [h, l];
    const m = n - 32;
    return [`((${h} << ${m}) | (${l} >>> ${32 - m}))`, `((${l} << ${m}) | (${h} >>> ${32 - m}))`];
  };
  // one round body inside a plain counted loop (a 24x unrolled body is too large for TurboFan)
  L.push('for (let r = 0; r < 24; r++) {');
  {
    // theta
    for (let x = 0; x < 5; x++) {
      L.push(`c${x}l = ${[0, 1, 2, 3, 4].map((y) => `s${lane(x, y)}l`).join(' ^ ')};`);
      L.push(`c${x}h = ${[0, 1, 2, 3, 4].map((y) => `s${lane(x, y)}h`).join(' ^ ')};`);
    }
    for (let x = 0; x < 5; x++) {
      const x1 = (x + 1) % 5;
      const x4 = (x + 4) % 5;
      const [rl, rh] = rot(`c${x1}l`, `c${x1}h`, 1);
      L.push(`dl = c${x4}l ^ ${rl}; dh = c${x4}h ^ ${rh};`);
      for (let y = 0; y < 5; y++) L.push(`s${lane(x, y)}l ^= dl; s${lane(x, y)}h ^= dh;`);
    }
    // rho + pi: B[y][(2x+3y)%5] = rot(A[x][y], r[x][y])
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) {
        const i = lane(x, y);
        const j = lane(y, (2 * x + 3 * y) % 5);
        const [rl, rh] = rot(`s${i}l`, `s${i}h`, ROT[x][y]);
        L.push(`b${j}l = ${rl}; b${j}h = ${rh};`);
      }
    // chi
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) {
        const i = lane(x, y);
        const i1 = lane((x + 1) % 5, y);
        const i2 = lane((x + 2) % 5, y);
        L.push(`s${i}l = b${i}l ^ (~b${i1}l & b${i2}l); s${i}h = b${i}h ^ (~b${i1}h & b${i2}h);`);
      }
    // iota
    L.push('s0l ^= RCL[r]; s0h ^= RCH[r];');
  }
  L.push('}');
  for (let i = 0; i < 25; i++) L.push(`s[${2 * i}] = s${i}l; s[${2 * i + 1}] = s${i}h;`);
  return new Function('RCL', 'RCH', `return function keccakP(s) {\n${L.join('\n')}\n}`)(RCL, RCH);
}

export const keccakP = generate();

// self-check against noble on a pseudo-random state
{
  const a = new Uint32Array(50);
  let x = 0x12345678;
  for (let i = 0; i < 50; i++) {
    x = (Math.imul(x, 1103515245) + 12345) | 0;
    a[i] = x;
  }
  const b = a.slice();
  keccakP(a);
  nobleKeccakP(b, 24);
  for (let i = 0; i < 50; i++) if (a[i] !== b[i]) throw new Error('fast-keccak: self-check failed');
}
