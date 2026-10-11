//! Raw hashing helpers used by the stage alternatives:
//!  * `keccak_f1600_x4`: 4 independent Keccak-f[1600] permutations in lockstep with AVX2
//!    (`__m256i` holds lane i of all four states). Verified at start-up against the `keccak`
//!    crate's permutation; if the CPU lacks AVX2 (or the self-test fails) `X4_AVAILABLE` is false
//!    and the x4 variants fall back to the scalar raw path.
//!  * scalar raw SHAKE256 / SHA-256 / SHA-512 "fused" calls that build one padded block and run the
//!    permutation / compression function directly (no `digest` buffering, no state cloning).

use std::sync::OnceLock;

pub const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
/// rotation offsets, index x + 5y
pub const RHO: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
/// pi destination index for source index i = x + 5y: y + 5*((2x+3y) mod 5)
pub const PI: [usize; 25] = {
    let mut p = [0usize; 25];
    let mut i = 0;
    while i < 25 {
        let (x, y) = (i % 5, i / 5);
        p[i] = y + 5 * ((2 * x + 3 * y) % 5);
        i += 1;
    }
    p
};

/// Scalar Keccak-f[1600] from the RustCrypto `keccak` crate.
#[inline]
pub fn keccak_f1600(st: &mut [u64; 25]) {
    keccak::Keccak::new().with_f1600(|f| f(st));
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::{PI, RC, RHO};
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn rotl(v: __m256i, r: u32) -> __m256i {
        // variable-count shifts (counts >= 64 yield zero, so r = 0 is handled naturally)
        _mm256_or_si256(_mm256_sll_epi64(v, _mm_cvtsi32_si128(r as i32)), _mm256_srl_epi64(v, _mm_cvtsi32_si128((64 - r) as i32)))
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn f1600_x4(st: &mut [[u64; 25]; 4]) {
        let mut a: [__m256i; 25] = [_mm256_setzero_si256(); 25];
        for i in 0..25 {
            a[i] = _mm256_set_epi64x(st[3][i] as i64, st[2][i] as i64, st[1][i] as i64, st[0][i] as i64);
        }
        let mut b: [__m256i; 25] = [_mm256_setzero_si256(); 25];
        for round in 0..24 {
            // theta
            let mut c = [_mm256_setzero_si256(); 5];
            for x in 0..5 {
                c[x] = _mm256_xor_si256(
                    _mm256_xor_si256(_mm256_xor_si256(a[x], a[x + 5]), _mm256_xor_si256(a[x + 10], a[x + 15])),
                    a[x + 20],
                );
            }
            for x in 0..5 {
                let d = _mm256_xor_si256(c[(x + 4) % 5], rotl(c[(x + 1) % 5], 1));
                for y in 0..5 {
                    a[x + 5 * y] = _mm256_xor_si256(a[x + 5 * y], d);
                }
            }
            // rho + pi
            for i in 0..25 {
                b[PI[i]] = rotl(a[i], RHO[i]);
            }
            // chi
            for y in 0..5 {
                for x in 0..5 {
                    a[x + 5 * y] = _mm256_xor_si256(b[x + 5 * y], _mm256_andnot_si256(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]));
                }
            }
            // iota
            a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(RC[round] as i64));
        }
        for i in 0..25 {
            let mut tmp = [0u64; 4];
            _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, a[i]);
            for l in 0..4 {
                st[l][i] = tmp[l];
            }
        }
    }
}

/// 4-way permutation; `X4_AVAILABLE` says whether this is the AVX2 path or a scalar fallback.
#[inline]
pub fn keccak_f1600_x4(st: &mut [[u64; 25]; 4]) {
    if x4_available() {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            avx2::f1600_x4(st)
        }
    } else {
        for s in st.iter_mut() {
            keccak_f1600(s);
        }
    }
}

static X4: OnceLock<bool> = OnceLock::new();

/// True when AVX2 is present and the x4 permutation reproduces the `keccak` crate on test states.
pub fn x4_available() -> bool {
    *X4.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            if !std::is_x86_feature_detected!("avx2") {
                return false;
            }
            let mut st = [[0u64; 25]; 4];
            let mut seed = 0x9e3779b97f4a7c15u64;
            for l in 0..4 {
                for i in 0..25 {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    st[l][i] = seed.wrapping_mul(l as u64 + 1);
                }
            }
            let mut want = st;
            for s in want.iter_mut() {
                keccak_f1600(s);
                keccak_f1600(s);
            }
            unsafe {
                avx2::f1600_x4(&mut st);
                avx2::f1600_x4(&mut st);
            }
            st == want
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    })
}

// ------------------------------------------------------------------------------------------------
// sponge helpers (scalar + x4)
// ------------------------------------------------------------------------------------------------

#[inline]
pub fn xor_bytes_into(st: &mut [u64; 25], data: &[u8]) {
    for (i, chunk) in data.chunks(8).enumerate() {
        let mut w = [0u8; 8];
        w[..chunk.len()].copy_from_slice(chunk);
        st[i] ^= u64::from_le_bytes(w);
    }
}

#[inline]
pub fn read_bytes(st: &[u64; 25], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let w = st[i].to_le_bytes();
        chunk.copy_from_slice(&w[..chunk.len()]);
    }
}

/// SHAKE256 of a message that fits in a single rate block (<= 135 bytes), `out.len()` <= 136.
#[inline]
pub fn shake256_1block(msg: &[u8], out: &mut [u8]) {
    debug_assert!(msg.len() < 136 && out.len() <= 136);
    let mut block = [0u8; 136];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] ^= 0x1f;
    block[135] ^= 0x80;
    let mut st = [0u64; 25];
    xor_bytes_into(&mut st, &block);
    keccak_f1600(&mut st);
    read_bytes(&st, out);
}

/// SHAKE256 of an arbitrary-length message built from parts, output `out.len()` <= 136 bytes.
pub fn shake256_multi(parts: &[&[u8]], out: &mut [u8]) {
    let mut st = [0u64; 25];
    let mut block = [0u8; 136];
    let mut fill = 0;
    for p in parts {
        for &b in *p {
            block[fill] = b;
            fill += 1;
            if fill == 136 {
                xor_bytes_into(&mut st, &block);
                keccak_f1600(&mut st);
                block = [0u8; 136];
                fill = 0;
            }
        }
    }
    block[fill] ^= 0x1f;
    block[135] ^= 0x80;
    xor_bytes_into(&mut st, &block);
    keccak_f1600(&mut st);
    read_bytes(&st, out);
}

/// Four single-block SHAKE256 computations at once (each `msgs[l].len()` < 136), `n` output bytes per lane.
#[inline]
pub fn shake256_1block_x4(msgs: &[&[u8]; 4], n: usize, out: &mut [[u8; 64]; 4]) {
    let mut st = [[0u64; 25]; 4];
    for l in 0..4 {
        let mut block = [0u8; 136];
        block[..msgs[l].len()].copy_from_slice(msgs[l]);
        block[msgs[l].len()] ^= 0x1f;
        block[135] ^= 0x80;
        xor_bytes_into(&mut st[l], &block);
    }
    keccak_f1600_x4(&mut st);
    for l in 0..4 {
        read_bytes(&st[l], &mut out[l][..n]);
    }
}

/// Streaming SHAKE128 squeezer for 4 lanes with single-block inputs (<= 167 bytes each).
pub struct Shake128X4 {
    st: [[u64; 25]; 4],
}
impl Shake128X4 {
    pub fn new(msgs: &[&[u8]; 4]) -> Self {
        let mut st = [[0u64; 25]; 4];
        for l in 0..4 {
            let mut block = [0u8; 168];
            block[..msgs[l].len()].copy_from_slice(msgs[l]);
            block[msgs[l].len()] ^= 0x1f;
            block[167] ^= 0x80;
            xor_bytes_into(&mut st[l], &block);
        }
        Self { st }
    }
    /// Produce the next 168-byte output block for every lane.
    pub fn squeeze_block(&mut self, out: &mut [[u8; 168]; 4]) {
        keccak_f1600_x4(&mut self.st);
        for l in 0..4 {
            read_bytes(&self.st[l], &mut out[l]);
        }
    }
}

/// Scalar streaming SHAKE128 (single-block input) on the raw permutation.
pub struct Shake128Raw {
    st: [u64; 25],
}
impl Shake128Raw {
    pub fn new(msg: &[u8]) -> Self {
        let mut block = [0u8; 168];
        block[..msg.len()].copy_from_slice(msg);
        block[msg.len()] ^= 0x1f;
        block[167] ^= 0x80;
        let mut st = [0u64; 25];
        xor_bytes_into(&mut st, &block);
        Self { st }
    }
    pub fn squeeze_block(&mut self, out: &mut [u8; 168]) {
        keccak_f1600(&mut self.st);
        read_bytes(&self.st, out);
    }
}

// ------------------------------------------------------------------------------------------------
// raw SHA-2 with midstate (FIPS 205 SHA2 suites)
// ------------------------------------------------------------------------------------------------

pub const SHA256_IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
pub const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Minimal streaming SHA-256 over `sha2::block_api::compress256`, seeded from a midstate (`consumed` bytes already compressed).
#[derive(Clone)]
pub struct RawSha256 {
    pub state: [u32; 8],
    pub consumed: u64,
    buf: [u8; 64],
    fill: usize,
}
impl RawSha256 {
    pub fn from_midstate(state: [u32; 8], consumed: u64) -> Self {
        Self { state, consumed, buf: [0; 64], fill: 0 }
    }
    pub fn new() -> Self {
        Self::from_midstate(SHA256_IV, 0)
    }
    #[inline]
    pub fn update(&mut self, mut data: &[u8]) {
        if self.fill > 0 {
            let take = (64 - self.fill).min(data.len());
            self.buf[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill == 64 {
                sha2::block_api::compress256(&mut self.state, core::slice::from_ref(&self.buf));
                self.consumed += 64;
                self.fill = 0;
            }
        }
        let full = data.len() / 64 * 64;
        if full > 0 {
            // SAFETY-free reinterpretation: copy into aligned blocks
            let mut blocks: Vec<[u8; 64]> = Vec::with_capacity(full / 64);
            for c in data[..full].chunks_exact(64) {
                let mut b = [0u8; 64];
                b.copy_from_slice(c);
                blocks.push(b);
            }
            sha2::block_api::compress256(&mut self.state, &blocks);
            self.consumed += full as u64;
            data = &data[full..];
        }
        if !data.is_empty() {
            // only reached with an empty or just-flushed buffer
            self.buf[..data.len()].copy_from_slice(data);
            self.fill = data.len();
        }
    }
    /// Finalize into `out` (first `out.len()` bytes of the digest).
    #[inline]
    pub fn finalize_into(mut self, out: &mut [u8]) {
        let total_bits = (self.consumed + self.fill as u64) * 8;
        self.buf[self.fill] = 0x80;
        self.fill += 1;
        if self.fill > 56 {
            for b in &mut self.buf[self.fill..] {
                *b = 0;
            }
            sha2::block_api::compress256(&mut self.state, core::slice::from_ref(&self.buf));
            self.fill = 0;
        }
        for b in &mut self.buf[self.fill..56] {
            *b = 0;
        }
        self.buf[56..].copy_from_slice(&total_bits.to_be_bytes());
        sha2::block_api::compress256(&mut self.state, core::slice::from_ref(&self.buf));
        let mut d = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            d[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        out.copy_from_slice(&d[..out.len()]);
    }
}

#[derive(Clone)]
pub struct RawSha512 {
    pub state: [u64; 8],
    pub consumed: u64,
    buf: [u8; 128],
    fill: usize,
}
impl RawSha512 {
    pub fn from_midstate(state: [u64; 8], consumed: u64) -> Self {
        Self { state, consumed, buf: [0; 128], fill: 0 }
    }
    pub fn new() -> Self {
        Self::from_midstate(SHA512_IV, 0)
    }
    #[inline]
    pub fn update(&mut self, mut data: &[u8]) {
        if self.fill > 0 {
            let take = (128 - self.fill).min(data.len());
            self.buf[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill == 128 {
                sha2::block_api::compress512(&mut self.state, core::slice::from_ref(&self.buf));
                self.consumed += 128;
                self.fill = 0;
            }
        }
        let full = data.len() / 128 * 128;
        if full > 0 {
            let mut blocks: Vec<[u8; 128]> = Vec::with_capacity(full / 128);
            for c in data[..full].chunks_exact(128) {
                let mut b = [0u8; 128];
                b.copy_from_slice(c);
                blocks.push(b);
            }
            sha2::block_api::compress512(&mut self.state, &blocks);
            self.consumed += full as u64;
            data = &data[full..];
        }
        if !data.is_empty() {
            // only reached with an empty or just-flushed buffer
            self.buf[..data.len()].copy_from_slice(data);
            self.fill = data.len();
        }
    }
    #[inline]
    pub fn finalize_into(mut self, out: &mut [u8]) {
        let total_bits = ((self.consumed + self.fill as u64) * 8) as u128;
        self.buf[self.fill] = 0x80;
        self.fill += 1;
        if self.fill > 112 {
            for b in &mut self.buf[self.fill..] {
                *b = 0;
            }
            sha2::block_api::compress512(&mut self.state, core::slice::from_ref(&self.buf));
            self.fill = 0;
        }
        for b in &mut self.buf[self.fill..112] {
            *b = 0;
        }
        self.buf[112..].copy_from_slice(&total_bits.to_be_bytes());
        sha2::block_api::compress512(&mut self.state, core::slice::from_ref(&self.buf));
        let mut d = [0u8; 64];
        for (i, w) in self.state.iter().enumerate() {
            d[8 * i..8 * i + 8].copy_from_slice(&w.to_be_bytes());
        }
        out.copy_from_slice(&d[..out.len()]);
    }
}
