//! ML-DSA verify split into the canonical stages (FIPS 204 Alg. 8 + external wrapper), built on the
//! vendored `ml-dsa` crate's internals (v0) plus alternatives implemented here.
//!
//! Stage outputs are rich types; `canon_*` turns them into the canonical bytes of the contract.

#![allow(non_snake_case)]

use crate::fasthash::{Shake128Raw, Shake128X4};
use hybrid_array::{typenum::Unsigned, Array};
use ml_dsa::algebra::{AlgebraExt, Elem, NttMatrix, NttPolynomial, NttVector, Polynomial, Vector};
use ml_dsa::crypto::H;
use ml_dsa::hint::Hint;
use ml_dsa::ntt::{Ntt, NttInverse};
use ml_dsa::param::{EncodedSignature, EncodedVerifyingKey, MlDsaParams, ParameterSet, SignatureParams, VerifyingKeyParams};
#[allow(unused_imports)]
use ml_dsa::param::SignatureParams as _;
use ml_dsa::sampling::{expand_a, rej_ntt_poly, sample_in_ball};
use ml_dsa::{MuBuilder, B32, B64};
use rayon::prelude::*;

pub const Q: u32 = 8_380_417;
pub const D: u32 = 13;

// ------------------------------------------------------------------------------------------------
// stage output types + canonical serialisation
// ------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct Decoded<P: MlDsaParams> {
    pub rho: B32,
    pub t1: Vector<P::K>,
    pub c_tilde: Array<u8, P::Lambda>,
    pub z: Vector<P::L>,
    pub h: Hint<P>,
}

fn push_vec<K: hybrid_array::ArraySize>(out: &mut Vec<u8>, v: &Vector<K>) {
    for p in v.0.iter() {
        for c in p.0.iter() {
            out.extend_from_slice(&c.0.to_le_bytes());
        }
    }
}

impl<P: MlDsaParams> Decoded<P> {
    /// full state (for equality checks between variants): c~ || rho || t1 || z || hint bits
    pub fn full_bytes(&self) -> Vec<u8> {
        let mut v = self.c_tilde.to_vec();
        v.extend_from_slice(&self.rho);
        push_vec(&mut v, &self.t1);
        push_vec(&mut v, &self.z);
        for row in self.h.0.iter() {
            v.extend(row.iter().map(|&b| b as u8));
        }
        v
    }
    pub fn canon(&self) -> Vec<u8> {
        self.c_tilde.to_vec()
    }
}

pub fn canon_matrix<P: MlDsaParams>(a: &NttMatrix<P::K, P::L>) -> Vec<u8> {
    let mut v = Vec::with_capacity(P::K::USIZE * P::L::USIZE * 1024);
    for row in a.0.iter() {
        for p in row.0.iter() {
            for c in p.0.iter() {
                v.extend_from_slice(&c.0.to_le_bytes());
            }
        }
    }
    v
}

pub fn canon_vector<K: hybrid_array::ArraySize>(w: &Vector<K>) -> Vec<u8> {
    let mut v = Vec::with_capacity(K::USIZE * 1024);
    push_vec(&mut v, w);
    v
}

/// hint_check output: w1Encode bytes + whether c~' == c~ (and the z bound held)
#[derive(Clone, PartialEq)]
pub struct HintOut {
    pub w1enc: Vec<u8>,
    pub ok: bool,
}

// ------------------------------------------------------------------------------------------------
// shared helpers
// ------------------------------------------------------------------------------------------------

fn ctx_ok(ctx: &[u8]) -> bool {
    ctx.len() <= 255
}

pub fn w1_bits<P: ParameterSet>() -> usize {
    if P::Gamma2::U32 == (Q - 1) / 88 {
        6
    } else {
        4
    }
}

// ------------------------------------------------------------------------------------------------
// decode
// ------------------------------------------------------------------------------------------------

/// v0: the crate's pkDecode / sigDecode primitives (incl. hint validity and ||z|| bound as in `Signature::decode`).
pub fn decode_v0<P: MlDsaParams>(pk: &[u8], sig: &[u8]) -> Option<Decoded<P>> {
    let pk = <&EncodedVerifyingKey<P>>::try_from(pk).ok()?;
    let sig = <&EncodedSignature<P>>::try_from(sig).ok()?;
    let (rho, t1_enc) = P::split_vk(pk);
    let t1 = P::decode_t1(t1_enc);
    let (c_tilde, z_enc, h_enc) = P::split_sig(sig);
    let z = P::decode_z(z_enc);
    let h = Hint::<P>::bit_unpack(h_enc)?;
    if z.infinity_norm() >= P::GAMMA1_MINUS_BETA {
        return None;
    }
    Some(Decoded { rho: rho.clone(), t1, c_tilde: c_tilde.clone(), z, h })
}

#[inline]
fn unpack_t1_poly(poly: &[u8]) -> Polynomial {
    let mut out = Polynomial::default();
    for (g, b) in poly.chunks_exact(5).enumerate() {
        let v = u64::from(b[0]) | u64::from(b[1]) << 8 | u64::from(b[2]) << 16 | u64::from(b[3]) << 24 | u64::from(b[4]) << 32;
        for c in 0..4 {
            out.0[4 * g + c] = Elem::new(((v >> (10 * c)) & 1023) as u32);
        }
    }
    out
}

/// z polynomial: e = gamma1 - z packed in 18 (gamma1 = 2^17) or 20 bits; returns (poly, max |z|).
#[inline]
fn unpack_z_poly(poly: &[u8], gamma1: u32) -> (Polynomial, u32) {
    let mut out = Polynomial::default();
    let mut maxabs = 0u32;
    let mut j = 0;
    let mut put = |e: u32, out: &mut Polynomial| {
        let (val, abs) = if e <= gamma1 { (gamma1 - e, gamma1 - e) } else { (Q - (e - gamma1), e - gamma1) };
        maxabs = maxabs.max(abs);
        out.0[j] = Elem::new(val);
        j += 1;
    };
    if gamma1 == 1 << 17 {
        for b in poly.chunks_exact(9) {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[..8]);
            let lo = u64::from_le_bytes(w);
            put((lo & 0x3ffff) as u32, &mut out);
            put(((lo >> 18) & 0x3ffff) as u32, &mut out);
            put(((lo >> 36) & 0x3ffff) as u32, &mut out);
            put((((lo >> 54) | u64::from(b[8]) << 10) & 0x3ffff) as u32, &mut out);
        }
    } else {
        for b in poly.chunks_exact(5) {
            let v = u64::from(b[0]) | u64::from(b[1]) << 8 | u64::from(b[2]) << 16 | u64::from(b[3]) << 24 | u64::from(b[4]) << 32;
            put((v & 0xfffff) as u32, &mut out);
            put(((v >> 20) & 0xfffff) as u32, &mut out);
        }
    }
    (out, maxabs)
}

/// hint: omega indices + k cut positions, with the FIPS 204 validity rules.
fn unpack_hint<P: MlDsaParams>(henc: &[u8]) -> Option<Hint<P>> {
    let omega = P::Omega::USIZE;
    let (idx, cuts) = henc.split_at(omega);
    let mut h = Hint::<P>::default();
    let mut start = 0usize;
    for (i, &end) in cuts.iter().enumerate() {
        let end = end as usize;
        if end < start || end > omega {
            return None;
        }
        let mut prev: i32 = -1;
        for &j in &idx[start..end] {
            if i32::from(j) <= prev {
                return None;
            }
            prev = i32::from(j);
            h.0[i][j as usize] = true;
        }
        start = end;
    }
    if idx[start..].iter().any(|&x| x != 0) {
        return None;
    }
    Some(h)
}

struct SigLayout {
    k: usize,
    l: usize,
    lambda: usize,
    zlen: usize,
}
fn layout<P: MlDsaParams>(pk: &[u8], sig: &[u8]) -> Option<SigLayout> {
    let (k, l, lambda, omega) = (P::K::USIZE, P::L::USIZE, P::Lambda::USIZE, P::Omega::USIZE);
    let zbits = if P::Gamma1::U32 == 1 << 17 { 18 } else { 20 };
    let zlen = 32 * zbits;
    if pk.len() != 32 + 320 * k || sig.len() != lambda + zlen * l + omega + k {
        return None;
    }
    Some(SigLayout { k, l, lambda, zlen })
}

/// v1: word-wise bit unpacking (5 bytes -> 4 t1 coefficients, 9 bytes -> 4 or 5 bytes -> 2 z
/// coefficients) and a direct hint-index scan, no generic bit cursor.
pub fn decode_fast<P: MlDsaParams>(pk: &[u8], sig: &[u8]) -> Option<Decoded<P>> {
    let SigLayout { k, l, lambda, zlen } = layout::<P>(pk, sig)?;
    let rho = B32::try_from(&pk[..32]).ok()?;
    let t1 = Vector::<P::K>::new(Array::from_fn(|i| unpack_t1_poly(&pk[32 + 320 * i..32 + 320 * (i + 1)])));
    let c_tilde = Array::<u8, P::Lambda>::try_from(&sig[..lambda]).ok()?;
    let mut maxabs = 0;
    let z = Vector::<P::L>::new(Array::from_fn(|i| {
        let (p, m) = unpack_z_poly(&sig[lambda + zlen * i..lambda + zlen * (i + 1)], P::Gamma1::U32);
        maxabs = maxabs.max(m);
        p
    }));
    let _ = k;
    let h = unpack_hint::<P>(&sig[lambda + zlen * l..])?;
    if maxabs >= P::GAMMA1_MINUS_BETA {
        return None;
    }
    Some(Decoded { rho, t1, c_tilde, z, h })
}

/// v5: the k + l polynomial unpackings of v1 spread over rayon (hint scan serial).
pub fn decode_rayon<P: MlDsaParams>(pk: &[u8], sig: &[u8], pool: &rayon::ThreadPool) -> Option<Decoded<P>> {
    let SigLayout { k, l, lambda, zlen } = layout::<P>(pk, sig)?;
    let rho = B32::try_from(&pk[..32]).ok()?;
    let c_tilde = Array::<u8, P::Lambda>::try_from(&sig[..lambda]).ok()?;
    let h = unpack_hint::<P>(&sig[lambda + zlen * l..])?;
    let polys: Vec<(Polynomial, u32)> = pool.install(|| {
        (0..k + l)
            .into_par_iter()
            .map(|i| {
                if i < k {
                    (unpack_t1_poly(&pk[32 + 320 * i..32 + 320 * (i + 1)]), 0)
                } else {
                    let i = i - k;
                    unpack_z_poly(&sig[lambda + zlen * i..lambda + zlen * (i + 1)], P::Gamma1::U32)
                }
            })
            .collect()
    });
    if polys[k..].iter().any(|(_, m)| *m >= P::GAMMA1_MINUS_BETA) {
        return None;
    }
    let t1 = Vector::<P::K>::new(Array::from_fn(|i| polys[i].0.clone()));
    let z = Vector::<P::L>::new(Array::from_fn(|i| polys[k + i].0.clone()));
    Some(Decoded { rho, t1, c_tilde, z, h })
}

// ------------------------------------------------------------------------------------------------
// mu
// ------------------------------------------------------------------------------------------------

pub fn tr_of(pk: &[u8]) -> B64 {
    H::default().absorb(pk).squeeze_new()
}

/// v0: tr = H(pk, 64); mu = H(tr || 0 || |ctx| || ctx || M, 64) with the crate's `H` / `MuBuilder`.
pub fn mu_v0(pk: &[u8], msg: &[u8], ctx: &[u8]) -> Option<B64> {
    if !ctx_ok(ctx) {
        return None;
    }
    let tr = tr_of(pk);
    Some(MuBuilder::new(&tr, ctx).message(&[msg]))
}

/// v1: tr cached per public key (only the mu absorb/squeeze is done).
pub fn mu_trcache(tr: &B64, msg: &[u8], ctx: &[u8]) -> Option<B64> {
    if !ctx_ok(ctx) {
        return None;
    }
    Some(MuBuilder::new(tr, ctx).message(&[msg]))
}

/// v2: the `sha3` crate's Shake256 used directly (finalize_xof_into, no sponge clone / reader object).
pub fn mu_direct(pk: &[u8], msg: &[u8], ctx: &[u8]) -> Option<B64> {
    use sha3::digest::{ExtendableOutput, Update};
    if !ctx_ok(ctx) {
        return None;
    }
    let mut tr = B64::default();
    let mut h = sha3::Shake256::default();
    h.update(pk);
    h.finalize_xof_into(&mut tr);
    let mut mu = B64::default();
    let mut h = sha3::Shake256::default();
    h.update(&tr);
    h.update(&[0, ctx.len() as u8]);
    h.update(ctx);
    h.update(msg);
    h.finalize_xof_into(&mut mu);
    Some(mu)
}

// ------------------------------------------------------------------------------------------------
// expandA
// ------------------------------------------------------------------------------------------------

pub fn expand_a_v0<P: MlDsaParams>(rho: &B32) -> NttMatrix<P::K, P::L> {
    expand_a::<P::K, P::L>(rho)
}

fn parse_coeffs(block: &[u8], out: &mut [u32; 256], n: &mut usize) {
    for ch in block.chunks_exact(3) {
        if *n == 256 {
            return;
        }
        let z = u32::from(ch[0]) | u32::from(ch[1]) << 8 | u32::from(ch[2] & 0x7f) << 16;
        if z < Q {
            out[*n] = z;
            *n += 1;
        }
    }
}

fn poly_from(c: &[u32; 256]) -> NttPolynomial {
    NttPolynomial::new(Array::from_fn(|i| Elem::new(c[i])))
}

/// v1: four matrix entries sampled at once with the 4-lane AVX2 Keccak (falls back to scalar lanes).
pub fn expand_a_x4<P: MlDsaParams>(rho: &B32) -> NttMatrix<P::K, P::L> {
    let (k, l) = (P::K::USIZE, P::L::USIZE);
    let total = k * l;
    let mut polys: Vec<[u32; 256]> = vec![[0u32; 256]; total];
    let mut idx = 0;
    while idx < total {
        let mut msgs = [[0u8; 34]; 4];
        for lane in 0..4 {
            let e = (idx + lane).min(total - 1);
            let (r, s) = (e / l, e % l);
            msgs[lane][..32].copy_from_slice(rho);
            msgs[lane][32] = s as u8;
            msgs[lane][33] = r as u8;
        }
        let refs: [&[u8]; 4] = [&msgs[0], &msgs[1], &msgs[2], &msgs[3]];
        let mut x4 = Shake128X4::new(&refs);
        let mut counts = [0usize; 4];
        let mut tmp = [[0u32; 256]; 4];
        let mut blocks = [[0u8; 168]; 4];
        while counts.iter().any(|&c| c < 256) {
            x4.squeeze_block(&mut blocks);
            for lane in 0..4 {
                parse_coeffs(&blocks[lane], &mut tmp[lane], &mut counts[lane]);
            }
        }
        for lane in 0..4 {
            if idx + lane < total {
                polys[idx + lane] = tmp[lane];
            }
        }
        idx += 4;
    }
    NttMatrix::new(Array::from_fn(|r| NttVector::new(Array::from_fn(|s| poly_from(&polys[r * l + s])))))
}

/// v2: rows of A sampled in parallel with rayon (the crate's `rej_ntt_poly` per entry).
pub fn expand_a_rayon<P: MlDsaParams>(rho: &B32, pool: &rayon::ThreadPool) -> NttMatrix<P::K, P::L> {
    let rows: Vec<NttVector<P::L>> = pool.install(|| {
        (0..P::K::USIZE)
            .into_par_iter()
            .map(|r| NttVector::new(Array::from_fn(|s| rej_ntt_poly(rho, r as u8, s as u8))))
            .collect()
    });
    NttMatrix::new(Array::from_fn(|r| rows[r].clone()))
}

/// v4: scalar raw SHAKE128 (keccak-f directly on a state) with the same streaming 3-byte parser.
pub fn expand_a_fastparse<P: MlDsaParams>(rho: &B32) -> NttMatrix<P::K, P::L> {
    let l = P::L::USIZE;
    NttMatrix::new(Array::from_fn(|r| {
        NttVector::new(Array::from_fn(|s| {
            let mut msg = [0u8; 34];
            msg[..32].copy_from_slice(rho);
            msg[32] = s as u8;
            msg[33] = r as u8;
            let _ = l;
            let mut x = Shake128Raw::new(&msg);
            let mut c = [0u32; 256];
            let mut n = 0;
            let mut block = [0u8; 168];
            while n < 256 {
                x.squeeze_block(&mut block);
                parse_coeffs(&block, &mut c, &mut n);
            }
            poly_from(&c)
        }))
    }))
}

// ------------------------------------------------------------------------------------------------
// w_approx
// ------------------------------------------------------------------------------------------------

pub fn t1_2d_hat<P: MlDsaParams>(t1: &Vector<P::K>) -> NttVector<P::K> {
    (Elem::new(1 << D) * t1).ntt()
}

/// v0: crate algebra (Barrett/u128 field ops): w' = NTT^-1(A^ o NTT(z) - NTT(c) o NTT(t1 * 2^d)).
pub fn w_approx_v0<P: MlDsaParams>(dec: &Decoded<P>, a_hat: &NttMatrix<P::K, P::L>) -> Vector<P::K> {
    let c = sample_in_ball(&dec.c_tilde, P::TAU);
    let z_hat = dec.z.ntt();
    let c_hat = c.ntt();
    let t1_hat = t1_2d_hat::<P>(&dec.t1);
    let az = a_hat * &z_hat;
    let ct = &c_hat * &t1_hat;
    (&az - &ct).ntt_inverse()
}

/// v2: NTT(t1 * 2^d) precomputed for the key (what a cached VerifyingKey holds).
pub fn w_approx_precomp<P: MlDsaParams>(dec: &Decoded<P>, a_hat: &NttMatrix<P::K, P::L>, t1_hat: &NttVector<P::K>) -> Vector<P::K> {
    let c = sample_in_ball(&dec.c_tilde, P::TAU);
    let z_hat = dec.z.ntt();
    let c_hat = c.ntt();
    let az = a_hat * &z_hat;
    let ct = &c_hat * t1_hat;
    (&az - &ct).ntt_inverse()
}

/// v3: rows of the result computed in parallel (each row: l products + accumulate + inverse NTT).
pub fn w_approx_rayon<P: MlDsaParams>(dec: &Decoded<P>, a_hat: &NttMatrix<P::K, P::L>, pool: &rayon::ThreadPool) -> Vector<P::K> {
    let c = sample_in_ball(&dec.c_tilde, P::TAU);
    let z_hat = dec.z.ntt();
    let c_hat = c.ntt();
    let t1_hat = t1_2d_hat::<P>(&dec.t1);
    let rows: Vec<Polynomial> = pool.install(|| {
        (0..P::K::USIZE)
            .into_par_iter()
            .map(|i| {
                let az = &a_hat.0[i] * &z_hat;
                let ct = &c_hat * &t1_hat.0[i];
                (&az - &ct).ntt_inverse()
            })
            .collect()
    });
    Vector::new(Array::from_fn(|i| rows[i].clone()))
}

/// v4: lazy reduction: the l products of a row are accumulated in u64 and reduced once per coefficient.
pub fn w_approx_lazy<P: MlDsaParams>(dec: &Decoded<P>, a_hat: &NttMatrix<P::K, P::L>) -> Vector<P::K> {
    let c = sample_in_ball(&dec.c_tilde, P::TAU);
    let z_hat = dec.z.ntt();
    let c_hat = c.ntt();
    let t1_hat = t1_2d_hat::<P>(&dec.t1);
    let q = u64::from(Q);
    Vector::new(Array::from_fn(|i| {
        let mut acc = [0u64; 256];
        for (a, z) in a_hat.0[i].0.iter().zip(z_hat.0.iter()) {
            for j in 0..256 {
                acc[j] += u64::from(a.0[j].0) * u64::from(z.0[j].0);
            }
        }
        let p = NttPolynomial::new(Array::from_fn(|j| {
            let ct = (u64::from(c_hat.0[j].0) * u64::from(t1_hat.0[i].0[j].0)) % q;
            Elem::new(((acc[j] % q + q - ct) % q) as u32)
        }));
        p.ntt_inverse()
    }))
}

// --- Montgomery NTT (reference-implementation style, i32 coefficients) ---

mod mont {
    use super::Q;
    pub const QI: i32 = Q as i32;
    pub const QINV: i32 = 58_728_449; // q^-1 mod 2^32
    pub const F: i64 = 41_978; // mont^2 / 256

    #[inline(always)]
    pub fn montgomery_reduce(a: i64) -> i32 {
        let t = (a as i32).wrapping_mul(QINV);
        ((a - i64::from(t) * i64::from(QI)) >> 32) as i32
    }
    #[inline(always)]
    pub fn reduce32(a: i32) -> i32 {
        let t = (a + (1 << 22)) >> 23;
        a - t * QI
    }
    #[inline(always)]
    pub fn caddq(a: i32) -> i32 {
        a + ((a >> 31) & QI)
    }

    pub static ZETAS: std::sync::LazyLock<[i32; 256]> = std::sync::LazyLock::new(|| {
        let q = u64::from(Q);
        let mont = (1u64 << 32) % q;
        let mut pow = [1u64; 256];
        for i in 1..256 {
            pow[i] = pow[i - 1] * 1753 % q;
        }
        let mut z = [0i32; 256];
        for i in 0..256 {
            let br = (i as u8).reverse_bits() as usize;
            let v = pow[br] * mont % q;
            z[i] = if v > q / 2 { v as i64 - q as i64 } else { v as i64 } as i32;
        }
        z
    });

    pub fn ntt(a: &mut [i32; 256]) {
        let zetas = &*ZETAS;
        let mut k = 0;
        let mut len = 128;
        while len > 0 {
            let mut start = 0;
            while start < 256 {
                k += 1;
                let zeta = i64::from(zetas[k]);
                for j in start..start + len {
                    let t = montgomery_reduce(zeta * i64::from(a[j + len]));
                    a[j + len] = a[j] - t;
                    a[j] += t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    pub fn invntt_tomont(a: &mut [i32; 256]) {
        let zetas = &*ZETAS;
        let mut k = 256;
        let mut len = 1;
        while len < 256 {
            let mut start = 0;
            while start < 256 {
                k -= 1;
                let zeta = -i64::from(zetas[k]);
                for j in start..start + len {
                    let t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = montgomery_reduce(zeta * i64::from(a[j + len]));
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        for x in a.iter_mut() {
            *x = montgomery_reduce(F * i64::from(*x));
        }
    }
}

fn poly_i32(p: &Polynomial) -> [i32; 256] {
    let mut a = [0i32; 256];
    for (i, c) in p.0.iter().enumerate() {
        a[i] = c.0 as i32;
    }
    a
}

/// v1: Montgomery arithmetic on i32 (pqcrystals reference layout): plain-domain NTTs, lazy i64
/// accumulation of the row products, one Montgomery reduction per coefficient, inverse NTT with the
/// 2^32-scaled constants, final caddq into [0, q).
pub fn w_approx_mont<P: MlDsaParams>(dec: &Decoded<P>, a_hat: &NttMatrix<P::K, P::L>) -> Vector<P::K> {
    use mont::*;
    let (k, l) = (P::K::USIZE, P::L::USIZE);
    let c = sample_in_ball(&dec.c_tilde, P::TAU);
    let mut c_hat = poly_i32(&c);
    ntt(&mut c_hat);
    let z_hat: Vec<[i32; 256]> = (0..l)
        .map(|s| {
            let mut z = poly_i32(&dec.z.0[s]);
            ntt(&mut z);
            z
        })
        .collect();
    let t1_hat: Vec<[i32; 256]> = (0..k)
        .map(|i| {
            let mut t = [0i32; 256];
            for j in 0..256 {
                t[j] = (dec.t1.0[i].0[j].0 << D) as i32;
            }
            ntt(&mut t);
            t
        })
        .collect();
    Vector::new(Array::from_fn(|i| {
        let mut w = [0i32; 256];
        for j in 0..256 {
            let mut acc: i64 = 0;
            for s in 0..l {
                acc += i64::from(a_hat.0[i].0[s].0[j].0 as i32) * i64::from(z_hat[s][j]);
            }
            let az = montgomery_reduce(acc);
            let ct = montgomery_reduce(i64::from(c_hat[j]) * i64::from(t1_hat[i][j]));
            w[j] = reduce32(az - ct);
        }
        invntt_tomont(&mut w);
        Polynomial::new(Array::from_fn(|j| Elem::new(caddq(reduce32(w[j])) as u32)))
    }))
}

// ------------------------------------------------------------------------------------------------
// hint_check
// ------------------------------------------------------------------------------------------------

/// v0: crate `use_hint`, `encode_w1`, `H`; compares c~' with c~ and re-checks the ||z|| bound.
pub fn hint_check_v0<P: MlDsaParams>(dec: &Decoded<P>, mu: &B64, w: &Vector<P::K>) -> HintOut {
    let zok = dec.z.infinity_norm() < P::GAMMA1_MINUS_BETA;
    let w1 = dec.h.use_hint(w);
    let w1enc = P::encode_w1(&w1);
    let cp: Array<u8, P::Lambda> = H::default().absorb(mu).absorb(&w1enc).squeeze_new();
    HintOut { w1enc: w1enc.to_vec(), ok: zok && cp == dec.c_tilde }
}

#[inline(always)]
fn decompose_nonct(r: u32, two_g2: u32) -> (u32, i32) {
    let g2 = two_g2 / 2;
    let mut r0 = (r % two_g2) as i32;
    if r0 > g2 as i32 {
        r0 -= two_g2 as i32;
    }
    if (r as i64 - r0 as i64) == i64::from(Q - 1) {
        (0, r0 - 1)
    } else {
        (((r as i64 - r0 as i64) / two_g2 as i64) as u32, r0)
    }
}

fn pack_w1<P: MlDsaParams>(w1: &[Vec<u32>]) -> Vec<u8> {
    let bits = w1_bits::<P>();
    let mut out = Vec::with_capacity(w1.len() * 32 * bits);
    for row in w1 {
        if bits == 4 {
            for p in row.chunks_exact(2) {
                out.push((p[0] | p[1] << 4) as u8);
            }
        } else {
            for p in row.chunks_exact(4) {
                let v = p[0] | p[1] << 6 | p[2] << 12 | p[3] << 18;
                out.extend_from_slice(&v.to_le_bytes()[..3]);
            }
        }
    }
    out
}

/// v1: non-constant-time Decompose/UseHint (native division by the public constant 2*gamma2,
/// branches instead of ct_select) and a direct 4/6-bit w1 packer; crate SHAKE.
pub fn hint_check_nonct<P: MlDsaParams>(dec: &Decoded<P>, mu: &B64, w: &Vector<P::K>) -> HintOut {
    let two_g2 = P::TwoGamma2::U32;
    let m = (Q - 1) / two_g2;
    let zok = dec.z.infinity_norm() < P::GAMMA1_MINUS_BETA;
    let w1: Vec<Vec<u32>> = (0..P::K::USIZE)
        .map(|i| {
            let hrow = &dec.h.0[i];
            (0..256)
                .map(|j| {
                    let (r1, r0) = decompose_nonct(w.0[i].0[j].0, two_g2);
                    if hrow[j] {
                        if r0 > 0 {
                            if r1 + 1 == m { 0 } else { r1 + 1 }
                        } else if r1 == 0 {
                            m - 1
                        } else {
                            r1 - 1
                        }
                    } else {
                        r1
                    }
                })
                .collect()
        })
        .collect();
    let w1enc = pack_w1::<P>(&w1);
    let cp: Array<u8, P::Lambda> = H::default().absorb(mu).absorb(&w1enc).squeeze_new();
    HintOut { ok: zok && cp == dec.c_tilde, w1enc }
}

/// v2: HighBits for every coefficient with a single division, the hint applied only at the <= omega
/// hinted positions (where r0 is recomputed), and the final SHAKE-256 run on the raw permutation.
pub fn hint_check_sparse<P: MlDsaParams>(dec: &Decoded<P>, mu: &B64, w: &Vector<P::K>) -> HintOut {
    let two_g2 = P::TwoGamma2::U32;
    let m = (Q - 1) / two_g2;
    let zok = dec.z.infinity_norm() < P::GAMMA1_MINUS_BETA;
    let mut w1: Vec<Vec<u32>> = Vec::with_capacity(P::K::USIZE);
    for i in 0..P::K::USIZE {
        let mut row: Vec<u32> = w.0[i].0.iter().map(|c| decompose_nonct(c.0, two_g2).0).collect();
        for j in 0..256 {
            if dec.h.0[i][j] {
                let (r1, r0) = decompose_nonct(w.0[i].0[j].0, two_g2);
                row[j] = if r0 > 0 {
                    if r1 + 1 == m { 0 } else { r1 + 1 }
                } else if r1 == 0 {
                    m - 1
                } else {
                    r1 - 1
                };
            }
        }
        w1.push(row);
    }
    let w1enc = pack_w1::<P>(&w1);
    let mut cp = vec![0u8; P::Lambda::USIZE];
    crate::fasthash::shake256_multi(&[mu, &w1enc], &mut cp);
    HintOut { ok: zok && cp.as_slice() == dec.c_tilde.as_slice(), w1enc }
}

// ------------------------------------------------------------------------------------------------
// end-to-end pipelines (used for `total`, `total_best` and `validate`)
// ------------------------------------------------------------------------------------------------

pub fn verify_total_v0<P: MlDsaParams>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Some(dec) = decode_v0::<P>(pk, sig) else { return false };
    let Some(mu) = mu_v0(pk, msg, ctx) else { return false };
    let a = expand_a_v0::<P>(&dec.rho);
    let w = w_approx_v0::<P>(&dec, &a);
    hint_check_v0::<P>(&dec, &mu, &w).ok
}

/// Composition of the fastest stateless alternatives: decode.v1 (fast unpack), mu.v2 (direct sha3),
/// expandA.v1 (x4 Keccak) or v4 when AVX2 is missing, w_approx.v1 (Montgomery), hint_check.v2 (sparse + raw SHAKE).
pub fn verify_total_best<P: MlDsaParams>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Some(dec) = decode_fast::<P>(pk, sig) else { return false };
    let Some(mu) = mu_direct(pk, msg, ctx) else { return false };
    let a = if crate::fasthash::x4_available() { expand_a_x4::<P>(&dec.rho) } else { expand_a_fastparse::<P>(&dec.rho) };
    let w = w_approx_mont::<P>(&dec, &a);
    hint_check_sparse::<P>(&dec, &mu, &w).ok
}

pub const TOTAL_BEST_DESC: &str = "decode.v1 fastunpack + mu.v2 direct-sha3 + expandA.v1 x4-keccak (v4 fastparse without AVX2) + w_approx.v1 montgomery + hint_check.v2 sparse-rawshake";
