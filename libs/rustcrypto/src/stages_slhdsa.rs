//! SLH-DSA verify split into the canonical stages (FIPS 205 Alg. 20 + external wrapper), built on the
//! vendored `slh-dsa` crate's internals (v0) plus alternatives implemented here.

use crate::fasthash::{self, RawSha256, RawSha512, SHA256_IV, SHA512_IV};
use hybrid_array::{typenum::Unsigned, Array};
use rayon::prelude::*;
use slh_dsa::address::{ForsTree, WotsHash};
use slh_dsa::fors::ForsParams;
use slh_dsa::hashes::HashSuite;
use slh_dsa::hypertree::HypertreeParams;
use slh_dsa::util::split_digest;
use slh_dsa::wots::WotsParams;
use slh_dsa::xmss::XmssParams;
use slh_dsa::{ParameterSet, PkSeed, Signature};

pub type Bytes = Vec<u8>;

// ------------------------------------------------------------------------------------------------
// parameters, addresses, families
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Fam {
    Shake,
    Sha2L1,  // n = 16: everything SHA-256
    Sha2L35, // n = 24/32: F/PRF SHA-256, H/T/Hmsg SHA-512
}

pub fn fam<P: ParameterSet>() -> Fam {
    if P::NAME.contains("SHAKE") {
        Fam::Shake
    } else if P::N::USIZE == 16 {
        Fam::Sha2L1
    } else {
        Fam::Sha2L35
    }
}

/// 32-byte ADRS: layer | tree (12 bytes, high word 0) | type | w5 | w6 | w7 (all big-endian).
#[inline]
pub fn adrs32(layer: u32, tree: u64, typ: u32, w5: u32, w6: u32, w7: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(&layer.to_be_bytes());
    a[8..16].copy_from_slice(&tree.to_be_bytes());
    a[16..20].copy_from_slice(&typ.to_be_bytes());
    a[20..24].copy_from_slice(&w5.to_be_bytes());
    a[24..28].copy_from_slice(&w6.to_be_bytes());
    a[28..32].copy_from_slice(&w7.to_be_bytes());
    a
}
#[inline]
pub fn adrs_compressed(a: &[u8; 32]) -> [u8; 22] {
    let mut c = [0u8; 22];
    c[0] = a[3];
    c[1..9].copy_from_slice(&a[8..16]);
    c[9] = a[19];
    c[10..22].copy_from_slice(&a[20..32]);
    c
}
pub const T_WOTS_HASH: u32 = 0;
pub const T_WOTS_PK: u32 = 1;
pub const T_TREE: u32 = 2;
pub const T_FORS_TREE: u32 = 3;
pub const T_FORS_ROOTS: u32 = 4;

/// Per-layer indices of the hypertree walk (idx_tree, idx_leaf) for layers 0..d.
pub fn layer_indices<P: ParameterSet>(mut idx_tree: u64, mut idx_leaf: u32) -> Vec<(u64, u32)> {
    let hp = P::HPrime::U32;
    let mut v = Vec::with_capacity(P::D::USIZE);
    v.push((idx_tree, idx_leaf));
    for _ in 1..P::D::U32 {
        idx_leaf = (idx_tree & ((1u64 << hp) - 1)) as u32;
        idx_tree >>= hp;
        v.push((idx_tree, idx_leaf));
    }
    v
}

/// WOTS+ digits (base 16, 2n message nibbles + 3 checksum nibbles).
pub fn wots_digits(m: &[u8]) -> Vec<u8> {
    let mut d: Vec<u8> = Vec::with_capacity(2 * m.len() + 3);
    for &b in m {
        d.push(b >> 4);
        d.push(b & 15);
    }
    let csum: u16 = d.iter().map(|&x| 15 - u16::from(x)).sum::<u16>() << 4;
    let cb = csum.to_be_bytes();
    d.push(cb[0] >> 4);
    d.push(cb[0] & 15);
    d.push(cb[1] >> 4);
    d
}

// ------------------------------------------------------------------------------------------------
// raw hash suite (fused single-block hashing on the compression function / permutation)
// ------------------------------------------------------------------------------------------------

pub struct RawSuite {
    pub fam: Fam,
    pub n: usize,
    pub pkseed: Vec<u8>,
    mid256: [u32; 8],
    mid512: [u64; 8],
}

impl RawSuite {
    pub fn new(fam: Fam, pkseed: &[u8]) -> Self {
        let n = pkseed.len();
        let mut mid256 = SHA256_IV;
        let mut mid512 = SHA512_IV;
        if fam != Fam::Shake {
            let mut b = [0u8; 64];
            b[..n].copy_from_slice(pkseed);
            sha2::block_api::compress256(&mut mid256, &[b]);
            let mut b = [0u8; 128];
            b[..n].copy_from_slice(pkseed);
            sha2::block_api::compress512(&mut mid512, &[b]);
        }
        Self { fam, n, pkseed: pkseed.to_vec(), mid256, mid512 }
    }
    #[inline]
    fn sha256_tail(&self, adrs: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
        let mut h = RawSha256::from_midstate(self.mid256, 64);
        h.update(&adrs_compressed(adrs));
        for p in parts {
            h.update(p);
        }
        h.finalize_into(out);
    }
    #[inline]
    fn sha512_tail(&self, adrs: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
        let mut h = RawSha512::from_midstate(self.mid512, 128);
        h.update(&adrs_compressed(adrs));
        for p in parts {
            h.update(p);
        }
        h.finalize_into(out);
    }
    #[inline]
    fn shake_tail(&self, adrs: &[u8; 32], parts: &[&[u8]], out: &mut [u8]) {
        let total: usize = self.n + 32 + parts.iter().map(|p| p.len()).sum::<usize>();
        if total < 136 {
            let mut buf = [0u8; 136];
            buf[..self.n].copy_from_slice(&self.pkseed);
            buf[self.n..self.n + 32].copy_from_slice(adrs);
            let mut o = self.n + 32;
            for p in parts {
                buf[o..o + p.len()].copy_from_slice(p);
                o += p.len();
            }
            fasthash::shake256_1block(&buf[..total], out);
        } else {
            let mut all: Vec<&[u8]> = vec![&self.pkseed, adrs];
            all.extend_from_slice(parts);
            fasthash::shake256_multi(&all, out);
        }
    }
    /// F (and PRF): SHA-256 for both SHA2 levels.
    #[inline]
    pub fn f(&self, adrs: &[u8; 32], m: &[u8], out: &mut [u8]) {
        match self.fam {
            Fam::Shake => self.shake_tail(adrs, &[m], out),
            _ => self.sha256_tail(adrs, &[m], out),
        }
    }
    /// H: SHA-256 (L1) or SHA-512 (L3/L5).
    #[inline]
    pub fn h(&self, adrs: &[u8; 32], m1: &[u8], m2: &[u8], out: &mut [u8]) {
        match self.fam {
            Fam::Shake => self.shake_tail(adrs, &[m1, m2], out),
            Fam::Sha2L1 => self.sha256_tail(adrs, &[m1, m2], out),
            Fam::Sha2L35 => self.sha512_tail(adrs, &[m1, m2], out),
        }
    }
    /// T_l over a flat concatenation of l n-byte strings.
    #[inline]
    pub fn t(&self, adrs: &[u8; 32], ms: &[u8], out: &mut [u8]) {
        match self.fam {
            Fam::Shake => self.shake_tail(adrs, &[ms], out),
            Fam::Sha2L1 => self.sha256_tail(adrs, &[ms], out),
            Fam::Sha2L35 => self.sha512_tail(adrs, &[ms], out),
        }
    }
    /// Four F calls at once (SHAKE: 4-lane Keccak; SHA2: four scalar calls).
    #[inline]
    pub fn f_x4(&self, adrs: &[[u8; 32]; 4], m: &[&[u8]; 4], out: &mut [[u8; 64]; 4]) {
        if self.fam == Fam::Shake {
            let n = self.n;
            let mut bufs = [[0u8; 136]; 4];
            for l in 0..4 {
                bufs[l][..n].copy_from_slice(&self.pkseed);
                bufs[l][n..n + 32].copy_from_slice(&adrs[l]);
                bufs[l][n + 32..n + 32 + n].copy_from_slice(m[l]);
            }
            let total = 2 * n + 32;
            let msgs: [&[u8]; 4] = [&bufs[0][..total], &bufs[1][..total], &bufs[2][..total], &bufs[3][..total]];
            fasthash::shake256_1block_x4(&msgs, n, out);
        } else {
            for l in 0..4 {
                let (a, b) = out.split_at_mut(l);
                let _ = a;
                self.f(&adrs[l], m[l], &mut b[0][..self.n]);
            }
        }
    }
    #[inline]
    pub fn h_x4(&self, adrs: &[[u8; 32]; 4], m1: &[&[u8]; 4], m2: &[&[u8]; 4], out: &mut [[u8; 64]; 4]) {
        if self.fam == Fam::Shake {
            let n = self.n;
            let mut bufs = [[0u8; 136]; 4];
            for l in 0..4 {
                bufs[l][..n].copy_from_slice(&self.pkseed);
                bufs[l][n..n + 32].copy_from_slice(&adrs[l]);
                bufs[l][n + 32..2 * n + 32].copy_from_slice(m1[l]);
                bufs[l][2 * n + 32..3 * n + 32].copy_from_slice(m2[l]);
            }
            let total = 3 * n + 32;
            let msgs: [&[u8]; 4] = [&bufs[0][..total], &bufs[1][..total], &bufs[2][..total], &bufs[3][..total]];
            fasthash::shake256_1block_x4(&msgs, n, out);
        } else {
            for l in 0..4 {
                let (_, b) = out.split_at_mut(l);
                self.h(&adrs[l], m1[l], m2[l], &mut b[0][..self.n]);
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// stage: hmsg
// ------------------------------------------------------------------------------------------------

#[derive(Clone, PartialEq)]
pub struct HmsgOut {
    pub digest: Bytes,
    pub md: Bytes,
    pub idx_tree: u64,
    pub idx_leaf: u32,
}

/// v0: crate signature parse (`Signature::try_from`) + `P::h_msg` + `split_digest`.
pub fn hmsg_v0<P: ParameterSet>(vk: &slh_dsa::VerifyingKey<P>, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<(HmsgOut, Signature<P>)> {
    if ctx.len() > 255 {
        return None;
    }
    let parsed = Signature::<P>::try_from(sig).ok()?;
    let hdr = [0u8, ctx.len() as u8];
    let m: [&[&[u8]]; 2] = [&[&hdr[..1], &hdr[1..], ctx], &[msg]];
    let digest = P::h_msg(&parsed.randomizer, &vk.pk_seed, &vk.pk_root, &m);
    let (md, idx_tree, idx_leaf) = split_digest::<P>(&digest);
    Some((HmsgOut { digest: digest.to_vec(), md: md.to_vec(), idx_tree, idx_leaf }, parsed))
}

/// Borrowed view of a signature (no copies): R, FORS part, HT part.
pub struct SigView<'a> {
    pub r: &'a [u8],
    pub fors: &'a [u8],
    pub ht: &'a [u8],
}
pub fn sig_view<'a, P: ParameterSet>(sig: &'a [u8]) -> Option<SigView<'a>> {
    let n = P::N::USIZE;
    let fors_len = P::K::USIZE * (P::A::USIZE + 1) * n;
    let ht_len = P::D::USIZE * (P::WotsSigLen::USIZE + P::HPrime::USIZE) * n;
    if sig.len() != n + fors_len + ht_len {
        return None;
    }
    Some(SigView { r: &sig[..n], fors: &sig[n..n + fors_len], ht: &sig[n + fors_len..] })
}

fn split_digest_raw<P: ParameterSet>(digest: &[u8]) -> (Bytes, u64, u32) {
    let d = Array::<u8, P::M>::try_from(digest).expect("digest length");
    let (md, t, l) = split_digest::<P>(&d);
    (md.to_vec(), t, l)
}

/// v1: zero-copy parse (length check + borrowed slices) with the crate's H_msg.
pub fn hmsg_zerocopy<P: ParameterSet>(vk: &slh_dsa::VerifyingKey<P>, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<HmsgOut> {
    if ctx.len() > 255 {
        return None;
    }
    let v = sig_view::<P>(sig)?;
    let r = Array::<u8, P::N>::try_from(v.r).ok()?;
    let hdr = [0u8, ctx.len() as u8];
    let m: [&[&[u8]]; 2] = [&[&hdr[..1], &hdr[1..], ctx], &[msg]];
    let digest = P::h_msg(&r, &vk.pk_seed, &vk.pk_root, &m);
    let (md, idx_tree, idx_leaf) = split_digest::<P>(&digest);
    Some(HmsgOut { digest: digest.to_vec(), md: md.to_vec(), idx_tree, idx_leaf })
}

/// v2: zero-copy parse + raw H_msg: SHAKE256 on the permutation, or SHA-2 digest + MGF1 with the
/// (R || PK.seed || digest) prefix hashed once as a midstate and only the counter block redone.
pub fn hmsg_raw<P: ParameterSet>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<HmsgOut> {
    if ctx.len() > 255 {
        return None;
    }
    let n = P::N::USIZE;
    let m = P::M::USIZE;
    if pk.len() != 2 * n {
        return None;
    }
    let v = sig_view::<P>(sig)?;
    let (pkseed, pkroot) = (&pk[..n], &pk[n..]);
    let hdr = [0u8, ctx.len() as u8];
    let mut digest = vec![0u8; m];
    match fam::<P>() {
        Fam::Shake => fasthash::shake256_multi(&[v.r, pkseed, pkroot, &hdr, ctx, msg], &mut digest),
        Fam::Sha2L1 => {
            let mut h = RawSha256::new();
            for p in [v.r, pkseed, pkroot, &hdr, ctx, msg] {
                h.update(p);
            }
            let mut inner = [0u8; 32];
            h.finalize_into(&mut inner);
            let mut seed = RawSha256::new();
            seed.update(v.r);
            seed.update(pkseed);
            seed.update(&inner);
            for (counter, chunk) in digest.chunks_mut(32).enumerate() {
                let mut hh = seed.clone();
                hh.update(&(counter as u32).to_be_bytes());
                hh.finalize_into(chunk);
            }
        }
        Fam::Sha2L35 => {
            let mut h = RawSha512::new();
            for p in [v.r, pkseed, pkroot, &hdr, ctx, msg] {
                h.update(p);
            }
            let mut inner = [0u8; 64];
            h.finalize_into(&mut inner);
            let mut seed = RawSha512::new();
            seed.update(v.r);
            seed.update(pkseed);
            seed.update(&inner);
            for (counter, chunk) in digest.chunks_mut(64).enumerate() {
                let mut hh = seed.clone();
                hh.update(&(counter as u32).to_be_bytes());
                hh.finalize_into(chunk);
            }
        }
    }
    let (md, idx_tree, idx_leaf) = split_digest_raw::<P>(&digest);
    Some(HmsgOut { digest, md, idx_tree, idx_leaf })
}

// ------------------------------------------------------------------------------------------------
// stage: fors
// ------------------------------------------------------------------------------------------------

/// v0: crate `fors_pk_from_sig`.
pub fn fors_v0<P: ParameterSet>(hs: &P, parsed: &Signature<P>, h: &HmsgOut) -> Bytes {
    let md = Array::<u8, P::MD>::try_from(h.md.as_slice()).expect("md");
    let adrs = ForsTree::new(h.idx_tree, h.idx_leaf);
    hs.fors_pk_from_sig(&parsed.fors_sig, &md, &adrs).to_vec()
}

/// FORS leaf indices from md (k values of a bits).
pub fn fors_indices<P: ParameterSet>(md: &[u8]) -> Vec<u32> {
    slh_dsa::util::base_2b::<P::K, P::A>(md).iter().map(|&x| u32::from(x)).collect()
}

/// v1: raw fused hashing, borrowed signature slices, no address structs.
pub fn fors_raw<P: ParameterSet>(rs: &RawSuite, fors: &[u8], h: &HmsgOut) -> Bytes {
    let (n, k, a) = (P::N::USIZE, P::K::USIZE, P::A::U32);
    let idx = fors_indices::<P>(&h.md);
    let mut roots = vec![0u8; k * n];
    let mut node = vec![0u8; n];
    let mut tmp = vec![0u8; n];
    for i in 0..k {
        let tree = &fors[i * (a as usize + 1) * n..];
        let sk = &tree[..n];
        let mut tree_index = ((i as u32) << a) + idx[i];
        let ad = adrs32(0, h.idx_tree, T_FORS_TREE, h.idx_leaf, 0, tree_index);
        rs.f(&ad, sk, &mut node);
        for j in 0..a {
            tree_index >>= 1;
            let ad = adrs32(0, h.idx_tree, T_FORS_TREE, h.idx_leaf, j + 1, tree_index);
            let auth = &tree[n * (1 + j as usize)..n * (2 + j as usize)];
            if (idx[i] >> j) & 1 == 0 {
                rs.h(&ad, &node, auth, &mut tmp);
            } else {
                rs.h(&ad, auth, &node, &mut tmp);
            }
            node.copy_from_slice(&tmp);
        }
        roots[i * n..(i + 1) * n].copy_from_slice(&node);
    }
    let mut out = vec![0u8; n];
    rs.t(&adrs32(0, h.idx_tree, T_FORS_ROOTS, h.idx_leaf, 0, 0), &roots, &mut out);
    out
}

/// v2: the k FORS trees walked four at a time in lockstep on the 4-lane Keccak (SHA2: scalar raw).
pub fn fors_x4<P: ParameterSet>(rs: &RawSuite, fors: &[u8], h: &HmsgOut) -> Bytes {
    let (n, k, a) = (P::N::USIZE, P::K::USIZE, P::A::U32);
    let idx = fors_indices::<P>(&h.md);
    let mut roots = vec![0u8; k * n];
    let mut i0 = 0;
    while i0 < k {
        let lanes: [usize; 4] = [i0.min(k - 1), (i0 + 1).min(k - 1), (i0 + 2).min(k - 1), (i0 + 3).min(k - 1)];
        let mut nodes = [[0u8; 64]; 4];
        let mut tidx = [0u32; 4];
        let mut ads = [[0u8; 32]; 4];
        let mut sks: [&[u8]; 4] = [&[]; 4];
        for l in 0..4 {
            let i = lanes[l];
            tidx[l] = ((i as u32) << a) + idx[i];
            ads[l] = adrs32(0, h.idx_tree, T_FORS_TREE, h.idx_leaf, 0, tidx[l]);
            sks[l] = &fors[i * (a as usize + 1) * n..i * (a as usize + 1) * n + n];
        }
        rs.f_x4(&ads, &sks, &mut nodes);
        for j in 0..a {
            let mut m1: [&[u8]; 4] = [&[]; 4];
            let mut m2: [&[u8]; 4] = [&[]; 4];
            let mut auths: [&[u8]; 4] = [&[]; 4];
            let cur = nodes;
            for l in 0..4 {
                let i = lanes[l];
                tidx[l] >>= 1;
                ads[l] = adrs32(0, h.idx_tree, T_FORS_TREE, h.idx_leaf, j + 1, tidx[l]);
                let base = i * (a as usize + 1) * n;
                auths[l] = &fors[base + n * (1 + j as usize)..base + n * (2 + j as usize)];
            }
            for l in 0..4 {
                if (idx[lanes[l]] >> j) & 1 == 0 {
                    m1[l] = &cur[l][..n];
                    m2[l] = auths[l];
                } else {
                    m1[l] = auths[l];
                    m2[l] = &cur[l][..n];
                }
            }
            rs.h_x4(&ads, &m1, &m2, &mut nodes);
        }
        for l in 0..4 {
            if i0 + l < k {
                roots[(i0 + l) * n..(i0 + l + 1) * n].copy_from_slice(&nodes[l][..n]);
            }
        }
        i0 += 4;
    }
    let mut out = vec![0u8; n];
    rs.t(&adrs32(0, h.idx_tree, T_FORS_ROOTS, h.idx_leaf, 0, 0), &roots, &mut out);
    out
}

/// v3: the k trees in parallel with rayon, crate hash functions.
pub fn fors_rayon<P: ParameterSet + Sync>(hs: &P, parsed: &Signature<P>, h: &HmsgOut, pool: &rayon::ThreadPool) -> Bytes {
    let (k, a) = (P::K::USIZE, P::A::U32);
    let idx = fors_indices::<P>(&h.md);
    let roots: Vec<Array<u8, P::N>> = pool.install(|| {
        (0..k)
            .into_par_iter()
            .map(|i| {
                let mut adrs = ForsTree::new(h.idx_tree, h.idx_leaf);
                let t = &parsed.fors_sig.0[i];
                adrs.tree_height.set(0);
                adrs.tree_index.set(((i as u32) << a) + idx[i]);
                let mut node = hs.f(&adrs, &t.sk);
                for j in 0..a {
                    adrs.tree_height.set(j + 1);
                    adrs.tree_index.set(adrs.tree_index.get() >> 1);
                    node = if (idx[i] >> j) & 1 == 0 { hs.h(&adrs, &node, &t.auth[j as usize]) } else { hs.h(&adrs, &t.auth[j as usize], &node) };
                }
                node
            })
            .collect()
    });
    let adrs = ForsTree::new(h.idx_tree, h.idx_leaf);
    let arr: Array<Array<u8, P::N>, P::K> = Array::from_fn(|i| roots[i].clone());
    hs.t(&adrs.fors_roots(), &arr).to_vec()
}

// ------------------------------------------------------------------------------------------------
// stage: ht_wots  (d WOTS+ pkFromSig, given each layer's message)
// ------------------------------------------------------------------------------------------------

pub fn wots_adrs<P: ParameterSet>(layer: u32, tree: u64, leaf: u32) -> WotsHash {
    let mut a = WotsHash::default();
    a.layer_adrs.set(layer);
    a.tree_adrs_low.set(tree);
    a.key_pair_adrs.set(leaf);
    a
}

/// v0: crate `wots_pk_from_sig` per layer. `msgs[j]` is layer j's message (FORS pk, then roots).
pub fn ht_wots_v0<P: ParameterSet>(hs: &P, parsed: &Signature<P>, h: &HmsgOut, msgs: &[Array<u8, P::N>]) -> Vec<Bytes> {
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    (0..P::D::USIZE)
        .map(|j| {
            let adrs = wots_adrs::<P>(j as u32, li[j].0, li[j].1);
            hs.wots_pk_from_sig(&parsed.ht_sig.0[j].sig, &msgs[j], &adrs).to_vec()
        })
        .collect()
}

fn xmss_sig_slice<'a, P: ParameterSet>(ht: &'a [u8], j: usize) -> &'a [u8] {
    let n = P::N::USIZE;
    let xs = (P::WotsSigLen::USIZE + P::HPrime::USIZE) * n;
    &ht[j * xs..(j + 1) * xs]
}

/// v1: raw fused hashing (midstate / single-block Keccak), borrowed slices.
pub fn ht_wots_raw<P: ParameterSet>(rs: &RawSuite, ht: &[u8], h: &HmsgOut, msgs: &[Bytes]) -> Vec<Bytes> {
    let (n, len) = (P::N::USIZE, P::WotsSigLen::USIZE);
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let mut out = Vec::with_capacity(P::D::USIZE);
    let mut tmp = vec![0u8; len * n];
    let mut cur = vec![0u8; n];
    let mut nxt = vec![0u8; n];
    for j in 0..P::D::USIZE {
        let (tree, leaf) = li[j];
        let xs = xmss_sig_slice::<P>(ht, j);
        let digits = wots_digits(&msgs[j]);
        for i in 0..len {
            cur.copy_from_slice(&xs[i * n..(i + 1) * n]);
            for step in digits[i]..15 {
                let ad = adrs32(j as u32, tree, T_WOTS_HASH, leaf, i as u32, u32::from(step));
                rs.f(&ad, &cur, &mut nxt);
                cur.copy_from_slice(&nxt);
            }
            tmp[i * n..(i + 1) * n].copy_from_slice(&cur);
        }
        let mut pk = vec![0u8; n];
        rs.t(&adrs32(j as u32, tree, T_WOTS_PK, leaf, 0, 0), &tmp, &mut pk);
        out.push(pk);
    }
    out
}

/// v2: all d*len chains flattened and advanced four at a time in lockstep on the 4-lane Keccak
/// (lanes whose chain is already finished keep hashing a dummy; SHA2 falls back to scalar raw).
pub fn ht_wots_x4<P: ParameterSet>(rs: &RawSuite, ht: &[u8], h: &HmsgOut, msgs: &[Bytes]) -> Vec<Bytes> {
    let (n, len, d) = (P::N::USIZE, P::WotsSigLen::USIZE, P::D::USIZE);
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let digits: Vec<Vec<u8>> = (0..d).map(|j| wots_digits(&msgs[j])).collect();
    let total = d * len;
    let mut chain_out = vec![0u8; total * n];
    let mut c0 = 0;
    while c0 < total {
        let lanes: [usize; 4] = [c0.min(total - 1), (c0 + 1).min(total - 1), (c0 + 2).min(total - 1), (c0 + 3).min(total - 1)];
        let mut vals = [[0u8; 64]; 4];
        let mut start = [0u8; 4];
        for l in 0..4 {
            let (j, i) = (lanes[l] / len, lanes[l] % len);
            let xs = xmss_sig_slice::<P>(ht, j);
            vals[l][..n].copy_from_slice(&xs[i * n..(i + 1) * n]);
            start[l] = digits[j][i];
        }
        for step in 0..15u8 {
            let mut ads = [[0u8; 32]; 4];
            let mut ms: [&[u8]; 4] = [&[]; 4];
            let cur = vals;
            for l in 0..4 {
                let (j, i) = (lanes[l] / len, lanes[l] % len);
                ads[l] = adrs32(j as u32, li[j].0, T_WOTS_HASH, li[j].1, i as u32, u32::from(step));
                ms[l] = &cur[l][..n];
            }
            let mut res = [[0u8; 64]; 4];
            rs.f_x4(&ads, &ms, &mut res);
            for l in 0..4 {
                if step >= start[l] {
                    vals[l] = res[l];
                }
            }
        }
        for l in 0..4 {
            if c0 + l < total {
                chain_out[(c0 + l) * n..(c0 + l + 1) * n].copy_from_slice(&vals[l][..n]);
            }
        }
        c0 += 4;
    }
    (0..d)
        .map(|j| {
            let mut pk = vec![0u8; n];
            rs.t(&adrs32(j as u32, li[j].0, T_WOTS_PK, li[j].1, 0, 0), &chain_out[j * len * n..(j + 1) * len * n], &mut pk);
            pk
        })
        .collect()
}

/// v3: the d layers in parallel with rayon (crate `wots_pk_from_sig`).
pub fn ht_wots_rayon<P: ParameterSet + Sync>(hs: &P, parsed: &Signature<P>, h: &HmsgOut, msgs: &[Array<u8, P::N>], pool: &rayon::ThreadPool) -> Vec<Bytes> {
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    pool.install(|| {
        (0..P::D::USIZE)
            .into_par_iter()
            .map(|j| {
                let adrs = wots_adrs::<P>(j as u32, li[j].0, li[j].1);
                hs.wots_pk_from_sig(&parsed.ht_sig.0[j].sig, &msgs[j], &adrs).to_vec()
            })
            .collect()
    })
}

// ------------------------------------------------------------------------------------------------
// stage: ht_auth  (d XMSS auth-path root computations + final compare)
// ------------------------------------------------------------------------------------------------

#[derive(Clone, PartialEq)]
pub struct AuthOut {
    pub roots: Vec<Bytes>,
    pub ok: bool,
}

/// v0: the auth-path loop of the crate's `xmss_pk_from_sig` (crate `h` with its HashTree address).
pub fn ht_auth_v0<P: ParameterSet>(hs: &P, parsed: &Signature<P>, h: &HmsgOut, wots_pks: &[Array<u8, P::N>], pk_root: &[u8]) -> AuthOut {
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let roots: Vec<Bytes> = (0..P::D::USIZE)
        .map(|j| {
            let adrs = wots_adrs::<P>(j as u32, li[j].0, li[j].1);
            let mut adrs = adrs.tree_adrs();
            let mut node = wots_pks[j].clone();
            let mut idx = li[j].1;
            let sig = &parsed.ht_sig.0[j];
            for k in 0..P::HPrime::U32 {
                adrs.tree_height.set(k + 1);
                let rem = idx & 1;
                idx >>= 1;
                adrs.tree_index.set(idx);
                node = if rem == 0 { hs.h(&adrs, &node, &sig.auth[k as usize]) } else { hs.h(&adrs, &sig.auth[k as usize], &node) };
            }
            node.to_vec()
        })
        .collect();
    let ok = roots.last().map(|r| r.as_slice() == pk_root).unwrap_or(false);
    AuthOut { roots, ok }
}

fn auth_slice<'a, P: ParameterSet>(ht: &'a [u8], j: usize) -> &'a [u8] {
    let n = P::N::USIZE;
    &xmss_sig_slice::<P>(ht, j)[P::WotsSigLen::USIZE * n..]
}

/// v1: raw fused hashing on borrowed auth-path slices.
pub fn ht_auth_raw<P: ParameterSet>(rs: &RawSuite, ht: &[u8], h: &HmsgOut, wots_pks: &[Bytes], pk_root: &[u8]) -> AuthOut {
    let n = P::N::USIZE;
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let mut tmp = vec![0u8; n];
    let roots: Vec<Bytes> = (0..P::D::USIZE)
        .map(|j| {
            let auth = auth_slice::<P>(ht, j);
            let mut node = wots_pks[j].clone();
            let mut idx = li[j].1;
            for k in 0..P::HPrime::U32 {
                let rem = idx & 1;
                idx >>= 1;
                let ad = adrs32(j as u32, li[j].0, T_TREE, 0, k + 1, idx);
                let a = &auth[k as usize * n..(k as usize + 1) * n];
                if rem == 0 {
                    rs.h(&ad, &node, a, &mut tmp);
                } else {
                    rs.h(&ad, a, &node, &mut tmp);
                }
                node.copy_from_slice(&tmp);
            }
            node
        })
        .collect();
    let ok = roots.last().map(|r| r.as_slice() == pk_root).unwrap_or(false);
    AuthOut { roots, ok }
}

/// v2: the d layers' auth paths climbed four at a time in lockstep on the 4-lane Keccak.
pub fn ht_auth_x4<P: ParameterSet>(rs: &RawSuite, ht: &[u8], h: &HmsgOut, wots_pks: &[Bytes], pk_root: &[u8]) -> AuthOut {
    let (n, d) = (P::N::USIZE, P::D::USIZE);
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let mut roots = vec![vec![0u8; n]; d];
    let mut j0 = 0;
    while j0 < d {
        let lanes: [usize; 4] = [j0.min(d - 1), (j0 + 1).min(d - 1), (j0 + 2).min(d - 1), (j0 + 3).min(d - 1)];
        let mut nodes = [[0u8; 64]; 4];
        let mut idx = [0u32; 4];
        for l in 0..4 {
            nodes[l][..n].copy_from_slice(&wots_pks[lanes[l]]);
            idx[l] = li[lanes[l]].1;
        }
        for k in 0..P::HPrime::U32 {
            let mut ads = [[0u8; 32]; 4];
            let mut m1: [&[u8]; 4] = [&[]; 4];
            let mut m2: [&[u8]; 4] = [&[]; 4];
            let cur = nodes;
            let mut rems = [0u32; 4];
            for l in 0..4 {
                rems[l] = idx[l] & 1;
                idx[l] >>= 1;
                ads[l] = adrs32(lanes[l] as u32, li[lanes[l]].0, T_TREE, 0, k + 1, idx[l]);
            }
            for l in 0..4 {
                let a = &auth_slice::<P>(ht, lanes[l])[k as usize * n..(k as usize + 1) * n];
                if rems[l] == 0 {
                    m1[l] = &cur[l][..n];
                    m2[l] = a;
                } else {
                    m1[l] = a;
                    m2[l] = &cur[l][..n];
                }
            }
            rs.h_x4(&ads, &m1, &m2, &mut nodes);
        }
        for l in 0..4 {
            if j0 + l < d {
                roots[j0 + l].copy_from_slice(&nodes[l][..n]);
            }
        }
        j0 += 4;
    }
    let ok = roots.last().map(|r| r.as_slice() == pk_root).unwrap_or(false);
    AuthOut { roots, ok }
}

/// v3: layers in parallel with rayon (crate `h`).
pub fn ht_auth_rayon<P: ParameterSet + Sync>(hs: &P, parsed: &Signature<P>, h: &HmsgOut, wots_pks: &[Array<u8, P::N>], pk_root: &[u8], pool: &rayon::ThreadPool) -> AuthOut {
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let roots: Vec<Bytes> = pool.install(|| {
        (0..P::D::USIZE)
            .into_par_iter()
            .map(|j| {
                let adrs = wots_adrs::<P>(j as u32, li[j].0, li[j].1);
                let mut adrs = adrs.tree_adrs();
                let mut node = wots_pks[j].clone();
                let mut idx = li[j].1;
                let sig = &parsed.ht_sig.0[j];
                for k in 0..P::HPrime::U32 {
                    adrs.tree_height.set(k + 1);
                    let rem = idx & 1;
                    idx >>= 1;
                    adrs.tree_index.set(idx);
                    node = if rem == 0 { hs.h(&adrs, &node, &sig.auth[k as usize]) } else { hs.h(&adrs, &sig.auth[k as usize], &node) };
                }
                node.to_vec()
            })
            .collect()
    });
    let ok = roots.last().map(|r| r.as_slice() == pk_root).unwrap_or(false);
    AuthOut { roots, ok }
}

// ------------------------------------------------------------------------------------------------
// end-to-end pipelines
// ------------------------------------------------------------------------------------------------

pub fn to_arr<P: ParameterSet>(b: &[u8]) -> Array<u8, P::N> {
    Array::<u8, P::N>::try_from(b).expect("n bytes")
}

/// v0 stages chained: the layered walk feeds layer j's root into layer j+1's WOTS message, exactly
/// like the crate's `ht_verify` (the stage split only separates the WOTS and auth-path halves).
pub fn verify_total_v0<P: ParameterSet>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = slh_dsa::VerifyingKey::<P>::try_from(pk) else { return false };
    let hs = P::new_from_pk_seed(&vk.pk_seed);
    let Some((h, parsed)) = hmsg_v0::<P>(&vk, msg, ctx, sig) else { return false };
    let fors_pk = fors_v0::<P>(&hs, &parsed, &h);
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let mut m = to_arr::<P>(&fors_pk);
    for j in 0..P::D::USIZE {
        let adrs = wots_adrs::<P>(j as u32, li[j].0, li[j].1);
        let wpk = hs.wots_pk_from_sig(&parsed.ht_sig.0[j].sig, &m, &adrs);
        let a = ht_auth_v0_layer::<P>(&hs, &parsed, &li, j, &wpk);
        m = a;
    }
    m.as_slice() == vk.pk_root.as_slice()
}

fn ht_auth_v0_layer<P: ParameterSet>(hs: &P, parsed: &Signature<P>, li: &[(u64, u32)], j: usize, wpk: &Array<u8, P::N>) -> Array<u8, P::N> {
    let adrs = wots_adrs::<P>(j as u32, li[j].0, li[j].1);
    let mut adrs = adrs.tree_adrs();
    let mut node = wpk.clone();
    let mut idx = li[j].1;
    let sig = &parsed.ht_sig.0[j];
    for k in 0..P::HPrime::U32 {
        adrs.tree_height.set(k + 1);
        let rem = idx & 1;
        idx >>= 1;
        adrs.tree_index.set(idx);
        node = if rem == 0 { hs.h(&adrs, &node, &sig.auth[k as usize]) } else { hs.h(&adrs, &sig.auth[k as usize], &node) };
    }
    node
}

/// Fastest stateless composition: hmsg.v2 (raw) + fors.v2 (x4) + per layer ht_wots.v2 (x4 chains) and
/// ht_auth.v1 (raw; a single layer has nothing to batch across). SHA2 sets use the scalar raw paths.
pub fn verify_total_best<P: ParameterSet>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let n = P::N::USIZE;
    if pk.len() != 2 * n {
        return false;
    }
    let rs = RawSuite::new(fam::<P>(), &pk[..n]);
    let Some(h) = hmsg_raw::<P>(pk, msg, ctx, sig) else { return false };
    let Some(v) = sig_view::<P>(sig) else { return false };
    let fors_pk = fors_x4::<P>(&rs, v.fors, &h);
    let li = layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let mut m = fors_pk;
    for j in 0..P::D::USIZE {
        let wpk = wots_layer_x4::<P>(&rs, v.ht, &li, j, &m);
        let auth = auth_slice::<P>(v.ht, j);
        let mut node = wpk;
        let mut tmp = vec![0u8; n];
        let mut idx = li[j].1;
        for k in 0..P::HPrime::U32 {
            let rem = idx & 1;
            idx >>= 1;
            let ad = adrs32(j as u32, li[j].0, T_TREE, 0, k + 1, idx);
            let a = &auth[k as usize * n..(k as usize + 1) * n];
            if rem == 0 {
                rs.h(&ad, &node, a, &mut tmp);
            } else {
                rs.h(&ad, a, &node, &mut tmp);
            }
            node.copy_from_slice(&tmp);
        }
        m = node;
    }
    m.as_slice() == &pk[n..]
}

/// One layer's WOTS+ pkFromSig with chains advanced four at a time.
fn wots_layer_x4<P: ParameterSet>(rs: &RawSuite, ht: &[u8], li: &[(u64, u32)], j: usize, msg: &[u8]) -> Bytes {
    let (n, len) = (P::N::USIZE, P::WotsSigLen::USIZE);
    let xs = xmss_sig_slice::<P>(ht, j);
    let digits = wots_digits(msg);
    let mut chain_out = vec![0u8; len * n];
    let mut c0 = 0;
    while c0 < len {
        let lanes: [usize; 4] = [c0.min(len - 1), (c0 + 1).min(len - 1), (c0 + 2).min(len - 1), (c0 + 3).min(len - 1)];
        let mut vals = [[0u8; 64]; 4];
        for l in 0..4 {
            vals[l][..n].copy_from_slice(&xs[lanes[l] * n..(lanes[l] + 1) * n]);
        }
        for step in 0..15u8 {
            let mut ads = [[0u8; 32]; 4];
            let mut ms: [&[u8]; 4] = [&[]; 4];
            let cur = vals;
            for l in 0..4 {
                ads[l] = adrs32(j as u32, li[j].0, T_WOTS_HASH, li[j].1, lanes[l] as u32, u32::from(step));
                ms[l] = &cur[l][..n];
            }
            let mut res = [[0u8; 64]; 4];
            rs.f_x4(&ads, &ms, &mut res);
            for l in 0..4 {
                if step >= digits[lanes[l]] {
                    vals[l] = res[l];
                }
            }
        }
        for l in 0..4 {
            if c0 + l < len {
                chain_out[(c0 + l) * n..(c0 + l + 1) * n].copy_from_slice(&vals[l][..n]);
            }
        }
        c0 += 4;
    }
    let mut pk = vec![0u8; n];
    rs.t(&adrs32(j as u32, li[j].0, T_WOTS_PK, li[j].1, 0, 0), &chain_out, &mut pk);
    pk
}

pub const TOTAL_BEST_DESC: &str = "hmsg.v2 raw-hmsg + fors.v2 x4-keccak + ht_wots.v2 x4-chains + ht_auth.v1 raw (SHA2 sets: scalar raw fused hashing)";
