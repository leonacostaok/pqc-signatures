//! `stages` subcommand: the verify stage split (section B of the Phase 2 contract) for both
//! families, variant tables and the memory op lists for the stage v0s / total pipelines.

use crate::schemes::Scheme;
use crate::stages_mldsa as ml;
use crate::stages_slhdsa as slh;
use crate::timing::{measure, stats};
use crate::{lib_version, runtime, sha256_hex, BUILD_TAG, LIB};
use hybrid_array::{typenum::Unsigned, Array};
use ml_dsa::param::MlDsaParams;
use serde::Serialize;
use slh_dsa::hashes::HashSuite;
use slh_dsa::ParameterSet;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

pub struct StageArgs {
    pub budget: Duration,
    pub stages: Option<Vec<String>>,
    pub variants: Option<Vec<String>>,
    pub msg: Vec<u8>,
    pub seed: Vec<u8>,
    pub pool: rayon::ThreadPool,
    pub threads: usize,
}

pub struct SVar {
    pub stage: &'static str,
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub tag: &'static str,
    /// implementation key (build-flag variants run the v0 implementation in their own binary)
    pub imp: &'static str,
}

macro_rules! sv {
    ($stage:literal, $id:literal, $name:literal, $tag:literal, $imp:literal, $desc:literal) => {
        SVar { stage: $stage, id: $id, name: $name, desc: $desc, tag: $tag, imp: $imp }
    };
}

pub const ML_VARS: &[SVar] = &[
    sv!("decode", "decode.v0", "crate", "base", "v0", "ml-dsa crate: pkDecode (split_vk + decode_t1) and sigDecode (decode_z, Hint::bit_unpack with FIPS validity rules, ||z|| bound)."),
    sv!("decode", "decode.v1", "fastunpack", "base", "fastunpack", "Word-wise unpacking: 5 bytes -> 4 t1 coefficients, 9/5 bytes -> 4/2 z coefficients via u64 windows, direct hint index scan; no generic bit cursor."),
    sv!("decode", "decode.v2", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("decode", "decode.v3", "lto", "lto", "v0", "v0 built with fat LTO + codegen-units=1 + panic=abort."),
    sv!("decode", "decode.v4", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("decode", "decode.v5", "rayon", "base", "rayon", "The k + l polynomial unpackings of v1 spread over a 4-thread rayon pool (hint scan serial)."),
    sv!("mu", "mu.v0", "crate", "base", "v0", "ml-dsa crate: tr = H(pk, 64) and mu = H(tr || 0 || |ctx| || ctx || M, 64) through its ShakeState/MuBuilder."),
    sv!("mu", "mu.v1", "trcache", "base", "trcache", "tr cached per public key (as a cached VerifyingKey holds it): only the mu SHAKE-256 is computed."),
    sv!("mu", "mu.v2", "directsha3", "base", "directsha3", "sha3 crate's Shake256 used directly with finalize_xof_into (no sponge clone, no XofReader object)."),
    sv!("mu", "mu.v3", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("mu", "mu.v4", "lto", "lto", "v0", "v0 built with fat LTO + codegen-units=1 + panic=abort."),
    sv!("mu", "mu.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("expandA", "expandA.v0", "crate", "base", "v0", "ml-dsa crate expand_a: k*l sequential SHAKE-128 rejection samplings (840-byte initial squeeze, 3 bytes at a time afterwards)."),
    sv!("expandA", "expandA.v1", "x4keccak", "base", "x4", "Four matrix entries sampled at once: 4-lane AVX2 Keccak-f[1600] (one __m256i per state word), same 3-byte stream parser; scalar lanes without AVX2."),
    sv!("expandA", "expandA.v2", "rayon", "base", "rayon", "Rows of A sampled in parallel on a 4-thread rayon pool (crate rej_ntt_poly per entry)."),
    sv!("expandA", "expandA.v3", "cachedA", "base", "cached", "A^ cached per public key (the crate's VerifyingKey keeps it): the stage is the clone of the cached matrix."),
    sv!("expandA", "expandA.v4", "fastparse", "base", "fastparse", "Scalar raw SHAKE-128 on the keccak permutation (no digest buffering/state cloning) with the streaming 3-byte parser."),
    sv!("expandA", "expandA.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("w_approx", "w_approx.v0", "crate", "base", "v0", "ml-dsa crate algebra: SampleInBall, NTT(z), NTT(c), NTT(t1*2^d), A^ o z^ - c^ o t1^, NTT^-1 (u128 Barrett products, ct ops)."),
    sv!("w_approx", "w_approx.v1", "montgomery", "base", "mont", "Reference-style i32 Montgomery arithmetic: lazy i64 accumulation of the l row products, one Montgomery reduction per coefficient, invntt with 2^32-scaled zetas, caddq."),
    sv!("w_approx", "w_approx.v2", "t1hat-precomp", "base", "precomp", "NTT(t1 * 2^d) precomputed for the key (as the crate's VerifyingKey does); crate algebra otherwise."),
    sv!("w_approx", "w_approx.v3", "rayon", "base", "rayon", "Rows of w' (l products + accumulate + inverse NTT each) computed in parallel on a 4-thread rayon pool."),
    sv!("w_approx", "w_approx.v4", "lazyacc", "base", "lazy", "Lazy reduction: the l products of a row accumulated in u64 and reduced once per coefficient; crate NTTs."),
    sv!("w_approx", "w_approx.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("hint_check", "hint_check.v0", "crate", "base", "v0", "ml-dsa crate: ||z|| bound, Hint::use_hint (ct_select, two modulo ops per coefficient), encode_w1, H(mu || w1Encode) compared with c~."),
    sv!("hint_check", "hint_check.v1", "nonct", "base", "nonct", "Non-constant-time Decompose/UseHint (native division by the public 2*gamma2, branches) with a direct 4/6-bit w1 packer; crate SHAKE."),
    sv!("hint_check", "hint_check.v2", "sparse-raw", "base", "sparse", "HighBits for all coefficients, hint applied only at the <= omega hinted positions, final SHAKE-256 on the raw keccak permutation."),
    sv!("hint_check", "hint_check.v3", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("hint_check", "hint_check.v4", "lto", "lto", "v0", "v0 built with fat LTO + codegen-units=1 + panic=abort."),
    sv!("hint_check", "hint_check.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
];

pub const SLH_VARS: &[SVar] = &[
    sv!("hmsg", "hmsg.v0", "crate", "base", "v0", "slh-dsa crate: Signature::try_from (full parse into nested arrays), P::h_msg (SHAKE256 or SHA-2 + MGF1), split_digest."),
    sv!("hmsg", "hmsg.v1", "zerocopy", "base", "zerocopy", "Zero-copy signature parse (length check + borrowed R/FORS/HT slices) with the crate's h_msg."),
    sv!("hmsg", "hmsg.v2", "rawhmsg", "base", "raw", "Zero-copy parse + raw H_msg: SHAKE256 on the permutation, or SHA-2 on the compression function with the MGF1 seed prefix hashed once as a midstate."),
    sv!("hmsg", "hmsg.v3", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("hmsg", "hmsg.v4", "lto", "lto", "v0", "v0 built with fat LTO + codegen-units=1 + panic=abort."),
    sv!("hmsg", "hmsg.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("fors", "fors.v0", "crate", "base", "v0", "slh-dsa crate fors_pk_from_sig (digest-API F/H with a cloned pk_seed-prefixed hasher per call, T over the k roots)."),
    sv!("fors", "fors.v1", "rawhash", "base", "raw", "Fused raw hashing: one padded block on keccak-f / SHA-2 compress with a PK.seed midstate, borrowed signature slices, byte-array addresses."),
    sv!("fors", "fors.v2", "x4keccak", "base", "x4", "The k FORS trees walked four at a time in lockstep on the 4-lane AVX2 Keccak (SHA2 sets: scalar raw path)."),
    sv!("fors", "fors.v3", "rayon", "base", "rayon", "The k trees in parallel on a 4-thread rayon pool (crate hash functions)."),
    sv!("fors", "fors.v4", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("fors", "fors.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("ht_wots", "ht_wots.v0", "crate", "base", "v0", "slh-dsa crate wots_pk_from_sig for each of the d layers (base_2b digits, chain of F calls, T over the len chain ends)."),
    sv!("ht_wots", "ht_wots.v1", "rawhash", "base", "raw", "Fused raw hashing (single-block keccak-f / SHA-256 midstate per F), borrowed slices, byte-array addresses."),
    sv!("ht_wots", "ht_wots.v2", "x4keccak", "base", "x4", "All d*len chains flattened and advanced four at a time in lockstep on the 4-lane Keccak; finished lanes hash a dummy (SHA2 sets: scalar raw path)."),
    sv!("ht_wots", "ht_wots.v3", "rayon", "base", "rayon", "The d layers in parallel on a 4-thread rayon pool (crate wots_pk_from_sig)."),
    sv!("ht_wots", "ht_wots.v4", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("ht_wots", "ht_wots.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
    sv!("ht_auth", "ht_auth.v0", "crate", "base", "v0", "The auth-path loop of the crate's xmss_pk_from_sig for each layer (crate H with its HashTree address) + compare with PK.root."),
    sv!("ht_auth", "ht_auth.v1", "rawhash", "base", "raw", "Fused raw hashing on borrowed auth-path slices (single-block keccak-f / SHA-512 or SHA-256 midstate per H)."),
    sv!("ht_auth", "ht_auth.v2", "x4keccak", "base", "x4", "The d layers' auth paths climbed four at a time in lockstep on the 4-lane Keccak (SHA2 sets: scalar raw path)."),
    sv!("ht_auth", "ht_auth.v3", "rayon", "base", "rayon", "The d layers in parallel on a 4-thread rayon pool (crate H)."),
    sv!("ht_auth", "ht_auth.v4", "native", "native", "v0", "v0 built with -C target-cpu=native."),
    sv!("ht_auth", "ht_auth.v5", "pgo", "pgo-verify", "v0", "v0 built with native + fat LTO + PGO (verify-trained profile)."),
];

#[derive(Serialize)]
struct StageLine<'a> {
    lib: &'a str,
    lib_version: String,
    lang: &'a str,
    runtime: String,
    family: &'a str,
    stage: &'a str,
    variant: &'a str,
    variant_name: &'a str,
    variant_desc: &'a str,
    param: &'a str,
    iterations: u64,
    wall_ns_median: u64,
    wall_ns_mean: u64,
    wall_ns_p95: u64,
    wall_ns_min: u64,
    cpu_ns_per_op: u64,
    cpu_util: f64,
    ops_per_sec: f64,
    threads: usize,
    output_sha256: String,
    #[serde(rename = "match")]
    matched: bool,
}

fn selected<'a>(vars: &'a [SVar], a: &StageArgs, stage: &str) -> Vec<&'a SVar> {
    vars.iter()
        .filter(|v| v.stage == stage)
        .filter(|v| v.tag == BUILD_TAG || (BUILD_TAG == "pgo-gen" && v.tag.starts_with("pgo-")))
        .filter(|v| a.stages.as_ref().is_none_or(|s| s.iter().any(|x| x == v.stage)))
        .filter(|v| a.variants.as_ref().is_none_or(|s| s.iter().any(|x| x == v.id)))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn emit(out: &mut dyn Write, family: &str, param: &str, v: &SVar, iterations: u64, samples: &mut [u64], wall_total: u64, cpu_total: u64, threads: usize, sha: String, matched: bool) {
    let (median, mean, p95, min) = stats(samples);
    let line = StageLine {
        lib: LIB,
        lib_version: lib_version(),
        lang: "rust",
        runtime: runtime(),
        family,
        stage: v.stage,
        variant: v.id,
        variant_name: v.name,
        variant_desc: v.desc,
        param,
        iterations,
        wall_ns_median: median,
        wall_ns_mean: mean,
        wall_ns_p95: p95,
        wall_ns_min: min,
        cpu_ns_per_op: cpu_total / iterations.max(1),
        cpu_util: cpu_total as f64 / wall_total.max(1) as f64,
        ops_per_sec: iterations as f64 / (wall_total as f64 / 1e9),
        threads,
        output_sha256: sha,
        matched,
    };
    writeln!(out, "{}", serde_json::to_string(&line).unwrap()).expect("write");
    eprintln!("{:16} {:22} median={:>10} ns  ops/s={:>10.1} thr={} match={}", v.id, param, median, line.ops_per_sec, threads, matched);
}

/// Generic per-stage driver: `make(imp)` builds the closure of an implementation (None = not
/// applicable); the v0 output is the reference for `match`.
fn run_stage<'c, T: PartialEq>(
    out: &mut dyn Write,
    family: &str,
    param: &str,
    vars: &[SVar],
    a: &StageArgs,
    stage: &str,
    make: &dyn Fn(&str) -> Option<Box<dyn Fn() -> T + Sync + 'c>>,
    canon: &dyn Fn(&T) -> Vec<u8>,
) {
    let sel = selected(vars, a, stage);
    if sel.is_empty() {
        return;
    }
    let v0 = make("v0").expect("v0")();
    for v in sel {
        let Some(op) = make(v.imp) else { continue };
        let threads = if v.imp == "rayon" { a.threads } else { 1 };
        let mut m = measure(&*op, a.budget, 1);
        let matched = m.out == v0;
        let sha = sha256_hex(&canon(&m.out));
        emit(out, family, param, v, m.iterations, &mut m.samples, m.wall_total, m.cpu_total, threads, sha, matched);
    }
}

fn run_totals(out: &mut dyn Write, family: &str, param: &str, a: &StageArgs, pk: &[u8], msg: &[u8], sig: &[u8], tampered: &[u8], v0: &(dyn Fn(&[u8], &[u8], &[u8], &[u8]) -> bool + Sync), best: &(dyn Fn(&[u8], &[u8], &[u8], &[u8]) -> bool + Sync), best_desc: &'static str) {
    if BUILD_TAG != "base" {
        return;
    }
    let want = |s: &str| a.stages.as_ref().is_none_or(|x| x.iter().any(|y| y == s));
    let total = SVar { stage: "total", id: "total.v0", name: "v0-stages", desc: "End-to-end verify chained from the v0 stage implementations.", tag: "base", imp: "v0" };
    let tbest = SVar { stage: "total_best", id: "total_best.v0", name: "best-stages", desc: best_desc, tag: "base", imp: "best" };
    for (v, f) in [(&total, v0), (&tbest, best)] {
        if !want(v.stage) || a.variants.as_ref().is_some_and(|x| !x.iter().any(|y| y == v.id)) {
            continue;
        }
        let op = || f(pk, msg, &[], sig);
        let mut m = measure(&op, a.budget, 1);
        let ok = m.out && !f(pk, msg, &[], tampered);
        emit(out, family, param, v, m.iterations, &mut m.samples, m.wall_total, m.cpu_total, 1, if ok { "true".into() } else { "false".into() }, ok);
    }
}

// ------------------------------------------------------------------------------------------------
// ML-DSA
// ------------------------------------------------------------------------------------------------

pub struct MlCtx<P: MlDsaParams> {
    pub pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub msg: Vec<u8>,
    pub dec: ml::Decoded<P>,
    pub tr: ml_dsa::B64,
    pub mu: ml_dsa::B64,
    pub a_hat: ml_dsa::algebra::NttMatrix<P::K, P::L>,
    pub t1_hat: ml_dsa::algebra::NttVector<P::K>,
    pub w: ml_dsa::algebra::Vector<P::K>,
}

pub fn ml_ctx<P: MlDsaParams>(s: &dyn Scheme, msg: &[u8], seed: &[u8]) -> MlCtx<P> {
    let (pk, sk) = s.keygen(seed);
    let sig = s.sign(&sk, msg);
    let dec = ml::decode_v0::<P>(&pk, &sig).expect("reference signature decodes");
    let tr = ml::tr_of(&pk);
    let mu = ml::mu_v0(&pk, msg, &[]).expect("mu");
    let a_hat = ml::expand_a_v0::<P>(&dec.rho);
    let t1_hat = ml::t1_2d_hat::<P>(&dec.t1);
    let w = ml::w_approx_v0::<P>(&dec, &a_hat);
    MlCtx { pk, sig, msg: msg.to_vec(), dec, tr, mu, a_hat, t1_hat, w }
}

pub fn run_ml<P: MlDsaParams + Send + Sync + 'static>(param: &str, a: &StageArgs, out: &mut dyn Write) {
    let s = crate::schemes::MlDsa::<P>(Box::leak(param.to_string().into_boxed_str()), core::marker::PhantomData);
    let c = ml_ctx::<P>(&s, &a.msg, &a.seed);
    run_ml_inner::<P>(&c, param, a, out)
}

fn run_ml_inner<'c, P: MlDsaParams + Send + Sync + 'static>(c: &'c MlCtx<P>, param: &str, a: &'c StageArgs, out: &mut dyn Write) {
    let mut tampered = c.sig.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    let fam = "ml-dsa";
    let pool = &a.pool;

    run_stage::<Vec<u8>>(out, fam, param, ML_VARS, a, "decode", &|imp: &str| -> Option<Box<dyn Fn() -> Vec<u8> + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| ml::decode_v0::<P>(&c.pk, &c.sig).map(|d| d.full_bytes()).unwrap_or_default()),
            "fastunpack" => Box::new(|| ml::decode_fast::<P>(&c.pk, &c.sig).map(|d| d.full_bytes()).unwrap_or_default()),
            "rayon" => Box::new(move || ml::decode_rayon::<P>(&c.pk, &c.sig, pool).map(|d| d.full_bytes()).unwrap_or_default()),
            _ => return None,
        })
    }, &|full| full[..c.dec.c_tilde.len()].to_vec());

    run_stage::<ml_dsa::B64>(out, fam, param, ML_VARS, a, "mu", &|imp: &str| -> Option<Box<dyn Fn() -> ml_dsa::B64 + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| ml::mu_v0(&c.pk, &c.msg, &[]).unwrap()),
            "trcache" => Box::new(|| ml::mu_trcache(&c.tr, &c.msg, &[]).unwrap()),
            "directsha3" => Box::new(|| ml::mu_direct(&c.pk, &c.msg, &[]).unwrap()),
            _ => return None,
        })
    }, &|mu| mu.to_vec());

    run_stage::<ml_dsa::algebra::NttMatrix<P::K, P::L>>(out, fam, param, ML_VARS, a, "expandA", &|imp: &str| -> Option<Box<dyn Fn() -> ml_dsa::algebra::NttMatrix<P::K, P::L> + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| ml::expand_a_v0::<P>(&c.dec.rho)),
            "x4" => Box::new(|| ml::expand_a_x4::<P>(&c.dec.rho)),
            "rayon" => Box::new(move || ml::expand_a_rayon::<P>(&c.dec.rho, pool)),
            "cached" => Box::new(|| c.a_hat.clone()),
            "fastparse" => Box::new(|| ml::expand_a_fastparse::<P>(&c.dec.rho)),
            _ => return None,
        })
    }, &|m| ml::canon_matrix::<P>(m));

    run_stage::<ml_dsa::algebra::Vector<P::K>>(out, fam, param, ML_VARS, a, "w_approx", &|imp: &str| -> Option<Box<dyn Fn() -> ml_dsa::algebra::Vector<P::K> + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| ml::w_approx_v0::<P>(&c.dec, &c.a_hat)),
            "mont" => Box::new(|| ml::w_approx_mont::<P>(&c.dec, &c.a_hat)),
            "precomp" => Box::new(|| ml::w_approx_precomp::<P>(&c.dec, &c.a_hat, &c.t1_hat)),
            "rayon" => Box::new(move || ml::w_approx_rayon::<P>(&c.dec, &c.a_hat, pool)),
            "lazy" => Box::new(|| ml::w_approx_lazy::<P>(&c.dec, &c.a_hat)),
            _ => return None,
        })
    }, &|w| ml::canon_vector(w));

    run_stage::<ml::HintOut>(out, fam, param, ML_VARS, a, "hint_check", &|imp: &str| -> Option<Box<dyn Fn() -> ml::HintOut + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| ml::hint_check_v0::<P>(&c.dec, &c.mu, &c.w)),
            "nonct" => Box::new(|| ml::hint_check_nonct::<P>(&c.dec, &c.mu, &c.w)),
            "sparse" => Box::new(|| ml::hint_check_sparse::<P>(&c.dec, &c.mu, &c.w)),
            _ => return None,
        })
    }, &|h| h.w1enc.clone());

    run_totals(out, fam, param, a, &c.pk, &c.msg, &c.sig, &tampered, &ml::verify_total_v0::<P>, &ml::verify_total_best::<P>, ml::TOTAL_BEST_DESC);
}

pub type MemOp = (String, String, Box<dyn Fn() -> bool + Send + Sync>);

pub fn ml_memory_ops<P: MlDsaParams + Send + Sync + 'static>(s: &dyn Scheme, msg: &[u8], seed: &[u8]) -> Vec<MemOp> {
    let c = Arc::new(ml_ctx::<P>(s, msg, seed));
    let mut v: Vec<MemOp> = vec![];
    let cc = c.clone();
    v.push(("decode".into(), "decode.v0".into(), Box::new(move || ml::decode_v0::<P>(&cc.pk, &cc.sig).is_some_and(|d| d.full_bytes() == cc.dec.full_bytes()))));
    let cc = c.clone();
    v.push(("mu".into(), "mu.v0".into(), Box::new(move || ml::mu_v0(&cc.pk, &cc.msg, &[]).is_some_and(|m| m == cc.mu))));
    let cc = c.clone();
    v.push(("expandA".into(), "expandA.v0".into(), Box::new(move || ml::expand_a_v0::<P>(&cc.dec.rho) == cc.a_hat)));
    let cc = c.clone();
    v.push(("w_approx".into(), "w_approx.v0".into(), Box::new(move || ml::w_approx_v0::<P>(&cc.dec, &cc.a_hat) == cc.w)));
    let cc = c.clone();
    v.push(("hint_check".into(), "hint_check.v0".into(), Box::new(move || ml::hint_check_v0::<P>(&cc.dec, &cc.mu, &cc.w).ok)));
    let cc = c.clone();
    v.push(("total".into(), "total.v0".into(), Box::new(move || ml::verify_total_v0::<P>(&cc.pk, &cc.msg, &[], &cc.sig))));
    let cc = c.clone();
    v.push(("total_best".into(), "total_best.v0".into(), Box::new(move || ml::verify_total_best::<P>(&cc.pk, &cc.msg, &[], &cc.sig))));
    v
}

// ------------------------------------------------------------------------------------------------
// SLH-DSA
// ------------------------------------------------------------------------------------------------

pub struct SlhCtx<P: ParameterSet> {
    pub pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub msg: Vec<u8>,
    pub vk: slh_dsa::VerifyingKey<P>,
    pub hs: P,
    pub rs: slh::RawSuite,
    pub parsed: Signature<P>,
    pub h: slh::HmsgOut,
    pub fors_pk: Vec<u8>,
    /// layer messages: fors_pk, then root of layer j-1
    pub msgs: Vec<Array<u8, P::N>>,
    pub msgs_b: Vec<Vec<u8>>,
    pub wots_pks: Vec<Array<u8, P::N>>,
    pub wots_pks_b: Vec<Vec<u8>>,
    pub auth: slh::AuthOut,
}
use slh_dsa::Signature;

pub fn slh_ctx<P: ParameterSet>(s: &dyn Scheme, msg: &[u8], seed: &[u8]) -> SlhCtx<P> {
    let (pk, sk) = s.keygen(seed);
    let sig = s.sign(&sk, msg);
    let vk = slh_dsa::VerifyingKey::<P>::try_from(pk.as_slice()).expect("pk");
    let hs = P::new_from_pk_seed(&vk.pk_seed);
    let rs = slh::RawSuite::new(slh::fam::<P>(), &vk.pk_seed.0);
    let (h, parsed) = slh::hmsg_v0::<P>(&vk, msg, &[], &sig).expect("hmsg");
    let fors_pk = slh::fors_v0::<P>(&hs, &parsed, &h);
    let li = slh::layer_indices::<P>(h.idx_tree, h.idx_leaf);
    let mut msgs = vec![slh::to_arr::<P>(&fors_pk)];
    let mut wots_pks = vec![];
    for j in 0..P::D::USIZE {
        let adrs = slh::wots_adrs::<P>(j as u32, li[j].0, li[j].1);
        let wpk = hs.wots_pk_from_sig(&parsed.ht_sig.0[j].sig, &msgs[j], &adrs);
        wots_pks.push(wpk.clone());
        let one = slh::ht_auth_v0::<P>(&hs, &parsed, &h, &pad_to_d::<P>(&wots_pks), &vk.pk_root);
        if j + 1 < P::D::USIZE {
            msgs.push(slh::to_arr::<P>(&one.roots[j]));
        }
    }
    let auth = slh::ht_auth_v0::<P>(&hs, &parsed, &h, &wots_pks, &vk.pk_root);
    assert!(auth.ok, "reference verification must succeed");
    let msgs_b = msgs.iter().map(|m| m.to_vec()).collect();
    let wots_pks_b = wots_pks.iter().map(|m| m.to_vec()).collect();
    SlhCtx { pk, sig, msg: msg.to_vec(), vk, hs, rs, parsed, h, fors_pk, msgs, msgs_b, wots_pks, wots_pks_b, auth }
}

/// ht_auth_v0 needs d WOTS pks; while building the context layer by layer, pad with zeros.
fn pad_to_d<P: ParameterSet>(w: &[Array<u8, P::N>]) -> Vec<Array<u8, P::N>> {
    let mut v = w.to_vec();
    while v.len() < P::D::USIZE {
        v.push(Array::default());
    }
    v
}

pub fn run_slh<P: ParameterSet + Send + Sync + 'static>(param: &str, a: &StageArgs, out: &mut dyn Write) {
    let s = crate::schemes::SlhDsa::<P>(Box::leak(param.to_string().into_boxed_str()), core::marker::PhantomData);
    let c = slh_ctx::<P>(&s, &a.msg, &a.seed);
    run_slh_inner::<P>(&c, param, a, out)
}

fn run_slh_inner<'c, P: ParameterSet + Send + Sync + 'static>(c: &'c SlhCtx<P>, param: &str, a: &'c StageArgs, out: &mut dyn Write) {
    let mut tampered = c.sig.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;
    let fam = "slh-dsa";
    let pool = &a.pool;
    let view: slh::SigView<'c> = slh::sig_view::<P>(&c.sig).expect("sig view");

    run_stage::<slh::HmsgOut>(out, fam, param, SLH_VARS, a, "hmsg", &|imp: &str| -> Option<Box<dyn Fn() -> slh::HmsgOut + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| slh::hmsg_v0::<P>(&c.vk, &c.msg, &[], &c.sig).unwrap().0),
            "zerocopy" => Box::new(|| slh::hmsg_zerocopy::<P>(&c.vk, &c.msg, &[], &c.sig).unwrap()),
            "raw" => Box::new(|| slh::hmsg_raw::<P>(&c.pk, &c.msg, &[], &c.sig).unwrap()),
            _ => return None,
        })
    }, &|h| h.digest.clone());

    run_stage::<Vec<u8>>(out, fam, param, SLH_VARS, a, "fors", &|imp: &str| -> Option<Box<dyn Fn() -> Vec<u8> + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| slh::fors_v0::<P>(&c.hs, &c.parsed, &c.h)),
            "raw" => Box::new(|| slh::fors_raw::<P>(&c.rs, view.fors, &c.h)),
            "x4" => Box::new(|| slh::fors_x4::<P>(&c.rs, view.fors, &c.h)),
            "rayon" => Box::new(move || slh::fors_rayon::<P>(&c.hs, &c.parsed, &c.h, pool)),
            _ => return None,
        })
    }, &|r| r.clone());

    run_stage::<Vec<Vec<u8>>>(out, fam, param, SLH_VARS, a, "ht_wots", &|imp: &str| -> Option<Box<dyn Fn() -> Vec<Vec<u8>> + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| slh::ht_wots_v0::<P>(&c.hs, &c.parsed, &c.h, &c.msgs)),
            "raw" => Box::new(|| slh::ht_wots_raw::<P>(&c.rs, view.ht, &c.h, &c.msgs_b)),
            "x4" => Box::new(|| slh::ht_wots_x4::<P>(&c.rs, view.ht, &c.h, &c.msgs_b)),
            "rayon" => Box::new(move || slh::ht_wots_rayon::<P>(&c.hs, &c.parsed, &c.h, &c.msgs, pool)),
            _ => return None,
        })
    }, &|v| v.concat());

    run_stage::<slh::AuthOut>(out, fam, param, SLH_VARS, a, "ht_auth", &|imp: &str| -> Option<Box<dyn Fn() -> slh::AuthOut + Sync + 'c>> {
        Some(match imp {
            "v0" => Box::new(|| slh::ht_auth_v0::<P>(&c.hs, &c.parsed, &c.h, &c.wots_pks, &c.vk.pk_root)),
            "raw" => Box::new(|| slh::ht_auth_raw::<P>(&c.rs, view.ht, &c.h, &c.wots_pks_b, &c.vk.pk_root)),
            "x4" => Box::new(|| slh::ht_auth_x4::<P>(&c.rs, view.ht, &c.h, &c.wots_pks_b, &c.vk.pk_root)),
            "rayon" => Box::new(move || slh::ht_auth_rayon::<P>(&c.hs, &c.parsed, &c.h, &c.wots_pks, &c.vk.pk_root, pool)),
            _ => return None,
        })
    }, &|r| r.roots.concat());

    run_totals(out, fam, param, a, &c.pk, &c.msg, &c.sig, &tampered, &slh::verify_total_v0::<P>, &slh::verify_total_best::<P>, slh::TOTAL_BEST_DESC);
}

pub fn slh_memory_ops<P: ParameterSet + Send + Sync + 'static>(s: &dyn Scheme, msg: &[u8], seed: &[u8]) -> Vec<MemOp> {
    let c = Arc::new(slh_ctx::<P>(s, msg, seed));
    let mut v: Vec<MemOp> = vec![];
    let cc = c.clone();
    v.push(("hmsg".into(), "hmsg.v0".into(), Box::new(move || slh::hmsg_v0::<P>(&cc.vk, &cc.msg, &[], &cc.sig).is_some_and(|(h, _)| h == cc.h))));
    let cc = c.clone();
    v.push(("fors".into(), "fors.v0".into(), Box::new(move || slh::fors_v0::<P>(&cc.hs, &cc.parsed, &cc.h) == cc.fors_pk)));
    let cc = c.clone();
    v.push(("ht_wots".into(), "ht_wots.v0".into(), Box::new(move || slh::ht_wots_v0::<P>(&cc.hs, &cc.parsed, &cc.h, &cc.msgs) == cc.wots_pks_b)));
    let cc = c.clone();
    v.push(("ht_auth".into(), "ht_auth.v0".into(), Box::new(move || slh::ht_auth_v0::<P>(&cc.hs, &cc.parsed, &cc.h, &cc.wots_pks, &cc.vk.pk_root) == cc.auth)));
    let cc = c.clone();
    v.push(("total".into(), "total.v0".into(), Box::new(move || slh::verify_total_v0::<P>(&cc.pk, &cc.msg, &[], &cc.sig))));
    let cc = c.clone();
    v.push(("total_best".into(), "total_best.v0".into(), Box::new(move || slh::verify_total_best::<P>(&cc.pk, &cc.msg, &[], &cc.sig))));
    v
}
