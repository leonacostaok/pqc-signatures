//! pqcbench: benchmark/vector/crossverify harness for RustCrypto ml-dsa + slh-dsa.
//!
//! Subcommands (see libs/rustcrypto/run.sh and common/CONTRACT.md):
//!   vectors <out.json>
//!   crossverify <artifacts.json> <out.json>
//!   bench --out <file.jsonl> [--budget-ms N] [--params a,b] [--ops keygen,sign,verify] [--variants id,id]
//!
//! The same source is compiled several times with different build settings; each binary carries a
//! build tag (env PQC_BUILD_TAG at compile time) and `bench` only runs the variants that belong to
//! its tag, so run.sh simply invokes every binary with the same arguments.

#![allow(clippy::too_many_arguments)]

mod fasthash;
mod memory;
mod schemes;
mod stages;
mod stages_mldsa;
mod stages_slhdsa;
mod timing;
mod validate;

/// Counting global allocator (heap numbers for `memory`); wraps mimalloc in the mimalloc build.
pub mod heap {
    use std::alloc::{GlobalAlloc, Layout};
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
    pub static ENABLED: AtomicBool = AtomicBool::new(false);
    pub static TOTAL: AtomicU64 = AtomicU64::new(0);
    pub static LIVE: AtomicI64 = AtomicI64::new(0);
    pub static PEAK: AtomicI64 = AtomicI64::new(0);
    pub static BASE: AtomicI64 = AtomicI64::new(0);
    pub struct Counting;
    #[cfg(feature = "mimalloc")]
    type Inner = mimalloc::MiMalloc;
    #[cfg(not(feature = "mimalloc"))]
    type Inner = std::alloc::System;
    #[cfg(feature = "mimalloc")]
    const INNER: Inner = mimalloc::MiMalloc;
    #[cfg(not(feature = "mimalloc"))]
    const INNER: Inner = std::alloc::System;
    #[inline]
    fn note_alloc(n: usize) {
        if ENABLED.load(Relaxed) {
            TOTAL.fetch_add(n as u64, Relaxed);
            let live = LIVE.fetch_add(n as i64, Relaxed) + n as i64;
            PEAK.fetch_max(live, Relaxed);
        }
    }
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            note_alloc(l.size());
            INNER.alloc(l)
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            note_alloc(l.size());
            INNER.alloc_zeroed(l)
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            if ENABLED.load(Relaxed) {
                LIVE.fetch_sub(l.size() as i64, Relaxed);
            }
            INNER.dealloc(p, l)
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
            if ENABLED.load(Relaxed) {
                if new > l.size() {
                    TOTAL.fetch_add((new - l.size()) as u64, Relaxed);
                }
                let live = LIVE.fetch_add(new as i64 - l.size() as i64, Relaxed) + new as i64 - l.size() as i64;
                PEAK.fetch_max(live, Relaxed);
            }
            INNER.realloc(p, l, new)
        }
    }
    /// start counting: total = 0, peak = current live level
    pub fn start() {
        TOTAL.store(0, Relaxed);
        let live = LIVE.load(Relaxed);
        BASE.store(live, Relaxed);
        PEAK.store(live, Relaxed);
        ENABLED.store(true, Relaxed);
    }
    /// (bytes allocated since start, peak live bytes above the level at start)
    pub fn stop() -> (u64, u64) {
        ENABLED.store(false, Relaxed);
        (TOTAL.load(Relaxed), (PEAK.load(Relaxed) - BASE.load(Relaxed)).max(0) as u64)
    }
}
#[global_allocator]
static GLOBAL: heap::Counting = heap::Counting;

use schemes::{all_schemes, Scheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use timing::{cpu_time_ns, measure, stats};

pub const LIB: &str = "rustcrypto";
pub const BUILD_TAG: &str = env!("PQC_BUILD_TAG");

pub fn lib_version() -> String {
    format!("ml-dsa {} + slh-dsa {}", env!("ML_DSA_VERSION"), env!("SLH_DSA_VERSION"))
}
pub fn runtime() -> String {
    format!("{} (build={})", env!("RUSTC_VERSION_STR"), BUILD_TAG)
}

// ------------------------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------------------------

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}
pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn common_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("PQC_COMMON_DIR") {
        return d.into();
    }
    // libs/rustcrypto/target/<tag>/<profile>/pqcbench -> ../../../../../common
    let exe = std::env::current_exe().expect("exe");
    let mut p = exe.clone();
    for _ in 0..5 {
        p.pop();
    }
    p.join("common")
}

#[derive(Deserialize)]
struct VectorParam {
    name: String,
    seed_hex: String,
}
#[derive(Deserialize)]
struct Vectors {
    message_hex: String,
    params: Vec<VectorParam>,
}
#[derive(Deserialize, Clone)]
pub struct RefEntry {
    pub pk_sha256: String,
    pub sk_sha256: String,
    pub sig_sha256: String,
}

pub struct Common {
    pub msg: Vec<u8>,
    pub seeds: BTreeMap<String, Vec<u8>>,
    pub reference: BTreeMap<String, RefEntry>,
}

pub fn load_common() -> Common {
    let d = common_dir();
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(d.join("vectors.json")).expect("read vectors.json")).expect("parse vectors.json");
    let reference: BTreeMap<String, RefEntry> = serde_json::from_str(&std::fs::read_to_string(d.join("reference.json")).expect("read reference.json")).expect("parse reference.json");
    Common {
        msg: unhex(&v.message_hex),
        seeds: v.params.iter().map(|p| (p.name.clone(), unhex(&p.seed_hex))).collect(),
        reference,
    }
}


// ------------------------------------------------------------------------------------------------
// vectors / crossverify
// ------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct ArtifactEntry {
    param: String,
    pk_hex: String,
    sig_hex: String,
    sk_sha256: String,
    pk_sha256: String,
    sig_sha256: String,
    self_verify: bool,
}
#[derive(Serialize)]
struct Artifacts {
    lib: String,
    lib_version: String,
    entries: Vec<ArtifactEntry>,
}

fn cmd_vectors(out: &str) {
    let c = load_common();
    let mut entries = vec![];
    let mut mismatches = 0;
    for s in all_schemes() {
        let name = s.name();
        let Some(seed) = c.seeds.get(name) else { continue };
        let (pk, sk) = s.keygen(seed);
        let sig = s.sign(&sk, &c.msg);
        let ok = s.verify(&pk, &c.msg, &sig);
        let mut tampered = sig.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        let tamper_ok = !s.verify(&pk, &c.msg, &tampered);
        let e = ArtifactEntry {
            param: name.to_string(),
            pk_hex: hex(&pk),
            sig_hex: hex(&sig),
            sk_sha256: sha256_hex(&sk),
            pk_sha256: sha256_hex(&pk),
            sig_sha256: sha256_hex(&sig),
            self_verify: ok && tamper_ok,
        };
        let m = match c.reference.get(name) {
            Some(r) => r.pk_sha256 == e.pk_sha256 && r.sk_sha256 == e.sk_sha256 && r.sig_sha256 == e.sig_sha256,
            None => false,
        };
        if !m || !e.self_verify {
            mismatches += 1;
        }
        eprintln!("{name:22} pk={} sk={} sig={} self_verify={} tamper_rejected={} reference_match={}", pk.len(), sk.len(), sig.len(), ok, tamper_ok, m);
        entries.push(e);
    }
    let a = Artifacts { lib: LIB.into(), lib_version: lib_version(), entries };
    std::fs::write(out, serde_json::to_string_pretty(&a).unwrap() + "\n").expect("write artifacts");
    if mismatches > 0 {
        eprintln!("FAIL: {mismatches} parameter set(s) do not match common/reference.json");
        std::process::exit(1);
    }
    eprintln!("all {} parameter sets match common/reference.json", a.entries.len());
}

#[derive(Deserialize)]
struct InArtifactEntry {
    param: String,
    pk_hex: String,
    sig_hex: String,
}
#[derive(Deserialize)]
struct InArtifacts {
    lib: String,
    entries: Vec<InArtifactEntry>,
}
#[derive(Serialize)]
struct CrossResult {
    param: String,
    ok: bool,
    error: Option<String>,
    tamper_rejected: bool,
}
#[derive(Serialize)]
struct CrossOut {
    lib: String,
    source: String,
    results: Vec<CrossResult>,
}

fn cmd_crossverify(input: &str, out: &str) {
    let c = load_common();
    let a: InArtifacts = serde_json::from_str(&std::fs::read_to_string(input).expect("read artifacts")).expect("parse artifacts");
    let schemes = all_schemes();
    let mut results = vec![];
    for e in &a.entries {
        let Some(s) = schemes.iter().find(|s| s.name() == e.param) else { continue }; // unsupported: skip
        let pk = unhex(&e.pk_hex);
        let sig = unhex(&e.sig_hex);
        let ok = s.verify(&pk, &c.msg, &sig);
        let mut t = sig.clone();
        if !t.is_empty() {
            let mid = t.len() / 2;
            t[mid] ^= 0x01;
        }
        let tamper_rejected = !s.verify(&pk, &c.msg, &t);
        eprintln!("{:22} ok={ok} tamper_rejected={tamper_rejected}", e.param);
        results.push(CrossResult {
            param: e.param.clone(),
            ok,
            error: if ok { None } else { Some("verification failed".into()) },
            tamper_rejected,
        });
    }
    let o = CrossOut { lib: LIB.into(), source: a.lib, results };
    std::fs::write(out, serde_json::to_string_pretty(&o).unwrap() + "\n").expect("write");
    let bad = o.results.iter().filter(|r| !r.ok || !r.tamper_rejected).count();
    eprintln!("crossverify of {}: {} entries, {} failures", o.source, o.results.len(), bad);
    if bad > 0 {
        std::process::exit(1);
    }
}

// ------------------------------------------------------------------------------------------------
// bench
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Plain,
    KeyCache,
    Par,
}

pub struct Variant {
    pub id: &'static str,
    pub op: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub tag: &'static str,
    pub kind: Kind,
}

pub const V: &[Variant] = &[
    // keygen
    Variant { id: "keygen.v0", op: "keygen", name: "default", desc: "Plain cargo build --release; SigningKey::from_seed / slh_keygen_internal, then pk/sk FIPS encoding.", tag: "base", kind: Kind::Plain },
    Variant { id: "keygen.v1", op: "keygen", name: "native", desc: "Same code built with RUSTFLAGS=-C target-cpu=native (AVX2/AVX-512 autovectorisation of NTT, Keccak, SHA-2).", tag: "native", kind: Kind::Plain },
    Variant { id: "keygen.v2", op: "keygen", name: "lto", desc: "Fat LTO + codegen-units=1 + panic=abort (cross-crate inlining of hybrid-array/digest/keccak).", tag: "lto", kind: Kind::Plain },
    Variant { id: "keygen.v3", op: "keygen", name: "pgo", desc: "target-cpu=native + fat LTO + profile-guided optimisation trained on the keygen workload.", tag: "pgo-keygen", kind: Kind::Plain },
    Variant { id: "keygen.v4", op: "keygen", name: "mimalloc", desc: "Default build with the mimalloc global allocator (ml-dsa boxes expanded keys and Vec outputs).", tag: "mimalloc", kind: Kind::Plain },
    Variant { id: "keygen.v5", op: "keygen", name: "par", desc: "Batch of independent keygens spread over all cores with rayon (throughput over the batch).", tag: "base", kind: Kind::Par },
    // sign
    Variant { id: "sign.v0", op: "sign", name: "default", desc: "Plain release build; sk bytes decoded on every call (ExpandedSigningKey::from_expanded / SigningKey::try_from) then deterministic sign + encode.", tag: "base", kind: Kind::Plain },
    Variant { id: "sign.v1", op: "sign", name: "native", desc: "Same as v0 built with -C target-cpu=native.", tag: "native", kind: Kind::Plain },
    Variant { id: "sign.v2", op: "sign", name: "lto", desc: "Same as v0 built with fat LTO + codegen-units=1 + panic=abort.", tag: "lto", kind: Kind::Plain },
    Variant { id: "sign.v3", op: "sign", name: "pgo", desc: "target-cpu=native + fat LTO + PGO trained on the sign workload.", tag: "pgo-sign", kind: Kind::Plain },
    Variant { id: "sign.v4", op: "sign", name: "keycache", desc: "Key object decoded once and reused (ML-DSA: A_hat and NTT(s1,s2,t0) precomputed; only Sign_internal + sigEncode per call).", tag: "base", kind: Kind::KeyCache },
    Variant { id: "sign.v5", op: "sign", name: "par", desc: "Batch of independent signatures spread over all cores with rayon (throughput over the batch).", tag: "base", kind: Kind::Par },
    // verify
    Variant { id: "verify.v0", op: "verify", name: "default", desc: "Plain release build; pk bytes decoded on every call (VerifyingKey::decode / try_from) + sig decode + verify.", tag: "base", kind: Kind::Plain },
    Variant { id: "verify.v1", op: "verify", name: "native", desc: "Same as v0 built with -C target-cpu=native.", tag: "native", kind: Kind::Plain },
    Variant { id: "verify.v2", op: "verify", name: "lto", desc: "Same as v0 built with fat LTO + codegen-units=1 + panic=abort.", tag: "lto", kind: Kind::Plain },
    Variant { id: "verify.v3", op: "verify", name: "pgo", desc: "target-cpu=native + fat LTO + PGO trained on the verify workload.", tag: "pgo-verify", kind: Kind::Plain },
    Variant { id: "verify.v4", op: "verify", name: "keycache", desc: "VerifyingKey decoded once and reused (ML-DSA: A_hat, NTT(2^d*t1) and tr precomputed); only sig decode + Verify_internal per call.", tag: "base", kind: Kind::KeyCache },
    Variant { id: "verify.v5", op: "verify", name: "par", desc: "Batch of independent verifications spread over all cores with rayon (throughput over the batch).", tag: "base", kind: Kind::Par },
];

#[derive(Serialize)]
struct BenchLine {
    lib: &'static str,
    lib_version: String,
    lang: &'static str,
    runtime: String,
    variant: &'static str,
    variant_name: &'static str,
    variant_desc: &'static str,
    op: &'static str,
    param: String,
    iterations: u64,
    threads: usize,
    wall_ns_median: u64,
    wall_ns_mean: u64,
    wall_ns_p95: u64,
    wall_ns_min: u64,
    cpu_ns_per_op: u64,
    cpu_util: f64,
    ops_per_sec: f64,
    output_sha256: String,
    match_: bool,
}

struct BenchOpts {
    out: String,
    budget_ms: u64,
    params: Option<Vec<String>>,
    ops: Option<Vec<String>>,
    variants: Option<Vec<String>>,
}

fn cmd_bench(o: BenchOpts) {
    let c = load_common();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("rayon pool");
    let batch = (threads * 4) as u64;
    let budget = Duration::from_millis(o.budget_ms);
    let mut outf = std::fs::OpenOptions::new().create(true).append(true).open(&o.out).expect("open --out");

    let selected: Vec<&Variant> = V
        .iter()
        .filter(|v| v.tag == BUILD_TAG || (BUILD_TAG == "pgo-gen" && v.tag.starts_with("pgo-")))
        .filter(|v| o.ops.as_ref().is_none_or(|ops| ops.iter().any(|x| x == v.op)))
        .filter(|v| o.variants.as_ref().is_none_or(|vs| vs.iter().any(|x| x == v.id)))
        .collect();
    if selected.is_empty() {
        return;
    }

    for s in all_schemes() {
        let name = s.name();
        if o.params.as_ref().is_some_and(|ps| !ps.iter().any(|x| x == name)) {
            continue;
        }
        let Some(seed) = c.seeds.get(name) else { continue };
        let Some(r) = c.reference.get(name) else { continue };
        // inputs prepared outside the timed region, from the reference seed
        let (pk, sk) = s.keygen(seed);
        let sig = s.sign(&sk, &c.msg);
        let mut tampered = sig.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        let msg = c.msg.clone();
        let sref: &dyn Scheme = &*s;
        let (pk, sk, sig, msg, tampered) = (&pk, &sk, &sig, &msg, &tampered);

        for v in &selected {
            let nthreads = if v.kind == Kind::Par { threads } else { 1 };
            let b = if v.kind == Kind::Par { batch } else { 1 };
            // Build the closure for this (variant, param). Returns the output bytes of the op
            // (for batch variants: concatenation of all outputs so they can all be checked).
            let keyed_sign = if v.op == "sign" && v.kind == Kind::KeyCache { Some(sref.cached_signer(sk)) } else { None };
            let keyed_verify = if v.op == "verify" && v.kind == Kind::KeyCache { Some(sref.cached_verifier(pk)) } else { None };
            let op: Box<dyn Fn() -> Vec<u8> + Sync + '_> = match (v.op, v.kind) {
                ("keygen", Kind::Plain) | ("keygen", Kind::KeyCache) => Box::new(|| {
                    let (mut pk, sk) = sref.keygen(seed);
                    pk.extend_from_slice(&sk);
                    pk
                }),
                ("sign", Kind::Plain) => Box::new(|| sref.sign(sk, msg)),
                ("sign", Kind::KeyCache) => {
                    let f = keyed_sign.as_ref().unwrap();
                    Box::new(move || f(msg))
                }
                ("verify", Kind::Plain) => Box::new(|| vec![sref.verify(pk, msg, sig) as u8]),
                ("verify", Kind::KeyCache) => {
                    let f = keyed_verify.as_ref().unwrap();
                    Box::new(move || vec![f(msg, sig) as u8])
                }
                (opn, Kind::Par) => {
                    use rayon::prelude::*;
                    let pool = &pool;
                    Box::new(move || {
                        pool.install(|| {
                            (0..b)
                                .into_par_iter()
                                .map(|_| match opn {
                                    "keygen" => {
                                        let (mut pk, sk) = sref.keygen(seed);
                                        pk.extend_from_slice(&sk);
                                        pk
                                    }
                                    "sign" => sref.sign(sk, msg),
                                    _ => vec![sref.verify(pk, msg, sig) as u8],
                                })
                                .reduce(Vec::new, |mut a, x| {
                                    a.extend_from_slice(&x);
                                    a
                                })
                        })
                    })
                }
                _ => unreachable!(),
            };

            let m = measure(&*op, budget, b);
            let (mut samples, iterations, wall_total, cpu_total, out) = (m.samples, m.iterations, m.wall_total, m.cpu_total, m.out);
            let (median, mean, p95, min) = stats(&mut samples);

            // correctness check on the actual output of the measured loop (never hard-coded)
            let (output_sha256, matched) = match v.op {
                "keygen" => {
                    let unit = pk.len() + sk.len();
                    let all_ok = out.len() == unit * b as usize
                        && out.chunks(unit).all(|ch| sha256_hex(&ch[..pk.len()]) == r.pk_sha256 && sha256_hex(&ch[pk.len()..]) == r.sk_sha256);
                    (sha256_hex(&out[..pk.len()]), all_ok)
                }
                "sign" => {
                    let unit = sig.len();
                    let all_ok = out.len() == unit * b as usize && out.chunks(unit).all(|ch| sha256_hex(ch) == r.sig_sha256);
                    (sha256_hex(&out[..unit.min(out.len())]), all_ok)
                }
                _ => {
                    let all_true = out.len() == b as usize && out.iter().all(|&x| x == 1);
                    let tamper_rejected = match v.kind {
                        Kind::KeyCache => !keyed_verify.as_ref().unwrap()(msg, tampered),
                        _ => !sref.verify(pk, msg, tampered),
                    };
                    let ok = all_true && tamper_rejected;
                    (if ok { "true".into() } else { "false".into() }, ok)
                }
            };

            let line = BenchLine {
                lib: LIB,
                lib_version: lib_version(),
                lang: "rust",
                runtime: runtime(),
                variant: v.id,
                variant_name: v.name,
                variant_desc: v.desc,
                op: v.op,
                param: name.to_string(),
                iterations,
                threads: nthreads,
                wall_ns_median: median,
                wall_ns_mean: mean,
                wall_ns_p95: p95,
                wall_ns_min: min,
                cpu_ns_per_op: cpu_total / iterations.max(1),
                cpu_util: cpu_total as f64 / wall_total.max(1) as f64,
                ops_per_sec: iterations as f64 / (wall_total as f64 / 1e9),
                output_sha256,
                match_: matched,
            };
            let mut js = serde_json::to_string(&line).unwrap();
            js = js.replace("\"match_\":", "\"match\":");
            writeln!(outf, "{js}").expect("write line");
            eprintln!("{:10} {:22} median={:>12} ns  ops/s={:>10.1} cpu_util={:.2} match={}", v.id, name, median, line.ops_per_sec, line.cpu_util, matched);
        }
    }
}

// ------------------------------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = || -> ! {
        eprintln!("usage: pqcbench vectors <out.json> | crossverify <artifacts.json> <out.json> | bench --out <f.jsonl> [--budget-ms N] [--params a,b] [--ops a,b] [--variants a,b] | stages --out <f.jsonl> [--budget-ms N] [--params a,b] [--stages a,b] [--variants a,b] | validate <suite.json.gz> <out.json> [--params a,b] [--kinds a,b] [--variants a,b] | validate-merge <out.json> <part.json>... | memory --out <f.jsonl> [--params a,b] | info");
        std::process::exit(2)
    };
    match args.get(1).map(String::as_str) {
        Some("vectors") => cmd_vectors(args.get(2).unwrap_or_else(|| usage())),
        Some("crossverify") => cmd_crossverify(args.get(2).unwrap_or_else(|| usage()), args.get(3).unwrap_or_else(|| usage())),
        Some("info") => println!("{{\"lib\":\"{LIB}\",\"lib_version\":\"{}\",\"runtime\":\"{}\",\"build_tag\":\"{BUILD_TAG}\"}}", lib_version(), runtime()),
        Some("selftest") => selftest(),
        Some("stages") => {
            let (mut out, mut budget_ms, mut params, mut stages_f, mut variants) = (String::new(), 1000u64, None, None, None);
            let list = |s: &str| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>();
            let mut i = 2;
            while i < args.len() {
                let val = args.get(i + 1).cloned().unwrap_or_default();
                match args[i].as_str() {
                    "--out" => out = val,
                    "--budget-ms" => budget_ms = val.parse().expect("--budget-ms"),
                    "--params" => params = Some(list(&val)),
                    "--stages" => stages_f = Some(list(&val)),
                    "--variants" => variants = Some(list(&val)),
                    _ => usage(),
                }
                i += 2;
            }
            if out.is_empty() {
                usage();
            }
            let c = load_common();
            let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("rayon pool");
            let mut outf = std::fs::OpenOptions::new().create(true).append(true).open(&out).expect("open --out");
            for s in all_schemes() {
                if params.as_ref().is_some_and(|ps| !ps.iter().any(|x| x == s.name())) {
                    continue;
                }
                let Some(seed) = c.seeds.get(s.name()) else { continue };
                let a = stages::StageArgs { budget: Duration::from_millis(budget_ms), stages: stages_f.clone(), variants: variants.clone(), msg: c.msg.clone(), seed: seed.clone(), pool: rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("pool"), threads };
                let _ = &pool;
                s.run_stages(&a, &mut outf);
            }
        }
        Some("validate") => {
            let (input, out) = (args.get(2).cloned().unwrap_or_else(|| usage()), args.get(3).cloned().unwrap_or_else(|| usage()));
            let (mut params, mut kinds, mut variants) = (None, None, None);
            let list = |s: &str| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>();
            let mut i = 4;
            while i < args.len() {
                let val = args.get(i + 1).cloned().unwrap_or_default();
                match args[i].as_str() {
                    "--params" => params = Some(list(&val)),
                    "--kinds" => kinds = Some(list(&val)),
                    "--variants" => variants = Some(list(&val)),
                    _ => usage(),
                }
                i += 2;
            }
            validate::cmd_validate(validate::ValidateOpts { input, out, params, kinds, variants });
        }
        Some("validate-merge") => {
            let out = args.get(2).cloned().unwrap_or_else(|| usage());
            validate::cmd_validate_merge(&out, &args[3..]);
        }
        Some("memory") => {
            let (mut out, mut params) = (String::new(), None);
            let list = |s: &str| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>();
            let mut i = 2;
            while i < args.len() {
                let val = args.get(i + 1).cloned().unwrap_or_default();
                match args[i].as_str() {
                    "--out" => out = val,
                    "--params" => params = Some(list(&val)),
                    _ => usage(),
                }
                i += 2;
            }
            if out.is_empty() {
                usage();
            }
            memory::cmd_memory(memory::MemOpts { out, params });
        }
        Some("bench") => {
            let mut o = BenchOpts { out: String::new(), budget_ms: 1000, params: None, ops: None, variants: None };
            let list = |s: &str| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>();
            let mut i = 2;
            while i < args.len() {
                let val = args.get(i + 1).cloned().unwrap_or_default();
                match args[i].as_str() {
                    "--out" => o.out = val,
                    "--budget-ms" => o.budget_ms = val.parse().expect("--budget-ms"),
                    "--params" => o.params = Some(list(&val)),
                    "--ops" => o.ops = Some(list(&val)),
                    "--variants" => o.variants = Some(list(&val)),
                    _ => usage(),
                }
                i += 2;
            }
            if o.out.is_empty() {
                usage();
            }
            cmd_bench(o);
        }
        _ => usage(),
    }
}

/// Internal consistency checks of the raw hashing helpers against the RustCrypto digest crates.
fn selftest() {
    use sha2::Digest as _;
    let data: Vec<u8> = (0..400u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut bad = 0;
    for len in 0..300 {
        for split in [0usize, 1, 17, 63, 64, 65, 127, 128, 129] {
            let split = split.min(len);
            let mut r = fasthash::RawSha256::new();
            r.update(&data[..split]);
            r.update(&data[split..len]);
            let mut out = [0u8; 32];
            r.finalize_into(&mut out);
            let want = sha2::Sha256::digest(&data[..len]);
            if out[..] != want[..] {
                bad += 1;
                eprintln!("RawSha256 mismatch len={len} split={split}");
            }
            let mut r = fasthash::RawSha512::new();
            r.update(&data[..split]);
            r.update(&data[split..len]);
            let mut out = [0u8; 64];
            r.finalize_into(&mut out);
            let want = sha2::Sha512::digest(&data[..len]);
            if out[..] != want[..] {
                bad += 1;
                eprintln!("RawSha512 mismatch len={len} split={split}");
            }
        }
    }
    // midstate path: prefix block compressed separately
    let mut st = fasthash::SHA256_IV;
    let mut b = [0u8; 64];
    b.copy_from_slice(&data[..64]);
    sha2::block_api::compress256(&mut st, &[b]);
    let mut r = fasthash::RawSha256::from_midstate(st, 64);
    r.update(&data[64..150]);
    let mut out = [0u8; 32];
    r.finalize_into(&mut out);
    if out[..] != sha2::Sha256::digest(&data[..150])[..] {
        bad += 1;
        eprintln!("RawSha256 midstate mismatch");
    }
    eprintln!("x4 keccak available: {}", fasthash::x4_available());
    let mut o = vec![0u8; 32];
    fasthash::shake256_multi(&[&data[..200]], &mut o);
    {
        use sha3::digest::{ExtendableOutput, Update};
        let mut h = sha3::Shake256::default();
        h.update(&data[..200]);
        let mut w = vec![0u8; 32];
        h.finalize_xof_into(&mut w);
        if o != w {
            bad += 1;
            eprintln!("shake256_multi mismatch");
        }
    }
    eprintln!("selftest: {} problems", bad);
    if bad > 0 {
        std::process::exit(1);
    }
}
