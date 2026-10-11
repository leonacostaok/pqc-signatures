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

mod schemes;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use schemes::{all_schemes, Scheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, Instant};

const LIB: &str = "rustcrypto";
const BUILD_TAG: &str = env!("PQC_BUILD_TAG");

fn lib_version() -> String {
    format!("ml-dsa {} + slh-dsa {}", env!("ML_DSA_VERSION"), env!("SLH_DSA_VERSION"))
}
fn runtime() -> String {
    format!("{} (build={})", env!("RUSTC_VERSION_STR"), BUILD_TAG)
}

// ------------------------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}
fn sha256_hex(b: &[u8]) -> String {
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
struct RefEntry {
    pk_sha256: String,
    sk_sha256: String,
    sig_sha256: String,
}

struct Common {
    msg: Vec<u8>,
    seeds: BTreeMap<String, Vec<u8>>,
    reference: BTreeMap<String, RefEntry>,
}

fn load_common() -> Common {
    let d = common_dir();
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(d.join("vectors.json")).expect("read vectors.json")).expect("parse vectors.json");
    let reference: BTreeMap<String, RefEntry> = serde_json::from_str(&std::fs::read_to_string(d.join("reference.json")).expect("read reference.json")).expect("parse reference.json");
    Common {
        msg: unhex(&v.message_hex),
        seeds: v.params.iter().map(|p| (p.name.clone(), unhex(&p.seed_hex))).collect(),
        reference,
    }
}

fn cpu_time_ns() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1000;
    tv(ru.ru_utime) + tv(ru.ru_stime)
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
enum Kind {
    Plain,
    KeyCache,
    Par,
}

struct Variant {
    id: &'static str,
    op: &'static str,
    name: &'static str,
    desc: &'static str,
    tag: &'static str,
    kind: Kind,
}

const V: &[Variant] = &[
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

/// Runs `op` (which returns output bytes) with warm-up and the contract's budget loop.
/// `batch` > 1 means `op` performs `batch` operations at once (wall per op = wall per batch / batch).
fn measure(op: &(dyn Fn() -> Vec<u8> + Sync), budget: Duration, batch: u64) -> (Vec<u64>, u64, u64, u64, Vec<u8>) {
    // warm-up: >= 1 call, up to 20 calls or 100 ms (not recorded)
    let w0 = Instant::now();
    let mut warm = 0;
    let mut first = Duration::ZERO;
    loop {
        let t = Instant::now();
        let _ = op();
        let d = t.elapsed();
        if warm == 0 {
            first = d;
        }
        warm += 1;
        if warm >= 20 || w0.elapsed() >= Duration::from_millis(100) || d > Duration::from_millis(500) {
            break;
        }
    }
    let min_calls = if first > Duration::from_secs(5) { 2 } else { 3 };
    let cap_calls = 100_000 / batch;

    let mut samples = Vec::with_capacity(1024);
    let mut out = vec![];
    let cpu0 = cpu_time_ns();
    let t0 = Instant::now();
    let mut calls = 0u64;
    loop {
        let t = Instant::now();
        out = op();
        samples.push(t.elapsed().as_nanos() as u64 / batch);
        calls += 1;
        if (t0.elapsed() >= budget && calls >= min_calls) || calls >= cap_calls {
            break;
        }
    }
    let wall_total = t0.elapsed().as_nanos() as u64;
    let cpu_total = cpu_time_ns() - cpu0;
    (samples, calls * batch, wall_total, cpu_total, out)
}

fn stats(samples: &mut [u64]) -> (u64, u64, u64, u64) {
    samples.sort_unstable();
    let n = samples.len();
    let median = if n % 2 == 1 { samples[n / 2] } else { (samples[n / 2 - 1] + samples[n / 2]) / 2 };
    let mean = (samples.iter().map(|&x| x as u128).sum::<u128>() / n as u128) as u64;
    let p95 = samples[((n as f64 * 0.95).ceil() as usize).clamp(1, n) - 1];
    (median, mean, p95, samples[0])
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

            let (mut samples, iterations, wall_total, cpu_total, out) = measure(&*op, budget, b);
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
        eprintln!("usage: pqcbench vectors <out.json> | crossverify <artifacts.json> <out.json> | bench --out <f.jsonl> [--budget-ms N] [--params a,b] [--ops a,b] [--variants a,b] | info");
        std::process::exit(2)
    };
    match args.get(1).map(String::as_str) {
        Some("vectors") => cmd_vectors(args.get(2).unwrap_or_else(|| usage())),
        Some("crossverify") => cmd_crossverify(args.get(2).unwrap_or_else(|| usage()), args.get(3).unwrap_or_else(|| usage())),
        Some("info") => println!("{{\"lib\":\"{LIB}\",\"lib_version\":\"{}\",\"runtime\":\"{}\",\"build_tag\":\"{BUILD_TAG}\"}}", lib_version(), runtime()),
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
