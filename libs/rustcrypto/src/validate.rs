//! `validate` subcommand (Phase 2 section A): every case of common/validation/validation.json.gz
//! through every variant of the matching process that lives in this binary (build tag), plus the
//! stage pipelines (total / total_best) for sigver cases. `validate-merge` combines the per-binary
//! partial files and computes the summary.

use crate::schemes::{all_schemes, Scheme};
use crate::{hex, unhex, Kind, BUILD_TAG, V};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Deserialize, Clone)]
pub struct Case {
    pub id: String,
    pub kind: String,
    pub param: String,
    #[serde(default)]
    pub seed_hex: Option<String>,
    #[serde(default)]
    pub expect_pk_hex: Option<String>,
    #[serde(default)]
    pub expect_sk_hex: Option<String>,
    #[serde(default)]
    pub sk_hex: Option<String>,
    #[serde(default)]
    pub pk_hex: Option<String>,
    #[serde(default)]
    pub msg_hex: Option<String>,
    #[serde(default)]
    pub ctx_hex: Option<String>,
    #[serde(default)]
    pub sig_hex: Option<String>,
    #[serde(default)]
    pub expect_sig_hex: Option<String>,
    #[serde(default)]
    pub expect: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
}
#[derive(Deserialize)]
struct Suite {
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Result1 {
    pub id: String,
    pub variant: String,
    pub pass: bool,
    pub got: Option<bool>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub skipped: Option<String>,
}
#[derive(Serialize, Deserialize, Default)]
pub struct Summary {
    pub pass: u64,
    pub fail: u64,
    pub skipped: u64,
}
#[derive(Serialize, Deserialize)]
pub struct Out {
    pub lib: String,
    pub lib_version: String,
    pub results: Vec<Result1>,
    pub summary: BTreeMap<String, Summary>,
}

pub struct ValidateOpts {
    pub input: String,
    pub out: String,
    pub params: Option<Vec<String>>,
    pub kinds: Option<Vec<String>>,
    pub variants: Option<Vec<String>>,
}

pub fn load_cases(path: &str) -> Vec<Case> {
    let f = std::fs::File::open(path).expect("open validation suite");
    let mut gz = flate2::read::GzDecoder::new(f);
    let mut s = String::new();
    gz.read_to_string(&mut s).expect("gunzip");
    serde_json::from_str::<Suite>(&s).expect("parse suite").cases
}

fn summarize(results: &[Result1]) -> BTreeMap<String, Summary> {
    let mut m: BTreeMap<String, Summary> = BTreeMap::new();
    for r in results {
        let e = m.entry(r.variant.clone()).or_default();
        if r.skipped.is_some() {
            e.skipped += 1;
        } else if r.pass {
            e.pass += 1;
        } else {
            e.fail += 1;
        }
    }
    m
}

/// Run a closure, converting a panic into an error string (only possible in panic=unwind builds).
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|e| {
        if let Some(s) = e.downcast_ref::<&str>() {
            format!("panic: {s}")
        } else if let Some(s) = e.downcast_ref::<String>() {
            format!("panic: {s}")
        } else {
            "panic".to_string()
        }
    })
}

fn all_same(v: &[Option<Vec<u8>>]) -> Option<Vec<u8>> {
    let first = v.first()?.clone()?;
    if v.iter().all(|x| x.as_ref() == Some(&first)) {
        Some(first)
    } else {
        None
    }
}

pub fn cmd_validate(o: ValidateOpts) {
    let cases = load_cases(&o.input);
    let schemes = all_schemes();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("pool");
    let silent_panics = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut results: Vec<Result1> = vec![];

    for case in &cases {
        if o.params.as_ref().is_some_and(|p| !p.iter().any(|x| *x == case.param)) {
            continue;
        }
        if o.kinds.as_ref().is_some_and(|k| !k.iter().any(|x| *x == case.kind)) {
            continue;
        }
        let Some(s) = schemes.iter().find(|s| s.name() == case.param) else { continue };
        let s: &dyn Scheme = &**s;
        let op = match case.kind.as_str() {
            "keygen" => "keygen",
            "siggen" => "sign",
            "sigver" => "verify",
            _ => continue,
        };
        let msg = case.msg_hex.as_deref().map(unhex).unwrap_or_default();
        let ctx = case.ctx_hex.as_deref().map(unhex).unwrap_or_default();

        // the process variants that live in this binary
        let mut variants: Vec<(String, Kind)> = V
            .iter()
            .filter(|v| v.op == op && (v.tag == BUILD_TAG || (BUILD_TAG == "pgo-gen" && v.tag.starts_with("pgo-"))))
            .map(|v| (v.id.to_string(), v.kind))
            .collect();
        if op == "verify" && BUILD_TAG == "base" {
            variants.push(("total.v0".into(), Kind::Plain));
            variants.push(("total_best.v0".into(), Kind::Plain));
        }
        for (vid, kind) in variants {
            if o.variants.as_ref().is_some_and(|vs| !vs.iter().any(|x| *x == vid)) {
                continue;
            }
            let copies = if kind == Kind::Par { threads } else { 1 };
            let (pass, got, error): (bool, Option<bool>, Option<String>) = match op {
                "keygen" => {
                    let seed = unhex(case.seed_hex.as_deref().unwrap_or(""));
                    let want_pk = unhex(case.expect_pk_hex.as_deref().unwrap_or(""));
                    let want_sk = unhex(case.expect_sk_hex.as_deref().unwrap_or(""));
                    let r = guarded(|| {
                        let outs: Vec<Option<Vec<u8>>> = if copies > 1 {
                            pool.install(|| {
                                (0..copies)
                                    .into_par_iter()
                                    .map(|_| {
                                        let (mut pk, sk) = s.keygen(&seed);
                                        pk.extend_from_slice(&sk);
                                        Some(pk)
                                    })
                                    .collect()
                            })
                        } else {
                            let (mut pk, sk) = s.keygen(&seed);
                            pk.extend_from_slice(&sk);
                            vec![Some(pk)]
                        };
                        all_same(&outs)
                    });
                    match r {
                        Ok(Some(out)) => {
                            let ok = out.len() == want_pk.len() + want_sk.len() && out[..want_pk.len()] == want_pk[..] && out[want_pk.len()..] == want_sk[..];
                            (ok, Some(ok), if ok { None } else { Some("keygen output differs from expectation".into()) })
                        }
                        Ok(None) => (false, Some(false), Some("batch outputs disagree".into())),
                        Err(e) => (false, None, Some(e)),
                    }
                }
                "sign" => {
                    let sk = unhex(case.sk_hex.as_deref().unwrap_or(""));
                    let want = unhex(case.expect_sig_hex.as_deref().unwrap_or(""));
                    let r = guarded(|| {
                        let outs: Vec<Option<Vec<u8>>> = match kind {
                            Kind::KeyCache => vec![s.cached_signer_ctx(&sk).and_then(|f| f(&msg, &ctx))],
                            Kind::Par => pool.install(|| (0..copies).into_par_iter().map(|_| s.sign_ctx(&sk, &msg, &ctx)).collect()),
                            Kind::Plain => vec![s.sign_ctx(&sk, &msg, &ctx)],
                        };
                        all_same(&outs)
                    });
                    match r {
                        Ok(Some(out)) => {
                            let ok = out == want;
                            (ok, Some(ok), if ok { None } else { Some("signature differs from expectation".into()) })
                        }
                        Ok(None) => (false, Some(false), Some("sign returned an error (or batch outputs disagree)".into())),
                        Err(e) => (false, None, Some(e)),
                    }
                }
                _ => {
                    let pk = unhex(case.pk_hex.as_deref().unwrap_or(""));
                    let sig = unhex(case.sig_hex.as_deref().unwrap_or(""));
                    let want = case.expect.unwrap_or(false);
                    let r = guarded(|| match vid.as_str() {
                        "total.v0" => Some(s.total_v0(&pk, &msg, &ctx, &sig)),
                        "total_best.v0" => Some(s.total_best(&pk, &msg, &ctx, &sig)),
                        _ => match kind {
                            Kind::KeyCache => Some(s.cached_verifier_ctx(&pk).map(|f| f(&msg, &ctx, &sig)).unwrap_or(false)),
                            Kind::Par => {
                                let outs: Vec<bool> = pool.install(|| (0..copies).into_par_iter().map(|_| s.verify_ctx(&pk, &msg, &ctx, &sig)).collect());
                                if outs.iter().all(|&b| b == outs[0]) {
                                    Some(outs[0])
                                } else {
                                    None
                                }
                            }
                            Kind::Plain => Some(s.verify_ctx(&pk, &msg, &ctx, &sig)),
                        },
                    });
                    match r {
                        Ok(Some(got)) => (got == want, Some(got), if got == want { None } else { Some(format!("expected {want}, got {got} ({})", case.reason.clone().unwrap_or_default())) }),
                        Ok(None) => (false, None, Some("batch results disagree".into())),
                        // a panic on malformed input is an error return => counts as false
                        Err(e) => (!want, Some(false), Some(e)),
                    }
                }
            };
            if !pass {
                eprintln!("FAIL {:40} {:14} got={:?} err={:?}", case.id, vid, got, error);
            }
            results.push(Result1 { id: case.id.clone(), variant: vid, pass, got, error, skipped: None });
        }
    }
    std::panic::set_hook(silent_panics);
    let summary = summarize(&results);
    let out = Out { lib: crate::LIB.into(), lib_version: crate::lib_version(), results, summary };
    std::fs::write(&o.out, serde_json::to_string(&out).unwrap() + "\n").expect("write");
    for (v, s) in &out.summary {
        eprintln!("{v:16} pass={} fail={} skipped={}", s.pass, s.fail, s.skipped);
    }
}

pub fn cmd_validate_merge(out: &str, parts: &[String]) {
    let mut results: Vec<Result1> = vec![];
    for p in parts {
        let o: Out = serde_json::from_str(&std::fs::read_to_string(p).expect("read part")).expect("parse part");
        results.extend(o.results);
    }
    results.sort_by(|a, b| a.id.cmp(&b.id).then(a.variant.cmp(&b.variant)));
    let summary = summarize(&results);
    let o = Out { lib: crate::LIB.into(), lib_version: crate::lib_version(), results, summary };
    std::fs::write(out, serde_json::to_string_pretty(&o).unwrap() + "\n").expect("write");
    let (mut p, mut f, mut sk) = (0, 0, 0);
    for (v, s) in &o.summary {
        eprintln!("{v:16} pass={} fail={} skipped={}", s.pass, s.fail, s.skipped);
        p += s.pass;
        f += s.fail;
        sk += s.skipped;
    }
    eprintln!("TOTAL pass={p} fail={f} skipped={sk} ({} result lines)", o.results.len());
    let _ = hex;
}
