//! One operation per new key: a sensitivity check, not a steady-state throughput benchmark.
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{hint::black_box, time::Instant};

#[derive(Clone, Deserialize, Serialize)]
struct Case {
    parameter: String,
    phase: String,
    index: usize,
    seed: String,
    message: String,
    context: String,
    entropy: String,
    #[serde(default)]
    pk: String,
    #[serde(default)]
    sk: String,
    #[serde(default)]
    signature: String,
}

#[derive(Deserialize)]
struct Corpus {
    version: String,
    cases: Vec<Case>,
}

#[derive(Serialize)]
struct Metric {
    elapsed_ns: u128,
    cpu_ns: u128,
}

fn cpu_ns() -> u128 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: a successful getrusage initializes the supplied rusage object.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec as u128 + usage.ru_stime.tv_sec as u128) * 1_000_000_000
        + (usage.ru_utime.tv_usec as u128 + usage.ru_stime.tv_usec as u128) * 1000
}

fn timed<T>(enabled: bool, operation: impl FnOnce() -> T) -> (T, Option<Metric>) {
    if !enabled {
        return (operation(), None);
    }
    let cpu = cpu_ns();
    let start = Instant::now();
    let result = black_box(operation());
    let elapsed_ns = start.elapsed().as_nanos();
    let cpu_ns = cpu_ns() - cpu;
    (result, Some(Metric { elapsed_ns, cpu_ns }))
}

macro_rules! implementation {
    ($module:ident, $library:ident) => {
        mod $module {
            use super::*;
            use $library::{Keypair, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey};

            pub fn execute<P: MlDsaParams>(case: &Case, measured: bool, expected: bool) -> serde_json::Value {
                let seed = Seed::try_from(hex::decode(&case.seed).unwrap().as_slice()).unwrap();
                let message = hex::decode(&case.message).unwrap();
                let context = hex::decode(&case.context).unwrap();
                assert_eq!(case.entropy, "00".repeat(32), "public deterministic signing uses zero entropy");
                let (key, keygen) = timed(measured, || SigningKey::<P>::from_seed(black_box(&seed)));
                let pk = key.verifying_key().encode();
                #[allow(deprecated)]
                let sk = key.expanded_key().to_expanded();
                if expected {
                    assert_eq!(hex::encode(&pk), case.pk);
                    assert_eq!(hex::encode(&sk), case.sk);
                }
                let (signature, sign) = timed(measured, || {
                    key.expanded_key().sign_deterministic(black_box(&message), black_box(&context)).unwrap()
                });
                let encoded = signature.encode();
                if expected { assert_eq!(hex::encode(&encoded), case.signature); }
                // Fresh verifier decoding and signature decoding occur outside the verify clock.
                let verifier = VerifyingKey::<P>::decode(&pk);
                let decoded = Signature::<P>::decode(&encoded).unwrap();
                let (valid, verify) = timed(measured, || {
                    verifier.verify_with_context(black_box(&message), black_box(&context), black_box(&decoded))
                });
                assert!(valid);
                let mut changed = encoded.clone();
                changed[0] ^= 1;
                if let Some(bad) = Signature::<P>::decode(&changed) {
                    let fresh = VerifyingKey::<P>::decode(&pk);
                    assert!(!fresh.verify_with_context(&message, &context, &bad));
                }
                let ((fresh_key, fresh_signature), keygen_sign) = timed(measured, || {
                    let fresh_key = SigningKey::<P>::from_seed(black_box(&seed));
                    let sig = fresh_key.expanded_key().sign_deterministic(black_box(&message), black_box(&context)).unwrap();
                    (fresh_key, sig)
                });
                assert_eq!(fresh_signature.encode(), encoded);
                assert_eq!(fresh_key.verifying_key().encode(), pk);
                let mut out = json!({"parameter":case.parameter,"phase":case.phase,"index":case.index,
                    "seed":case.seed,"pk":hex::encode(pk),"sk":hex::encode(sk),
                    "signature":hex::encode(encoded),"valid":true,"tamper_rejected":true});
                if measured {
                    out["metrics"] = json!({"keygen":keygen.unwrap(),"sign":sign.unwrap(),
                        "verify":verify.unwrap(),"keygen_sign":keygen_sign.unwrap()});
                }
                out
            }
        }
    };
}

implementation!(original, baseline);
implementation!(changed, candidate);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 5, "check|bench INPUT PARAMETER VARIANT");
    assert!(args[1] == "check" || args[1] == "bench");
    assert!(args[4] == "baseline" || args[4] == "candidate");
    assert!(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"].contains(&args[3].as_str()));
    let input: Corpus = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    assert_eq!(input.version, "pqc-tenkeys-v1/rustcrypto");
    let cases: Vec<&Case> = input
        .cases
        .iter()
        .filter(|c| c.parameter == args[3])
        .collect();
    assert_eq!(cases.len(), 12);
    assert_eq!(cases.iter().filter(|c| c.phase == "warmup").count(), 2);
    assert_eq!(cases.iter().filter(|c| c.phase == "measured").count(), 10);
    let bench = args[1] == "bench";
    for case in cases {
        let measured = bench && case.phase == "measured";
        macro_rules! run {
            ($module:ident, $library:ident) => {
                match args[3].as_str() {
                    "ML-DSA-44" => $module::execute::<$library::MlDsa44>(case, measured, bench),
                    "ML-DSA-65" => $module::execute::<$library::MlDsa65>(case, measured, bench),
                    "ML-DSA-87" => $module::execute::<$library::MlDsa87>(case, measured, bench),
                    _ => unreachable!(),
                }
            };
        }
        let mut row = if args[4] == "baseline" {
            run!(original, baseline)
        } else {
            run!(changed, candidate)
        };
        row["variant"] = json!(args[4]);
        if !bench || measured {
            println!("{}", row);
        }
    }
}
