//! Standalone differential and paired timing driver; production sources are built unchanged apart from the reviewed patch.
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
struct Case {
    seed: String,
    message: String,
    context: String,
    randomness: String,
    #[serde(default)]
    pk: String,
    #[serde(default)]
    sk: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    internal_signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Corpus {
    version: String,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize)]
struct Fixtures {
    version: String,
    p44: Vec<Case>,
    p65: Vec<Case>,
    p87: Vec<Case>,
}

#[derive(Serialize)]
struct Metric {
    iterations: u64,
    elapsed_ns: u128,
    cpu_ns: u128,
    ns_per_op: f64,
}

fn cpu_ns() -> u128 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage writes exactly the initialized rusage on success; the return code is checked.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec as u128 + usage.ru_stime.tv_sec as u128) * 1_000_000_000
        + (usage.ru_utime.tv_usec as u128 + usage.ru_stime.tv_usec as u128) * 1000
}

fn measure<T>(
    count: usize,
    budget: Duration,
    mut operation: impl FnMut(usize) -> T,
    check: impl FnOnce(T),
) -> Metric {
    assert!(count > 0);
    let mut iterations = 0u64;
    let mut last = None;
    let cpu = cpu_ns();
    let start = Instant::now();
    loop {
        for i in 0..count {
            last = Some(black_box(operation(black_box(i))));
            iterations += 1;
        }
        if start.elapsed() >= budget {
            break;
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let cpu_ns = cpu_ns() - cpu;
    check(last.unwrap());
    Metric {
        iterations,
        elapsed_ns,
        cpu_ns,
        ns_per_op: elapsed_ns as f64 / iterations as f64,
    }
}

macro_rules! implementation {
    ($module:ident, $library:ident) => {
        mod $module {
            use super::*;
            use $library::{Keypair, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey};

            pub fn fixtures<P: MlDsaParams>(input: &[Case]) -> Vec<Case> {
                input
                    .iter()
                    .cloned()
                    .map(|mut case| {
                        let seed =
                            Seed::try_from(hex::decode(&case.seed).unwrap().as_slice()).unwrap();
                        let message = hex::decode(&case.message).unwrap();
                        let context = hex::decode(&case.context).unwrap();
                        let random = hex::decode(&case.randomness)
                            .unwrap()
                            .as_slice()
                            .try_into()
                            .unwrap();
                        let key = SigningKey::<P>::from_seed(&seed);
                        case.pk = hex::encode(key.verifying_key().encode());
                        #[allow(deprecated)]
                        {
                            case.sk = hex::encode(key.expanded_key().to_expanded());
                        }
                        case.signature = hex::encode(
                            key.expanded_key()
                                .sign_deterministic(&message, &context)
                                .unwrap()
                                .encode(),
                        );
                        case.internal_signature = hex::encode(
                            key.expanded_key()
                                .sign_internal(&[&message], &random)
                                .encode(),
                        );
                        case
                    })
                    .collect()
            }

            pub fn check<P: MlDsaParams>(cases: &[Case]) {
                for case in cases {
                    let seed = Seed::try_from(hex::decode(&case.seed).unwrap().as_slice()).unwrap();
                    let message = hex::decode(&case.message).unwrap();
                    let context = hex::decode(&case.context).unwrap();
                    let random = hex::decode(&case.randomness)
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap();
                    let key = SigningKey::<P>::from_seed(&seed);
                    let vk = key.verifying_key();
                    assert_eq!(hex::encode(vk.encode()), case.pk);
                    #[allow(deprecated)]
                    {
                        assert_eq!(hex::encode(key.expanded_key().to_expanded()), case.sk);
                    }
                    assert!(vk == key.expanded_key().verifying_key());
                    assert!(vk == VerifyingKey::decode(&vk.encode()));
                    let sig = key
                        .expanded_key()
                        .sign_deterministic(&message, &context)
                        .unwrap();
                    assert_eq!(hex::encode(sig.encode()), case.signature);
                    assert!(vk.verify_with_context(&message, &context, &sig));
                    let internal = key.expanded_key().sign_internal(&[&message], &random);
                    assert_eq!(hex::encode(internal.encode()), case.internal_signature);
                    assert!(vk.verify_internal(&message, &internal));
                    let from_baseline = Signature::decode(
                        &hex::decode(&case.signature)
                            .unwrap()
                            .as_slice()
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap();
                    assert!(vk.verify_with_context(&message, &context, &from_baseline));
                    let mut bad_message = message.clone();
                    bad_message.push(1);
                    assert!(!vk.verify_with_context(&bad_message, &context, &sig));
                    let mut bad_context = context.clone();
                    bad_context.push(1);
                    assert!(!vk.verify_with_context(&message, &bad_context, &sig));
                    let mut bad_sig = sig.encode();
                    bad_sig[0] ^= 1;
                    if let Some(bad) = Signature::decode(&bad_sig) {
                        assert!(!vk.verify_with_context(&message, &context, &bad));
                    }
                    assert!(
                        key.expanded_key()
                            .sign_deterministic(&message, &[0; 256])
                            .is_err()
                    );
                    assert!(!vk.verify_with_context(&message, &[0; 256], &sig));
                    let cloned = key.clone();
                    drop(key);
                    assert!(cloned.verifying_key() == vk);
                }
            }

            pub fn timer<'a, P: MlDsaParams + 'a>(
                cases: &'a [Case],
                op: &'a str,
            ) -> impl FnMut(Duration) -> Metric + 'a {
                let seeds: Vec<Seed> = cases
                    .iter()
                    .map(|c| hex::decode(&c.seed).unwrap().as_slice().try_into().unwrap())
                    .collect();
                let messages: Vec<Vec<u8>> = cases
                    .iter()
                    .map(|c| hex::decode(&c.message).unwrap())
                    .collect();
                let contexts: Vec<Vec<u8>> = cases
                    .iter()
                    .map(|c| hex::decode(&c.context).unwrap())
                    .collect();
                let keys: Vec<SigningKey<P>> = seeds.iter().map(SigningKey::from_seed).collect();
                let vks: Vec<VerifyingKey<P>> = keys.iter().map(|k| k.verifying_key()).collect();
                let signatures: Vec<Signature<P>> = cases
                    .iter()
                    .map(|c| {
                        Signature::decode(
                            &hex::decode(&c.signature)
                                .unwrap()
                                .as_slice()
                                .try_into()
                                .unwrap(),
                        )
                        .unwrap()
                    })
                    .collect();
                let end = cases.last().unwrap();
                move |budget| match op {
                    "keygen" => measure(
                        cases.len(),
                        budget,
                        |i| SigningKey::<P>::from_seed(&seeds[i]),
                        |key| {
                            assert_eq!(hex::encode(key.verifying_key().encode()), end.pk);
                            #[allow(deprecated)]
                            {
                                assert_eq!(hex::encode(key.expanded_key().to_expanded()), end.sk);
                            }
                        },
                    ),
                    "keygen_sign" => measure(
                        cases.len(),
                        budget,
                        |i| {
                            let key = SigningKey::<P>::from_seed(&seeds[i]);
                            let sig = key
                                .expanded_key()
                                .sign_deterministic(&messages[i], &contexts[i])
                                .unwrap();
                            (key, sig)
                        },
                        |(key, sig)| {
                            assert_eq!(hex::encode(key.verifying_key().encode()), end.pk);
                            assert_eq!(hex::encode(sig.encode()), end.signature);
                        },
                    ),
                    "sign" => measure(
                        cases.len(),
                        budget,
                        |i| {
                            keys[i]
                                .expanded_key()
                                .sign_deterministic(&messages[i], &contexts[i])
                                .unwrap()
                        },
                        |sig| assert_eq!(hex::encode(sig.encode()), end.signature),
                    ),
                    "verify" => measure(
                        cases.len(),
                        budget,
                        |i| vks[i].verify_with_context(&messages[i], &contexts[i], &signatures[i]),
                        |valid| assert!(valid),
                    ),
                    _ => panic!("unknown operation"),
                }
            }
        }
    };
}

implementation!(base, baseline);
implementation!(next, candidate);

fn pairs(
    parameter: &str,
    fork: usize,
    rounds: usize,
    budget: Duration,
    op: &str,
    mut baseline: impl FnMut(Duration) -> Metric,
    mut candidate: impl FnMut(Duration) -> Metric,
) {
    let warmup = Duration::from_millis(300);
    if fork % 2 == 0 {
        baseline(warmup);
        candidate(warmup);
    } else {
        candidate(warmup);
        baseline(warmup);
    }
    for round in 0..rounds {
        let (a, b, order) = if (fork + round) % 2 == 0 {
            (
                baseline(budget),
                candidate(budget),
                ["baseline", "candidate"],
            )
        } else {
            let b = candidate(budget);
            let a = baseline(budget);
            (a, b, ["candidate", "baseline"])
        };
        println!(
            "{}",
            json!({"parameter":parameter,"operation":op,"fork":fork,"round":round,
            "order":order,"speedup":a.ns_per_op/b.ns_per_op,"baseline":a,"candidate":b})
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args[1].as_str() {
        "fixtures" => {
            assert_eq!(args.len(), 3);
            let input: Corpus = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
            assert_eq!(input.version, "mldsa-keygen-v1/204");
            assert_eq!(input.cases.len(), 16);
            let result = Fixtures {
                version: input.version,
                p44: base::fixtures::<baseline::MlDsa44>(&input.cases),
                p65: base::fixtures::<baseline::MlDsa65>(&input.cases),
                p87: base::fixtures::<baseline::MlDsa87>(&input.cases),
            };
            println!("{}", serde_json::to_string(&result).unwrap());
        }
        "check" => {
            assert_eq!(args.len(), 3);
            let f: Fixtures = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
            assert_eq!(f.version, "mldsa-keygen-v1/204");
            assert_eq!((f.p44.len(), f.p65.len(), f.p87.len()), (16, 16, 16));
            base::check::<baseline::MlDsa44>(&f.p44);
            next::check::<candidate::MlDsa44>(&f.p44);
            base::check::<baseline::MlDsa65>(&f.p65);
            next::check::<candidate::MlDsa65>(&f.p65);
            base::check::<baseline::MlDsa87>(&f.p87);
            next::check::<candidate::MlDsa87>(&f.p87);
            println!(
                "{}",
                json!({"cases":48,"variants":2,"exact_keygen":true,"exact_signatures":96,"negative_checks_per_variant":240,"cached_keys_equal_derived":true})
            );
        }
        "bench" => {
            assert_eq!(args.len(), 7);
            let f: Fixtures = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
            assert_eq!(f.version, "mldsa-keygen-v1/204");
            assert_eq!((f.p44.len(), f.p65.len(), f.p87.len()), (16, 16, 16));
            let fork: usize = args[3].parse().unwrap();
            let rounds: usize = args[4].parse().unwrap();
            let millis: u64 = args[5].parse().unwrap();
            let op = &args[6];
            assert!(rounds >= 2 && rounds % 2 == 0 && millis >= 100 && millis <= 10000);
            let budget = Duration::from_millis(millis);
            pairs(
                "ML-DSA-44",
                fork,
                rounds,
                budget,
                op,
                base::timer::<baseline::MlDsa44>(&f.p44, op),
                next::timer::<candidate::MlDsa44>(&f.p44, op),
            );
            pairs(
                "ML-DSA-65",
                fork,
                rounds,
                budget,
                op,
                base::timer::<baseline::MlDsa65>(&f.p65, op),
                next::timer::<candidate::MlDsa65>(&f.p65, op),
            );
            pairs(
                "ML-DSA-87",
                fork,
                rounds,
                budget,
                op,
                base::timer::<baseline::MlDsa87>(&f.p87, op),
                next::timer::<candidate::MlDsa87>(&f.p87, op),
            );
        }
        _ => panic!("unknown command"),
    }
}
