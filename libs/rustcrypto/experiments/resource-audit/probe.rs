//! Untimed, single-threaded requested-allocation accounting for synthetic ML-DSA inputs.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering::SeqCst};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Counter;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static WATCH: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicBool = AtomicBool::new(false);
static CLEARED: AtomicBool = AtomicBool::new(false);

fn add(size: usize) {
    ALLOCS.fetch_add(1, SeqCst); BYTES.fetch_add(size, SeqCst);
    let live = LIVE.fetch_add(size as isize, SeqCst) + size as isize;
    PEAK.fetch_max(live.max(0) as usize, SeqCst);
}
fn remove(size: usize) {
    FREES.fetch_add(1, SeqCst); FREED.fetch_add(size, SeqCst);
    LIVE.fetch_sub(size as isize, SeqCst);
}
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && ACTIVE.load(SeqCst) { add(layout.size()); }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() && ACTIVE.load(SeqCst) { add(layout.size()); }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH.load(SeqCst) == ptr as usize && layout.size() == 32 {
            // The watched allocation is exactly a fully initialized Seed byte array. Read only
            // before forwarding to System; never read padding, freed storage or secret fields.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, 32) };
            CLEARED.store(bytes.iter().all(|&b| b == 0), SeqCst);
            SEEN.store(true, SeqCst);
        }
        if ACTIVE.load(SeqCst) { remove(layout.size()); }
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(ptr, layout, size) };
        if !out.is_null() && ACTIVE.load(SeqCst) {
            REALLOCS.fetch_add(1, SeqCst); remove(layout.size()); add(size);
        }
        out
    }
}
#[global_allocator]
static GLOBAL: Counter = Counter;

fn account<T>(enabled: bool, call: impl FnOnce() -> T) -> (T, Value) {
    assert!(!ACTIVE.load(SeqCst));
    for counter in [&ALLOCS, &FREES, &REALLOCS, &BYTES, &FREED, &PEAK] { counter.store(0, SeqCst); }
    LIVE.store(0, SeqCst); ACTIVE.store(enabled, SeqCst);
    let output = black_box(call());
    ACTIVE.store(false, SeqCst);
    let metrics = json!({"allocations":ALLOCS.load(SeqCst),"deallocations":FREES.load(SeqCst),
        "reallocations":REALLOCS.load(SeqCst),"allocated_bytes":BYTES.load(SeqCst),
        "freed_bytes":FREED.load(SeqCst),"live_delta_bytes":LIVE.load(SeqCst),
        "peak_live_above_entry_bytes":PEAK.load(SeqCst)});
    (output, metrics)
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
struct Outcome { row: Value, pk: Vec<u8>, sk: Vec<u8>, sig: Vec<u8> }

macro_rules! implementation {
    ($module:ident, $lib:ident) => { mod $module {
        use super::*;
        use $lib::{Keypair, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey, ExpandedSigningKey};
        #[inline(never)]
        pub fn construct44(seed: &Seed) -> SigningKey<$lib::MlDsa44> { black_box(SigningKey::from_seed(black_box(seed))) }
        #[inline(never)]
        pub fn construct65(seed: &Seed) -> SigningKey<$lib::MlDsa65> { black_box(SigningKey::from_seed(black_box(seed))) }
        #[inline(never)]
        pub fn construct87(seed: &Seed) -> SigningKey<$lib::MlDsa87> { black_box(SigningKey::from_seed(black_box(seed))) }
        pub fn run<P: MlDsaParams>(parameter: &str, index: usize, enabled: bool, construct: fn(&Seed)->SigningKey<P>) -> Outcome {
            let seed = Seed::from(std::array::from_fn::<u8,32,_>(|j| (index * 37 + j * 13 + 1) as u8));
            let message: Vec<u8> = (0..[0,1,128,1024][index%4]).map(|j| (j*17+index) as u8).collect();
            let context: Vec<u8> = (0..[0,1,31,255][index%4]).map(|j| (j*19+index) as u8).collect();
            let sizes = json!({"signing_key":std::mem::size_of::<SigningKey<P>>(),
                "expanded_signing_key":std::mem::size_of::<ExpandedSigningKey<P>>(),
                "verifying_key":std::mem::size_of::<VerifyingKey<P>>(),
                "signature":std::mem::size_of::<Signature<P>>(),"seed":std::mem::size_of::<Seed>()});
            let (key, keygen) = account(enabled, || construct(&seed));
            let vk = key.verifying_key();
            let pk = vk.encode().to_vec();
            #[allow(deprecated)]
            let sk = key.expanded_key().to_expanded().to_vec();
            let (signature, sign) = account(enabled, || key.expanded_key().sign_deterministic(black_box(&message),black_box(&context)));
            let signature = signature.unwrap(); let sig = signature.encode().to_vec();
            let (valid, verify) = account(enabled, || vk.verify_with_context(black_box(&message),black_box(&context),black_box(&signature)));
            assert!(valid);
            let mut tampered = signature.encode(); tampered[0] ^= 1;
            if let Some(bad) = Signature::<P>::decode(&tampered) { assert!(!vk.verify_with_context(&message,&context,&bad)); }
            let ((fresh, fresh_sig), fresh_key_sign) = account(enabled, || {
                let fresh = construct(&seed);
                let signature = fresh.expanded_key().sign_deterministic(black_box(&message),black_box(&context));
                (fresh,signature)
            });
            let fresh_sig = fresh_sig.unwrap();
            assert_eq!(fresh_sig.encode().as_slice(),sig.as_slice());
            assert_eq!(fresh.verifying_key().encode().as_slice(),pk.as_slice());
            assert_eq!(fresh.to_seed(),seed);
            let (_, fresh_drop) = account(enabled, || drop((fresh,fresh_sig)));
            SEEN.store(false,SeqCst); CLEARED.store(false,SeqCst);
            WATCH.store(key.as_seed().as_ptr() as usize,SeqCst);
            let (_, key_drop) = account(enabled, || drop(key));
            WATCH.store(0,SeqCst);
            assert!(vk.verify_with_context(&message,&context,&signature));
            let row = json!({"parameter":parameter,"case":index,"sizes":sizes,
                "encoded_sizes":{"public_key":pk.len(),"expanded_private_key":sk.len(),"signature":sig.len(),"seed":32},
                "output_sha256":{"public_key":digest(&pk),"expanded_private_key":digest(&sk),"signature":digest(&sig)},
                "metrics":{"keygen":keygen,"fresh_key_sign":fresh_key_sign,"sign":sign,"verify":verify,"key_drop":key_drop,"fresh_key_drop":fresh_drop},
                "seed_deallocation_observed":SEEN.load(SeqCst),"seed_zero_before_deallocation":CLEARED.load(SeqCst),
                "seed_observation_length":32,"exact_output_checked":true,"tamper_rejected":true});
            Outcome { row,pk,sk,sig }
        }
    }};
}
implementation!(original,baseline);
implementation!(changed,candidate);
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len()==2 && ["check","account"].contains(&args[1].as_str()));
    let enabled=args[1]=="account";
    for index in 0..4 {
        macro_rules! run { ($parameter:literal,$type:ident,$construct:ident) => {{
            let a=original::run::<baseline::$type>($parameter,index,enabled,original::$construct);
            let b=changed::run::<candidate::$type>($parameter,index,enabled,changed::$construct);
            assert_eq!(a.pk,b.pk); assert_eq!(a.sk,b.sk); assert_eq!(a.sig,b.sig);
            assert_eq!(a.row["sizes"],b.row["sizes"]);
            println!("{}",json!({"baseline":a.row,"candidate":b.row,"exact_cross_variant":true}));
        }}; }
        run!("ML-DSA-44",MlDsa44,construct44); run!("ML-DSA-65",MlDsa65,construct65); run!("ML-DSA-87",MlDsa87,construct87);
    }
}
