//! `memory` subcommand (Phase 2 section C): peak stack per operation measured by running the op on a
//! thread whose stack we allocate (mmap) and paint with 0xA5 (`pthread_attr_setstack`), then scanning
//! for the lowest overwritten byte; heap via the counting global allocator in main.rs.

use crate::heap;
use crate::schemes::Scheme;
use serde::Serialize;
use std::ffi::c_void;
use std::io::Write;

const STACK_SIZE: usize = 32 << 20;
const PATTERN: u8 = 0xA5;
pub const RESOLUTION: u64 = 16;

struct Payload<F, R> {
    f: Option<F>,
    r: Option<R>,
    heap: (u64, u64),
}

extern "C" fn trampoline<F: FnOnce() -> R, R>(p: *mut c_void) -> *mut c_void {
    // SAFETY: p points at a Payload<F, R> that outlives the thread (joined before it is dropped).
    let p = unsafe { &mut *(p as *mut Payload<F, R>) };
    let f = p.f.take().expect("closure");
    heap::start();
    let r = f();
    p.heap = heap::stop();
    p.r = Some(r);
    std::ptr::null_mut()
}

/// Returns (result, stack bytes touched below the thread's initial frames, heap (alloc_total, peak_live)).
pub fn run_painted<F: FnOnce() -> R + Send, R: Send>(f: F) -> (R, usize, (u64, u64)) {
    unsafe {
        let mem = libc::mmap(std::ptr::null_mut(), STACK_SIZE, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
        assert!(mem != libc::MAP_FAILED, "mmap stack");
        libc::memset(mem, PATTERN as i32, STACK_SIZE);
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        libc::pthread_attr_init(&mut attr);
        assert_eq!(libc::pthread_attr_setstack(&mut attr, mem, STACK_SIZE), 0, "setstack");
        let mut payload = Payload::<F, R> { f: Some(f), r: None, heap: (0, 0) };
        let mut tid: libc::pthread_t = 0;
        let rc = libc::pthread_create(&mut tid, &attr, trampoline::<F, R>, &mut payload as *mut _ as *mut c_void);
        assert_eq!(rc, 0, "pthread_create");
        libc::pthread_join(tid, std::ptr::null_mut());
        libc::pthread_attr_destroy(&mut attr);
        let slice = std::slice::from_raw_parts(mem as *const u8, STACK_SIZE);
        // scan upwards in 8-byte words for the first word that is not the pattern
        let words = std::slice::from_raw_parts(mem as *const u64, STACK_SIZE / 8);
        let pat = u64::from_ne_bytes([PATTERN; 8]);
        let first_word = words.iter().position(|&w| w != pat).unwrap_or(words.len());
        let mut first = first_word * 8;
        while first < STACK_SIZE && slice[first] == PATTERN {
            first += 1;
        }
        let used = STACK_SIZE - first;
        let r = payload.r.take().expect("thread result");
        let heap = payload.heap;
        libc::munmap(mem, STACK_SIZE);
        (r, used, heap)
    }
}

/// Stack bytes used by the thread machinery alone (TLS block at the top of a user stack, start frames).
pub fn baseline() -> usize {
    let mut b = usize::MAX;
    for _ in 0..3 {
        let (_, used, _) = run_painted(|| std::hint::black_box(0u8));
        b = b.min(used);
    }
    b
}

#[derive(Serialize)]
struct MemLine<'a> {
    lib: &'a str,
    variant: &'a str,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'a str>,
    param: &'a str,
    stack_bytes: u64,
    stack_method: &'a str,
    stack_resolution_bytes: u64,
    heap_alloc_bytes_per_op: u64,
    heap_peak_bytes: u64,
    heap_method: &'a str,
    threads: usize,
    #[serde(rename = "match")]
    matched: bool,
}

const STACK_METHOD: &str = "painted mmap stack (pthread_attr_setstack, 0xA5 fill), lowest overwritten byte, minus empty-closure baseline on the same kind of thread; peak of one op";
const HEAP_METHOD: &str = "counting GlobalAlloc wrapper (System or mimalloc): bytes allocated during the op and peak live bytes above the level at op start";

pub struct MemOpts {
    pub out: String,
    pub params: Option<Vec<String>>,
}

pub fn cmd_memory(o: MemOpts) {
    let c = crate::load_common();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let base = baseline();
    eprintln!("stack baseline (thread bookkeeping) = {base} bytes");
    let mut outf = std::fs::OpenOptions::new().create(true).append(true).open(&o.out).expect("open --out");
    let mut emit = |variant: &str, op: &str, stage: Option<&str>, param: &str, used: usize, heap: (u64, u64), thr: usize, matched: bool| {
        let line = MemLine {
            lib: crate::LIB,
            variant,
            op,
            stage,
            param,
            stack_bytes: used.saturating_sub(base) as u64,
            stack_method: STACK_METHOD,
            stack_resolution_bytes: RESOLUTION,
            heap_alloc_bytes_per_op: heap.0,
            heap_peak_bytes: heap.1,
            heap_method: HEAP_METHOD,
            threads: thr,
            matched,
        };
        writeln!(outf, "{}", serde_json::to_string(&line).unwrap()).expect("write");
        eprintln!("{:16} {:22} stack={:>8} heap_alloc={:>9} heap_peak={:>9} match={}", variant, param, line.stack_bytes, heap.0, heap.1, matched);
    };

    for s in crate::schemes::all_schemes() {
        let name = s.name();
        if o.params.as_ref().is_some_and(|ps| !ps.iter().any(|x| x == name)) {
            continue;
        }
        let Some(seed) = c.seeds.get(name) else { continue };
        let Some(r) = c.reference.get(name) else { continue };
        let sref: &dyn Scheme = &*s;
        let (pk, sk) = sref.keygen(seed);
        let sig = sref.sign(&sk, &c.msg);
        let msg = &c.msg;
        let mut tampered = sig.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 1;

        // process variants of this binary; par variants: one worker's item (threads reported)
        for v in crate::V.iter().filter(|v| v.tag == crate::BUILD_TAG) {
            let thr = if v.kind == crate::Kind::Par { threads } else { 1 };
            let (used, heap, matched) = match (v.op, v.kind) {
                ("keygen", _) => {
                    let (out, used, heap) = run_painted(|| sref.keygen(seed));
                    (used, heap, crate::sha256_hex(&out.0) == r.pk_sha256 && crate::sha256_hex(&out.1) == r.sk_sha256)
                }
                ("sign", crate::Kind::KeyCache) => {
                    let f = sref.cached_signer(&sk);
                    let (out, used, heap) = run_painted(|| f(msg));
                    (used, heap, crate::sha256_hex(&out) == r.sig_sha256)
                }
                ("sign", _) => {
                    let (out, used, heap) = run_painted(|| sref.sign(&sk, msg));
                    (used, heap, crate::sha256_hex(&out) == r.sig_sha256)
                }
                ("verify", crate::Kind::KeyCache) => {
                    let f = sref.cached_verifier(&pk);
                    let (out, used, heap) = run_painted(|| f(msg, &sig));
                    (used, heap, out && !f(msg, &tampered))
                }
                _ => {
                    let (out, used, heap) = run_painted(|| sref.verify(&pk, msg, &sig));
                    (used, heap, out && !sref.verify(&pk, msg, &tampered))
                }
            };
            emit(v.id, v.op, None, name, used, heap, thr, matched);
        }

        // verify stages (v0) + total pipelines: base binary only
        if crate::BUILD_TAG == "base" {
            for (stage, variant, op) in sref.stage_memory_ops(msg, seed) {
                let (ok, used, heap) = run_painted(|| op());
                emit(&variant, "verify-stage", Some(&stage), name, used, heap, 1, ok);
            }
        }
    }
}
