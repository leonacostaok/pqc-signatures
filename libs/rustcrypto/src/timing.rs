//! Contract timing loop: warm-up, then run until the budget elapsed and >= 3 calls (2 if an op takes
//! more than 5 s), cap 100 000 ops; per-op wall samples via `Instant`, process CPU via getrusage.

use std::time::{Duration, Instant};

pub fn cpu_time_ns() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as u64 * 1_000_000_000 + t.tv_usec as u64 * 1000;
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

pub struct Measured<T> {
    pub samples: Vec<u64>,
    pub iterations: u64,
    pub wall_total: u64,
    pub cpu_total: u64,
    pub out: T,
}

/// `batch` > 1 means one call performs `batch` operations (wall per op = wall per call / batch).
pub fn measure<T>(op: &(dyn Fn() -> T + Sync), budget: Duration, batch: u64) -> Measured<T> {
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
    let cap_calls = (100_000 / batch).max(1);

    let mut samples = Vec::with_capacity(1024);
    let cpu0 = cpu_time_ns();
    let t0 = Instant::now();
    let mut calls = 0u64;
    let out = loop {
        let t = Instant::now();
        let out = op();
        samples.push(t.elapsed().as_nanos() as u64 / batch);
        calls += 1;
        if (t0.elapsed() >= budget && calls >= min_calls) || calls >= cap_calls {
            break out;
        }
    };
    let wall_total = t0.elapsed().as_nanos() as u64;
    let cpu_total = cpu_time_ns() - cpu0;
    Measured { samples, iterations: calls * batch, wall_total, cpu_total, out }
}

/// (median, mean, p95, min)
pub fn stats(samples: &mut [u64]) -> (u64, u64, u64, u64) {
    samples.sort_unstable();
    let n = samples.len();
    let median = if n % 2 == 1 { samples[n / 2] } else { (samples[n / 2 - 1] + samples[n / 2]) / 2 };
    let mean = (samples.iter().map(|&x| x as u128).sum::<u128>() / n as u128) as u64;
    let p95 = samples[((n as f64 * 0.95).ceil() as usize).clamp(1, n) - 1];
    (median, mean, p95, samples[0])
}
