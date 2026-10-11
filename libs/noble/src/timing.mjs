// Timing core shared by the single-thread and worker runners (CONTRACT.md "Timing method").
const now = () => process.hrtime.bigint(); // ns, monotonic
export const cpuNs = () => {
  const u = process.cpuUsage(); // microseconds, user + system, whole process (all threads)
  return (u.user + u.system) * 1000;
};
export const WARMUP_MIN_MS = 200;
export const WARMUP_MIN_OPS = 20;
export const WARMUP_CAP_MS = 3000; // slow ops: still at least 1 op
export const MAX_ITERS = 100000;

// Runs `fn` (returns the op output) with the warm-up / budget rules; `check(out, i)` is called
// outside the timed region and must throw on a wrong result. Returns stats in ns.
export function measureSingle(fn, check, budgetMs) {
  // warm-up
  {
    const t0 = now();
    let n = 0;
    do {
      check(fn(), -1);
      n++;
    } while ((n < WARMUP_MIN_OPS || Number(now() - t0) / 1e6 < WARMUP_MIN_MS) && Number(now() - t0) / 1e6 < WARMUP_CAP_MS);
  }
  const times = [];
  const cpu0 = cpuNs();
  const loopStart = now();
  let minOps = 3;
  for (;;) {
    const s = now();
    const out = fn();
    const e = now();
    const dt = Number(e - s);
    times.push(dt);
    check(out, times.length - 1);
    if (times.length === 1 && dt > 5e9) minOps = 2;
    const elapsedMs = Number(now() - loopStart) / 1e6;
    if ((elapsedMs >= budgetMs && times.length >= minOps) || times.length >= MAX_ITERS) break;
  }
  const loopWall = Number(now() - loopStart);
  const cpu = cpuNs() - cpu0;
  return finish(times, loopWall, cpu, times.length, 1);
}

export function finish(perOpNs, loopWallNs, cpuNs_, ops, threads) {
  const sorted = Float64Array.from(perOpNs).sort();
  const q = (p) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
  const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
  return {
    iterations: ops,
    threads,
    wall_ns_median: Math.round(q(0.5)),
    wall_ns_mean: Math.round(mean),
    wall_ns_p95: Math.round(q(0.95)),
    wall_ns_min: Math.round(sorted[0]),
    cpu_ns_per_op: Math.round(cpuNs_ / ops),
    cpu_util: +(cpuNs_ / loopWallNs).toFixed(3),
    ops_per_sec: +((ops * 1e9) / loopWallNs).toFixed(3),
  };
}

// async flavour (worker-parallel stage alternatives): identical rules, fn returns a promise.
export async function measureAsync(fn, check, budgetMs) {
  {
    const t0 = now();
    let n = 0;
    do {
      check(await fn(), -1);
      n++;
    } while ((n < WARMUP_MIN_OPS || Number(now() - t0) / 1e6 < WARMUP_MIN_MS) && Number(now() - t0) / 1e6 < WARMUP_CAP_MS);
  }
  const times = [];
  const cpu0 = cpuNs();
  const loopStart = now();
  let minOps = 3;
  for (;;) {
    const s = now();
    const out = await fn();
    const e = now();
    const dt = Number(e - s);
    times.push(dt);
    check(out, times.length - 1);
    if (times.length === 1 && dt > 5e9) minOps = 2;
    const elapsedMs = Number(now() - loopStart) / 1e6;
    if ((elapsedMs >= budgetMs && times.length >= minOps) || times.length >= MAX_ITERS) break;
  }
  const loopWall = Number(now() - loopStart);
  const cpu = cpuNs() - cpu0;
  return finish(times, loopWall, cpu, times.length, 1);
}
