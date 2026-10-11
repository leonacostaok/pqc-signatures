import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/** Shared warm-up + measured-loop logic (same policy as Bench.measure) for the stage and memory drivers. */
final class Timing {
    static long cpuNow() {
        return ((com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean()).getProcessCpuTime();
    }

    interface Check { boolean ok(Object out) throws Exception; }

    static final class Stats {
        long n, ops, cpu, wallTotal; long[] wall; boolean match = true; int batch = 1;
        void put(Map<String, Object> line) {
            Arrays.sort(wall);
            int k = (int) n;
            line.put("iterations", ops);
            line.put("wall_ns_median", k == 0 ? 0 : wall[k / 2]);
            line.put("wall_ns_mean", k == 0 ? 0 : Arrays.stream(wall).sum() / k);
            line.put("wall_ns_p95", k == 0 ? 0 : wall[Math.min(k - 1, Math.max(0, (int) Math.ceil(0.95 * k) - 1))]);
            line.put("wall_ns_min", k == 0 ? 0 : wall[0]);
            line.put("cpu_ns_per_op", ops == 0 ? 0 : cpu / ops);
            line.put("cpu_util", wallTotal == 0 ? 0.0 : (double) cpu / wallTotal);
            line.put("ops_per_sec", wallTotal == 0 ? 0.0 : ops * 1e9 / wallTotal);
        }
    }

    /**
     * Warm-up: >= 1 s and >= 20 ops, capped at 3 s. Measured: until budget and >= 3 ops (2 if an op > 5 s), cap 100000.
     * `check` is applied to the first warm-up output and to every measured output (outside the timed region).
     */
    static Stats measure(Callable<Object> op, int batch, long budgetMs, Check check) throws Exception {
        Stats st = new Stats();
        st.batch = batch;
        long ws = System.nanoTime(); int wn = 0; boolean first = true;
        while (true) {
            Object o = op.call(); wn += batch;
            if (first) { first = false; if (!check.ok(o)) st.match = false; }
            long el = System.nanoTime() - ws;
            if ((el >= 1_000_000_000L && wn >= 20) || el >= 3_000_000_000L) break;
        }
        long[] samples = new long[1024];
        int n = 0; long maxOp = 0;
        long budget = budgetMs * 1_000_000L;
        long cpu0 = cpuNow();
        long start = System.nanoTime();
        while (true) {
            long t0 = System.nanoTime();
            Object o = op.call();
            long t1 = System.nanoTime();
            if (n == samples.length) samples = Arrays.copyOf(samples, n * 2);
            samples[n++] = (t1 - t0) / batch;
            maxOp = Math.max(maxOp, t1 - t0);
            if (!check.ok(o)) st.match = false;
            long el = t1 - start;
            int minOps = maxOp > 5_000_000_000L ? 2 : 3;
            if ((el >= budget && (long) n * batch >= minOps) || (long) n * batch >= 100000) break;
        }
        st.wallTotal = System.nanoTime() - start;
        st.cpu = cpuNow() - cpu0;
        st.wall = Arrays.copyOf(samples, n);
        st.n = n; st.ops = (long) n * batch;
        return st;
    }

    static Map<String, Object> baseLine(String variant, String name, String desc) {
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("lib", Bench.LIB); l.put("lib_version", Bench.LIB_VERSION); l.put("lang", "java"); l.put("runtime", Bench.RUNTIME);
        l.put("variant", variant); l.put("variant_name", name); l.put("variant_desc", desc);
        return l;
    }
}
