import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * `memory`: peak stack per operation (binary search of Thread stackSize until no StackOverflowError, after JIT
 * warm-up) and heap allocation per op (ThreadMXBean.getThreadAllocatedBytes) for every bench variant, every
 * verify stage v0 and the total_best pipeline. JVM-flag variants run in a child JVM with their flags.
 */
final class Memory {
    static final com.sun.management.ThreadMXBean TMX = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    static void main(String[] a) throws Exception {
        String out = null; boolean child = false;
        List<String> params = new ArrayList<>(), variants = null, ops = Arrays.asList("keygen", "sign", "verify", "verify-stage");
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--out": out = a[++i]; break;
                case "--params": params = Arrays.asList(a[++i].split(",")); break;
                case "--variants": variants = Arrays.asList(a[++i].split(",")); break;
                case "--ops": ops = Arrays.asList(a[++i].split(",")); break;
                case "--child": child = true; break;
                default: Bench.usage();
            }
        }
        if (out == null) Bench.usage();
        if (params.isEmpty()) for (Alg alg : Alg.ALL.values()) if (alg.byteMatch()) params.add(alg.name);
        PrintStream sink = out.equals("-") ? new PrintStream(new FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8")
                                           : new PrintStream(new FileOutputStream(out, true), true, "UTF-8");
        if (!out.equals("-")) System.setOut(System.err);

        calibrate();

        for (String pn : params) {
            Alg alg = Alg.get(pn);
            if (!alg.byteMatch()) continue;
            Variants.Inputs in = Bench.baseline(alg);
            for (String op : new String[]{"keygen", "sign", "verify"}) {
                if (!ops.contains(op)) continue;
                for (Variants.Variant v : Variants.forOp(op)) {
                    if (variants != null && !variants.contains(v.id)) continue;
                    if (v.jvmFlags != null && !child) { runChild(v.id, op, pn, sink); continue; }
                    Map<String, Object> line = header(v.id, op, pn, null, v.threads);
                    try {
                        measureVariant(v, in, line);
                    } catch (Throwable t) { line.put("match", false); line.put("error", t.toString()); System.err.println("ERROR " + v.id + " " + pn + ": " + t); }
                    emit(sink, line);
                }
            }
            if (ops.contains("verify-stage") && (variants == null || variants.stream().anyMatch(s -> s.contains("total") || s.endsWith(".v0") && !s.matches("(keygen|sign|verify)\\..*")))) {
                boolean ml = alg.family == Alg.Family.MLDSA;
                Object cx = ml ? new Stages.MlCtx(alg, in) : new Stages.SlhCtx(alg, in);
                for (String stage : ml ? Stages.ML_STAGES : Stages.SLH_STAGES) {
                    Stages.SVariant sv = Stages.variants(stage).get(0);
                    if (variants != null && !variants.contains(sv.id)) continue;
                    Stages.StageOp sop = ml ? Stages.mlOp(sv, (Stages.MlCtx) cx) : Stages.slhOp(sv, (Stages.SlhCtx) cx);
                    Map<String, Object> line = header(sv.id, "verify-stage", pn, stage, 1);
                    try {
                        byte[] expect = sop.canon(sop.run());
                        measureOp(() -> sop.run(), o -> Arrays.equals(sop.canon(o), expect), 1, false, line);
                    } catch (Throwable t) { line.put("match", false); line.put("error", t.toString()); }
                    emit(sink, line);
                }
                if (variants == null || variants.contains("total_best")) {
                    Map<String, String> comp = Stages.bestComposition(alg);
                    int threads = 1;
                    for (String id : comp.values()) threads = Math.max(threads, Stages.find(id).threads);
                    Map<String, Object> line = header("total_best", "verify-stage", pn, "total_best", threads);
                    line.put("composition", comp);
                    try {
                        bc.mldsa.MlStages ms = ml ? new bc.mldsa.MlStages(alg.mldsa) : null;
                        bc.slhdsa.SlhStages ss = ml ? null : new bc.slhdsa.SlhStages(alg.name);
                        Callable<Object> op = () -> ml ? Stages.verifyMl(ms, in.pk, in.msg, new byte[0], in.sig, comp) : Stages.verifySlh(ss, in.pk, in.msg, new byte[0], in.sig, comp);
                        measureOp(op, o -> Boolean.TRUE.equals(o), 1, threads > 1, line);
                    } catch (Throwable t) { line.put("match", false); line.put("error", t.toString()); }
                    emit(sink, line);
                }
            }
        }
        sink.flush();
        Stages.POOL.shutdownNow();
    }

    static Map<String, Object> header(String variant, String op, String param, String stage, int threads) {
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("lib", Bench.LIB); l.put("lib_version", Bench.LIB_VERSION); l.put("variant", variant); l.put("op", op); l.put("param", param);
        if (stage != null) l.put("stage", stage);
        l.put("threads", threads);
        return l;
    }

    static void emit(PrintStream sink, Map<String, Object> line) {
        sink.println(Json.write(line)); sink.flush();
        System.err.printf("%-14s %-13s %-20s stack=%s (res %s) heap/op=%s match=%s%n", line.get("variant"), line.get("op"), line.get("param"),
            line.get("stack_bytes"), line.get("stack_resolution_bytes"), line.get("heap_alloc_bytes_per_op"), line.get("match"));
    }

    interface Check { boolean ok(Object o) throws Exception; }

    /** an op instance for one probe: created on the probe thread before the recursion, closed after it */
    interface ProbeOp extends Callable<Object>, AutoCloseable { }
    interface ProbeFactory { ProbeOp create() throws Exception; }

    static ProbeOp simple(Callable<Object> c) { return new ProbeOp() { public Object call() throws Exception { return c.call(); } public void close() {} }; }

    /** bench variant: fresh Runner per probe (a StackOverflowError inside a reused engine leaves it unusable) */
    static void measureVariant(Variants.Variant v, Variants.Inputs in, Map<String, Object> line) throws Exception {
        boolean parallel = v.impl.equals("parallel");
        boolean match;
        try (Variants.Runner r = Variants.make(v, in)) {
            Object o = r.run();
            match = r.check(o) && r.tamperRejected();
            long t0 = System.nanoTime(); int n = 0;
            while ((System.nanoTime() - t0 < 1_000_000_000L || n < 20) && System.nanoTime() - t0 < 3_000_000_000L) { if (!r.check(r.run())) match = false; n++; }
        }
        line.put("match", match);
        try (Variants.Runner r = Variants.make(v, in)) {
            long[] h = heapPerOp(() -> r.run(), r.batch, parallel);
            line.put("heap_alloc_bytes_per_op", h[0]); line.put("heap_peak_bytes", null);
            line.put("heap_method", parallel ? "ThreadMXBean.getTotalThreadAllocatedBytes delta / ops (all threads)" : "ThreadMXBean.getThreadAllocatedBytes delta / ops (measuring thread)");
        }
        // stack: the op itself; for parallel variants one lane's work on the probe thread (= per-worker stack)
        ProbeFactory f = () -> {
            Variants.Runner r = Variants.make(v, in);
            return new ProbeOp() {
                public Object call() throws Exception { return parallel ? ((Variants.Parallel) r).lane(0, 0) : r.run(); }
                public void close() { r.close(); }
            };
        };
        putStack(line, stackBytes(f, isSlow(f)), (parallel ? "per worker thread (one lane's op): " : "") + STACK_METHOD);
    }

    static void measureOp(Callable<Object> op, Check check, int batch, boolean multi, Map<String, Object> line) throws Exception {
        boolean match = check.ok(op.call());
        long t0 = System.nanoTime(); int n = 0;
        while ((System.nanoTime() - t0 < 1_000_000_000L || n < 20) && System.nanoTime() - t0 < 3_000_000_000L) { if (!check.ok(op.call())) match = false; n++; }
        line.put("match", match);
        long[] h = heapPerOp(op, batch, multi);
        line.put("heap_alloc_bytes_per_op", h[0]); line.put("heap_peak_bytes", null);
        line.put("heap_method", multi ? "ThreadMXBean.getTotalThreadAllocatedBytes delta / ops (all threads)" : "ThreadMXBean.getThreadAllocatedBytes delta / ops (measuring thread)");
        ProbeFactory f = () -> simple(op);
        putStack(line, stackBytes(f, isSlow(f)), STACK_METHOD);
    }

    static boolean isSlow(ProbeFactory f) throws Exception {
        try (ProbeOp op = f.create()) { long t0 = System.nanoTime(); op.call(); return System.nanoTime() - t0 > 100_000_000L; }
    }

    static void putStack(Map<String, Object> line, long bytes, String method) {
        line.put("stack_bytes", bytes < 0 ? null : bytes);
        line.put("stack_method", method);
        line.put("stack_resolution_bytes", frameBytes);
        line.put("stack_probe_thread_bytes", PROBE_STACK);
    }

    static long[] heapPerOp(Callable<Object> op, int batch, boolean allThreads) throws Exception {
        long tid = Thread.currentThread().getId();
        long a0 = allThreads ? TMX.getTotalThreadAllocatedBytes() : TMX.getThreadAllocatedBytes(tid);
        long t0 = System.nanoTime(); long n = 0;
        while (n < 10 || System.nanoTime() - t0 < 300_000_000L) { op.call(); n += batch; if (n >= 20000) break; }
        long a1 = allThreads ? TMX.getTotalThreadAllocatedBytes() : TMX.getThreadAllocatedBytes(tid);
        return new long[]{(a1 - a0) / n};
    }

    // ------------------------------------------------------------------ stack: pre-consumed recursion depth
    //
    // HotSpot silently raises a Thread stackSize below its internal minimum (~ guard + shadow zones + a few pages),
    // so a plain binary search over stackSize bottoms out at that minimum for every op. Instead a probe thread of
    // fixed size first recurses d frames of a constant-size method and then calls the op; the deepest d that still
    // completes (binary search, StackOverflowError = too deep) is found for the op and for a no-op, and
    // stack(op) = (d_noop - d_op) * frameBytes. frameBytes is calibrated from the no-op depths at two thread sizes.

    static final long PROBE_STACK = 2L << 20;
    static double frameBytes = -1;
    static int depthNoop = -1;
    static final Callable<Object> NOOP = () -> null;

    static void rec(int d, int target, Callable<Object> op) throws Exception {
        if (d == target) { op.call(); return; }
        rec(d + 1, target, op);
    }

    static boolean probe(ProbeFactory f, long stackSize, int depth) throws Exception {
        final Throwable[] err = new Throwable[1];
        Thread t = new Thread(null, () -> { try (ProbeOp op = f.create()) { rec(0, depth, op); } catch (Throwable x) { err[0] = x; } }, "stack-probe", stackSize);
        t.start(); t.join();
        if (err[0] == null) return true;
        if (isSOE(err[0])) return false;
        throw new RuntimeException("probe failed with " + err[0], err[0]);
    }

    static boolean isSOE(Throwable t) {
        for (Throwable x = t; x != null; x = x.getCause()) if (x instanceof StackOverflowError) return true;
        return false;
    }

    /** deepest recursion depth at which op still completes on a thread of the given stack size */
    static int maxDepth(ProbeFactory f, long stackSize) throws Exception {
        int lo = 0, hi = depthNoop > 0 ? depthNoop + 1 : 1 << 22;   // lo works, hi does not
        if (!probe(f, stackSize, 0)) return -1;
        while (probe(f, stackSize, hi)) hi <<= 1;
        while (hi - lo > 1) { int mid = (lo + hi) >>> 1; if (probe(f, stackSize, mid)) lo = mid; else hi = mid; }
        return lo;
    }

    static void calibrate() throws Exception {
        // warm the recursion method into compiled code with a constant frame layout
        for (int i = 0; i < 3000; i++) rec(0, 2000, NOOP);
        ProbeFactory noop = () -> simple(NOOP);
        int d1 = maxDepth(noop, PROBE_STACK), d2 = maxDepth(noop, 2 * PROBE_STACK);
        frameBytes = (double) PROBE_STACK / (d2 - d1);
        depthNoop = Math.max(d1, maxDepth(noop, PROBE_STACK));   // re-measure after warm-up/compilation settled
        System.err.printf("stack calibration: frame = %.1f bytes (depth %d @ %d KiB, %d @ %d KiB), no-op depth %d%n", frameBytes, d1, PROBE_STACK >> 10, d2, PROBE_STACK >> 9, depthNoop);
    }

    /**
     * stack bytes used by one op beyond the probe frame, or -1 if the op never completes on the probe thread.
     * The op is first warmed through the exact probe call path (so no JIT deoptimisation happens mid-probe), and
     * the search is repeated (3x, or once for ops slower than 100 ms) taking the deepest success.
     */
    static long stackBytes(ProbeFactory f, boolean slow) throws Exception {
        if (frameBytes < 0) calibrate();
        try (ProbeOp op = f.create()) {
            long t0 = System.nanoTime(); int n = 0;
            while ((System.nanoTime() - t0 < 500_000_000L || n < 10) && System.nanoTime() - t0 < 2_000_000_000L) { op.call(); n++; }
        }
        int best = -1;
        for (int i = 0; i < (slow ? 1 : 3); i++) best = Math.max(best, maxDepth(f, PROBE_STACK));
        if (best < 0) return -1;
        return Math.round(Math.max(0, depthNoop - best) * frameBytes);
    }

    static final String STACK_METHOD = "probe thread (2 MiB) recurses d constant-size frames then runs the op; deepest d without StackOverflowError (binary search, best of 3, after JIT warm-up through the same path) vs a no-op, times the calibrated frame size";

    static void runChild(String id, String op, String param, PrintStream sink) throws Exception {
        Variants.Variant v = null;
        for (Variants.Variant x : Variants.forOp(op)) if (x.id.equals(id)) v = x;
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>();
        cmd.add(java); cmd.addAll(Arrays.asList(v.jvmFlags));
        cmd.add("-Dpqc.common=" + Bench.COMMON);
        cmd.add("-cp"); cmd.add(System.getProperty("pqc.classpath", System.getProperty("java.class.path")));
        cmd.add("Bench"); cmd.add("memory"); cmd.add("--child"); cmd.add("--out"); cmd.add("-");
        cmd.add("--ops"); cmd.add(op); cmd.add("--variants"); cmd.add(id); cmd.add("--params"); cmd.add(param);
        System.err.println("[child] " + String.join(" ", cmd));
        Process p = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) if (l.startsWith("{")) { sink.println(l); sink.flush(); }
        }
        int rc = p.waitFor();
        if (rc != 0) System.err.println("[child] " + id + " exited with " + rc);
    }
}
