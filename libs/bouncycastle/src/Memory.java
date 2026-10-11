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
    static final long RES = 4096;           // search resolution (one page; HotSpot rounds stack sizes to pages)
    static final long MAX = 64L << 20;      // search upper bound
    static long baselineStack = -1;         // smallest stack a no-op thread needs (JVM guard/shadow zones)

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

        baselineStack = minStack(() -> null, false);
        System.err.println("baseline (no-op thread) minimum stack: " + baselineStack + " bytes");

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
        System.err.printf("%-14s %-13s %-20s stack=%s (raw %s) heap/op=%s match=%s%n", line.get("variant"), line.get("op"), line.get("param"),
            line.get("stack_bytes"), line.get("stack_bytes_raw"), line.get("heap_alloc_bytes_per_op"), line.get("match"));
    }

    interface Check { boolean ok(Object o) throws Exception; }

    /** bench variant: a fresh Runner per stack probe (parallel runners get their lane stack size from Variants.Parallel.STACK) */
    static void measureVariant(Variants.Variant v, Variants.Inputs in, Map<String, Object> line) throws Exception {
        boolean parallel = v.impl.equals("parallel");
        // JIT warm-up on a normal thread, and correctness
        boolean match;
        try (Variants.Runner r = Variants.make(v, in)) {
            Object o = r.run();
            match = r.check(o) && r.tamperRejected();
            long t0 = System.nanoTime(); int n = 0;
            while ((System.nanoTime() - t0 < 1_000_000_000L || n < 20) && System.nanoTime() - t0 < 3_000_000_000L) { if (!r.check(r.run())) match = false; n++; }
        }
        line.put("match", match);
        // heap: allocated bytes per op on the measuring thread (parallel: all threads)
        try (Variants.Runner r = Variants.make(v, in)) {
            long[] h = heapPerOp(() -> r.run(), r.batch, parallel);
            line.put("heap_alloc_bytes_per_op", h[0]); line.put("heap_peak_bytes", null);
            line.put("heap_method", parallel ? "ThreadMXBean.getTotalThreadAllocatedBytes delta / ops (all threads)" : "ThreadMXBean.getThreadAllocatedBytes delta / ops (measuring thread)");
        }
        // stack
        long raw;
        if (parallel) {
            raw = minStackParallel(v, in);
        } else {
            raw = minStack(() -> { try (Variants.Runner r = Variants.make(v, in)) { return r.run(); } }, true);
        }
        putStack(line, raw, parallel ? "per worker thread: Thread(stackSize) of the pool's lanes binary-searched until the batch completes without StackOverflowError (after JIT warm-up)"
                                     : "Thread(stackSize) binary search until the op completes without StackOverflowError (after JIT warm-up); minus the JVM's no-op thread minimum");
    }

    static void measureOp(Callable<Object> op, Check check, int batch, boolean multi, Map<String, Object> line) throws Exception {
        boolean match = check.ok(op.call());
        long t0 = System.nanoTime(); int n = 0;
        while ((System.nanoTime() - t0 < 1_000_000_000L || n < 20) && System.nanoTime() - t0 < 3_000_000_000L) { if (!check.ok(op.call())) match = false; n++; }
        line.put("match", match);
        long[] h = heapPerOp(op, batch, multi);
        line.put("heap_alloc_bytes_per_op", h[0]); line.put("heap_peak_bytes", null);
        line.put("heap_method", multi ? "ThreadMXBean.getTotalThreadAllocatedBytes delta / ops (all threads)" : "ThreadMXBean.getThreadAllocatedBytes delta / ops (measuring thread)");
        long raw = minStack(op, true);
        putStack(line, raw, "Thread(stackSize) binary search until the op completes without StackOverflowError (after JIT warm-up); minus the JVM's no-op thread minimum");
    }

    static void putStack(Map<String, Object> line, long raw, String method) {
        line.put("stack_bytes", raw < 0 ? null : Math.max(0, raw - baselineStack));
        line.put("stack_bytes_raw", raw < 0 ? null : raw);
        line.put("stack_baseline_bytes", baselineStack);
        line.put("stack_method", method);
        line.put("stack_resolution_bytes", RES);
    }

    static long[] heapPerOp(Callable<Object> op, int batch, boolean allThreads) throws Exception {
        long tid = Thread.currentThread().getId();
        long a0 = allThreads ? TMX.getTotalThreadAllocatedBytes() : TMX.getThreadAllocatedBytes(tid);
        long t0 = System.nanoTime(); long n = 0;
        while (n < 10 || System.nanoTime() - t0 < 300_000_000L) { op.call(); n += batch; if (n >= 20000) break; }
        long a1 = allThreads ? TMX.getTotalThreadAllocatedBytes() : TMX.getThreadAllocatedBytes(tid);
        return new long[]{(a1 - a0) / n};
    }

    /** smallest Thread stackSize (multiple of RES) for which op completes without StackOverflowError; -1 if it never does */
    static long minStack(Callable<Object> op, boolean requireSuccessAtMax) throws Exception {
        if (!probe(op, MAX)) return -1;
        long lo = 0, hi = MAX;                 // invariant: hi works, lo does not (or is 0)
        while (hi - lo > RES) {
            long mid = ((lo + hi) / 2 / RES) * RES;
            if (probe(op, mid)) hi = mid; else lo = mid;
        }
        return hi;
    }

    static boolean probe(Callable<Object> op, long stackSize) throws Exception {
        final Throwable[] err = new Throwable[1];
        Thread t = new Thread(null, () -> { try { op.call(); } catch (Throwable x) { err[0] = x; } }, "stack-probe", stackSize);
        t.start(); t.join();
        if (err[0] == null) return true;
        if (isSOE(err[0])) return false;
        throw new RuntimeException("probe failed with " + err[0], err[0]);
    }

    static boolean isSOE(Throwable t) {
        for (Throwable x = t; x != null; x = x.getCause()) if (x instanceof StackOverflowError) return true;
        return false;
    }

    static long minStackParallel(Variants.Variant v, Variants.Inputs in) throws Exception {
        Callable<Object> probeAt = () -> { try (Variants.Runner r = Variants.make(v, in)) { return r.run(); } };
        long lo = 0, hi = MAX;
        Variants.Parallel.STACK = MAX;
        try { probeAt.call(); } catch (Throwable t) { Variants.Parallel.STACK = 0; return -1; }
        while (hi - lo > RES) {
            long mid = ((lo + hi) / 2 / RES) * RES;
            Variants.Parallel.STACK = mid;
            boolean ok;
            try { probeAt.call(); ok = true; } catch (Throwable t) { if (isSOE(t)) ok = false; else throw new RuntimeException(t); }
            if (ok) hi = mid; else lo = mid;
        }
        Variants.Parallel.STACK = 0;
        return hi;
    }

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
