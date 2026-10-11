import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;

/**
 * Entry point: vectors / crossverify / bench (see common/CONTRACT.md).
 * System properties: pqc.common (dir with vectors.json + reference.json), pqc.classpath (for child JVMs).
 */
public final class Bench {
    static final String LIB = "bouncycastle";
    static final String LIB_VERSION = Alg.BC.getVersionStr();
    static final String RUNTIME = "openjdk " + System.getProperty("java.version") + " (" + System.getProperty("java.vm.name") + ")";
    static final String COMMON = System.getProperty("pqc.common", "common");

    static Map<String, Object> vectors;
    static Map<String, Object> reference;
    static byte[] message;

    public static void main(String[] args) throws Exception {
        vectors = Json.obj(Json.parse(Files.readString(Paths.get(COMMON, "vectors.json"))));
        reference = Json.obj(Json.parse(Files.readString(Paths.get(COMMON, "reference.json"))));
        message = Alg.unhex((String) vectors.get("message_hex"));
        if (args.length == 0) usage();
        switch (args[0]) {
            case "vectors": vectors(args[1]); break;
            case "crossverify": crossverify(args[1], args[2]); break;
            case "bench": bench(Arrays.copyOfRange(args, 1, args.length)); break;
            default: usage();
        }
    }

    static void usage() {
        System.err.println("usage: Bench vectors <out.json> | crossverify <artifacts.json> <out.json> | bench --out <f> [--budget-ms N] [--params a,b] [--ops o,o] [--variants id,id]");
        System.exit(2);
    }

    static List<Map<String, Object>> paramEntries() {
        List<Map<String, Object>> l = new ArrayList<>();
        for (Object o : Json.arr(vectors.get("params"))) l.add(Json.obj(o));
        return l;
    }
    static byte[] seedOf(String param) {
        for (Map<String, Object> p : paramEntries()) if (p.get("name").equals(param)) return Alg.unhex((String) p.get("seed_hex"));
        throw new IllegalArgumentException("no seed for " + param);
    }

    // ------------------------------------------------------------------ baseline keygen+sign+verify for one param

    /** Baseline (JCA, variant v0 code path) artifacts; byte-matchable params are checked against reference.json. */
    static Variants.Inputs baseline(Alg alg) throws Exception {
        byte[] seed = seedOf(alg.name);
        byte[] pk, sk, sig;
        if (alg.family == Alg.Family.FALCON) {
            FalconKeyPairGenerator g = new FalconKeyPairGenerator();
            g.init(new FalconKeyGenerationParameters(new Alg.ShakeRandom(seed), alg.falcon));
            AsymmetricCipherKeyPair kp = g.generateKeyPair();
            pk = Alg.pubBytes(kp); sk = Alg.privBytes(kp);
            FalconSigner s = new FalconSigner();
            s.init(true, new ParametersWithRandom(kp.getPrivate(), new Alg.ShakeRandom(Arrays.copyOf(seed, 16))));
            sig = alg.falconPadSig(s.generateSignature(message));
        } else {
            java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance(alg.jcaAlg, "BC");
            g.initialize(alg.jcaSpec, new Alg.SeedRandom(seed));
            java.security.KeyPair kp = g.generateKeyPair();
            pk = Variants.keygenPk(kp); sk = Variants.keygenSk(kp);
            java.security.Signature s = java.security.Signature.getInstance(alg.jcaAlg, "BC");
            s.initSign(kp.getPrivate());
            s.update(message);
            sig = s.sign();
        }
        return new Variants.Inputs(alg, seed, message, pk, sk, sig);
    }

    static boolean baselineVerify(Alg alg, byte[] pk, byte[] msg, byte[] sig) throws Exception {
        if (alg.family == Alg.Family.FALCON) return Variants.llVerify(alg, alg.pubFromBytes(pk), msg, sig);
        java.security.Signature s = java.security.Signature.getInstance(alg.jcaAlg, "BC");
        s.initVerify(alg.jcaPublic(pk));
        s.update(msg);
        return s.verify(sig);
    }

    /** Returns null if the inputs match reference.json, else a description of the mismatch. */
    static String refMismatch(Variants.Inputs in) {
        if (!in.alg.byteMatch()) return null;
        Map<String, Object> r = Json.obj(reference.get(in.alg.name));
        if (r == null) return "no reference entry";
        StringBuilder b = new StringBuilder();
        if (!r.get("pk_sha256").equals(Alg.sha256Hex(in.pk))) b.append("pk ");
        if (!r.get("sk_sha256").equals(Alg.sha256Hex(in.sk))) b.append("sk ");
        if (!r.get("sig_sha256").equals(Alg.sha256Hex(in.sig))) b.append("sig ");
        return b.length() == 0 ? null : b.toString().trim() + " digest mismatch";
    }

    // ------------------------------------------------------------------ vectors

    static void vectors(String outFile) throws Exception {
        List<Object> entries = new ArrayList<>();
        int bad = 0;
        for (Map<String, Object> p : paramEntries()) {
            Alg alg = Alg.ALL.get((String) p.get("name"));
            if (alg == null) continue;
            Variants.Inputs in = baseline(alg);
            boolean selfOk = baselineVerify(alg, in.pk, message, in.sig) && !baselineVerify(alg, in.pk, message, in.tamperedSig());
            String mm = refMismatch(in);
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("param", alg.name);
            e.put("pk_hex", Alg.hex(in.pk));
            e.put("sig_hex", Alg.hex(in.sig));
            e.put("sk_sha256", Alg.sha256Hex(in.sk));
            e.put("pk_sha256", Alg.sha256Hex(in.pk));
            e.put("sig_sha256", Alg.sha256Hex(in.sig));
            e.put("self_verify", selfOk);
            e.put("byte_match", alg.byteMatch() ? (Object) (mm == null) : null);
            entries.add(e);
            System.err.printf("%-20s pk=%5d sk=%5d sig=%5d self_verify=%s %s%n", alg.name, in.pk.length, in.sk.length, in.sig.length, selfOk,
                alg.byteMatch() ? (mm == null ? "MATCH reference" : "MISMATCH: " + mm) : "(no byte match expected)");
            if (!selfOk || mm != null) bad++;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("lib", LIB); out.put("lib_version", LIB_VERSION); out.put("entries", entries);
        Files.writeString(Paths.get(outFile), Json.write(out) + "\n");
        if (bad != 0) { System.err.println(bad + " param(s) failed"); System.exit(1); }
    }

    // ------------------------------------------------------------------ crossverify

    static void crossverify(String artifactsFile, String outFile) throws Exception {
        Map<String, Object> art = Json.obj(Json.parse(Files.readString(Paths.get(artifactsFile))));
        List<Object> results = new ArrayList<>();
        int fail = 0;
        for (Object o : Json.arr(art.get("entries"))) {
            Map<String, Object> e = Json.obj(o);
            Alg alg = Alg.ALL.get((String) e.get("param"));
            if (alg == null) continue; // unsupported: skipped
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("param", alg.name);
            try {
                byte[] pk = Alg.unhex((String) e.get("pk_hex"));
                byte[] sig = Alg.unhex((String) e.get("sig_hex"));
                boolean ok = baselineVerify(alg, pk, message, sig);
                byte[] bad = sig.clone(); bad[bad.length / 2] ^= 0x01;
                boolean tamperRejected;
                try { tamperRejected = !baselineVerify(alg, pk, message, bad); }
                catch (Exception ex) { tamperRejected = true; } // a decode error on a corrupted sig is a rejection
                r.put("ok", ok); r.put("error", null); r.put("tamper_rejected", tamperRejected);
                if (!ok || !tamperRejected) fail++;
            } catch (Exception ex) {
                r.put("ok", false); r.put("error", ex.toString()); r.put("tamper_rejected", null);
                fail++;
            }
            System.err.println(alg.name + " " + r);
            results.add(r);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("lib", LIB); out.put("source", art.get("lib")); out.put("results", results);
        Files.writeString(Paths.get(outFile), Json.write(out) + "\n");
        System.err.println(results.size() + " entries verified, " + fail + " failures");
    }

    // ------------------------------------------------------------------ bench

    static void bench(String[] a) throws Exception {
        String out = null; long budget = 1000; boolean child = false;
        List<String> params = new ArrayList<>(), ops = Arrays.asList("keygen", "sign", "verify"), variants = null;
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--out": out = a[++i]; break;
                case "--budget-ms": budget = Long.parseLong(a[++i]); break;
                case "--params": params = Arrays.asList(a[++i].split(",")); break;
                case "--ops": ops = Arrays.asList(a[++i].split(",")); break;
                case "--variants": variants = Arrays.asList(a[++i].split(",")); break;
                case "--child": child = true; break;
                default: usage();
            }
        }
        if (out == null) usage();
        if (params.isEmpty()) {
            for (Map<String, Object> p : paramEntries())
                if (Boolean.TRUE.equals(p.get("byte_match_expected")) && Alg.ALL.containsKey((String) p.get("name"))) params.add((String) p.get("name"));
        }
        PrintStream sink = out.equals("-") ? new PrintStream(new FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8")
                                           : new PrintStream(new FileOutputStream(out, true), true, "UTF-8");
        if (!out.equals("-")) System.setOut(System.err); // keep stdout clean of anything but JSON when piped

        for (String op : ops) {
            for (Variants.Variant v : Variants.forOp(op)) {
                if (variants != null && !variants.contains(v.id)) continue;
                if (v.jvmFlags != null && !child) {
                    runChild(v, params, budget, sink);
                    continue;
                }
                for (String pn : params) {
                    Alg alg = Alg.get(pn);
                    if (!alg.byteMatch()) continue;
                    Map<String, Object> line = measure(v, alg, budget);
                    sink.println(Json.write(line));
                    sink.flush();
                }
            }
        }
        sink.flush();
    }

    /** Runs the given variant for all params in a child JVM with the variant's flags; forwards its JSON lines. */
    static void runChild(Variants.Variant v, List<String> params, long budget, PrintStream sink) throws Exception {
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>();
        cmd.add(java);
        cmd.addAll(Arrays.asList(v.jvmFlags));
        cmd.add("-Dpqc.common=" + COMMON);
        cmd.add("-cp"); cmd.add(System.getProperty("pqc.classpath", System.getProperty("java.class.path")));
        cmd.add("Bench"); cmd.add("bench"); cmd.add("--child"); cmd.add("--out"); cmd.add("-");
        cmd.add("--budget-ms"); cmd.add(Long.toString(budget));
        cmd.add("--ops"); cmd.add(v.op);
        cmd.add("--variants"); cmd.add(v.id);
        cmd.add("--params"); cmd.add(String.join(",", params));
        System.err.println("[child] " + String.join(" ", cmd));
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.INHERIT);
        Process p = pb.start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) if (l.startsWith("{")) { sink.println(l); sink.flush(); }
        }
        int rc = p.waitFor();
        if (rc != 0) System.err.println("[child] " + v.id + " exited with " + rc);
    }

    static long cpuNow() {
        return ((com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean()).getProcessCpuTime();
    }

    static final boolean EPSILON_GUARD = ManagementFactory.getGarbageCollectorMXBeans().stream().anyMatch(g -> g.getName().contains("Epsilon"));
    static boolean heapNearlyFull(double frac) {
        Runtime rt = Runtime.getRuntime();
        return (rt.totalMemory() - rt.freeMemory()) > frac * rt.maxMemory();
    }

    static Map<String, Object> measure(Variants.Variant v, Alg alg, long budgetMs) throws Exception {
        Variants.Inputs in = baseline(alg);
        String mm = refMismatch(in);
        boolean match = mm == null;
        if (!match) System.err.println("WARNING baseline for " + alg.name + ": " + mm);
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("lib", LIB); line.put("lib_version", LIB_VERSION); line.put("lang", "java"); line.put("runtime", RUNTIME);
        line.put("variant", v.id); line.put("variant_name", v.name); line.put("variant_desc", v.desc);
        line.put("op", v.op); line.put("param", alg.name);
        String digest = "";
        long[] wall = new long[0]; int n = 0; long cpu = 0, wallTotal = 0; int batch = 1;
        try (Variants.Runner r = Variants.make(v, in)) {
            // ---- first op: digest + match
            Object first = r.run();
            if (!r.check(first)) match = false;
            if (!r.tamperRejected()) match = false;
            switch (v.op) {
                case "keygen":
                    digest = Alg.sha256Hex(Variants.keygenPk(first));
                    line.put("pk_sha256", digest); line.put("sk_sha256", Alg.sha256Hex(Variants.keygenSk(first)));
                    break;
                case "sign": digest = Alg.sha256Hex((byte[]) Variants.first(first)); break;
                default: digest = match ? "true" : "false";
            }
            // ---- batch sizing for parallel variants: aim for >= ~40 ms per batch, at most 16 ops per lane
            if (r instanceof Variants.Parallel) {
                long t0 = System.nanoTime(); r.run(); long one = (System.nanoTime() - t0); // one batch of `threads` ops
                int k = (int) Math.max(1, Math.min(16, 40_000_000L / Math.max(1, one)));
                ((Variants.Parallel) r).setPerLane(k);
            }
            batch = r.batch;
            // ---- warm-up: >= 1 s and >= 20 ops, but never more than ~3 s (slow SLH-DSA ops) and at least 1 op
            long ws = System.nanoTime(); int wn = 0;
            while (true) {
                Object o = r.run(); wn += batch;
                if (!r.check(o)) match = false;
                long el = System.nanoTime() - ws;
                if ((el >= 1_000_000_000L && wn >= 20) || el >= 3_000_000_000L) break;
                if (EPSILON_GUARD && heapNearlyFull(0.45)) break;
            }
            // ---- measured loop
            long[] samples = new long[1024];
            long budget = budgetMs * 1_000_000L;
            long cpu0 = cpuNow();
            long start = System.nanoTime();
            long maxOp = 0;
            while (true) {
                long t0 = System.nanoTime();
                Object o = r.run();
                long t1 = System.nanoTime();
                if (n == samples.length) samples = Arrays.copyOf(samples, n * 2);
                samples[n++] = (t1 - t0) / batch;
                maxOp = Math.max(maxOp, t1 - t0);
                if (!r.check(o)) match = false;
                long el = t1 - start;
                int minOps = maxOp > 5_000_000_000L ? 2 : 3;
                if ((el >= budget && n * batch >= minOps) || n * batch >= 100000) break;
                if (EPSILON_GUARD && n * batch >= minOps && heapNearlyFull(0.85)) { System.err.println("  (epsilon heap guard stopped loop after " + n + " iterations)"); break; }
            }
            wallTotal = System.nanoTime() - start;
            cpu = cpuNow() - cpu0;
            wall = Arrays.copyOf(samples, n);
        } catch (Throwable t) {
            match = false;
            line.put("error", t.toString());
            System.err.println("ERROR " + v.id + " " + alg.name + ": " + t);
        }
        Arrays.sort(wall);
        long ops = (long) n * batch;
        line.put("iterations", ops);
        line.put("threads", v.threads);
        line.put("batch", batch);
        line.put("wall_ns_median", n == 0 ? 0 : wall[n / 2]);
        line.put("wall_ns_mean", n == 0 ? 0 : Arrays.stream(wall).sum() / n);
        line.put("wall_ns_p95", n == 0 ? 0 : wall[Math.min(n - 1, Math.max(0, (int) Math.ceil(0.95 * n) - 1))]);
        line.put("wall_ns_min", n == 0 ? 0 : wall[0]);
        line.put("cpu_ns_per_op", ops == 0 ? 0 : cpu / ops);
        line.put("cpu_util", wallTotal == 0 ? 0.0 : (double) cpu / wallTotal);
        line.put("ops_per_sec", wallTotal == 0 ? 0.0 : ops * 1e9 / wallTotal);
        line.put("output_sha256", digest);
        line.put("match", match);
        if (v.jvmFlags != null) line.put("jvm_flags", String.join(" ", v.jvmFlags));
        System.err.printf("%-9s %-18s %-20s n=%-6d median=%10.1f us cpu/op=%10.1f us util=%.2f ops/s=%10.1f match=%s%n",
            v.id, v.name, alg.name, ops, (n == 0 ? 0 : wall[n / 2]) / 1e3, (ops == 0 ? 0 : cpu / ops) / 1e3,
            wallTotal == 0 ? 0 : (double) cpu / wallTotal, wallTotal == 0 ? 0 : ops * 1e9 / wallTotal, match);
        return line;
    }
}
