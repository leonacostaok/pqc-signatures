import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.GZIPInputStream;

/**
 * `validate <suite.json.gz> <out.json>`: every keygen case through keygen.v0..v5, every siggen case through
 * sign.v0..v5, every sigver case through verify.v0..v5 and through the stage pipelines total.v0 / total_best.
 * JVM-flag variants run in a child JVM with their flags (`--child --variants id`, results on stdout).
 */
final class Validate {
    static void main(String[] a) throws Exception {
        List<String> pos = new ArrayList<>(), variants = null;
        boolean child = false;
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--child": child = true; break;
                case "--variants": variants = Arrays.asList(a[++i].split(",")); break;
                default: pos.add(a[i]);
            }
        }
        if (pos.size() != 2) Bench.usage();
        String suite = pos.get(0), out = pos.get(1);
        Map<String, Object> doc;
        try (GZIPInputStream in = new GZIPInputStream(Files.newInputStream(Paths.get(suite)))) {
            doc = Json.obj(Json.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        }
        List<Map<String, Object>> cases = new ArrayList<>();
        for (Object o : Json.arr(doc.get("cases"))) cases.add(Json.obj(o));
        if (!child) System.err.println(cases.size() + " cases loaded from " + suite);

        List<Map<String, Object>> results = new ArrayList<>();
        java.io.PrintStream stdout = new java.io.PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8");
        if (!out.equals("-")) System.setOut(System.err);

        for (String op : new String[]{"keygen", "sign", "verify"}) {
            String kind = op.equals("sign") ? "siggen" : op.equals("verify") ? "sigver" : "keygen";
            List<String> ids = new ArrayList<>();
            for (Variants.Variant v : Variants.forOp(op)) ids.add(v.id);
            if (op.equals("verify")) { ids.add("total.v0"); ids.add("total_best"); }
            for (String id : ids) {
                if (variants != null && !variants.contains(id)) continue;
                Variants.Variant v = id.startsWith("total") ? null : Variants.forOp(op).get(Integer.parseInt(id.substring(id.indexOf(".v") + 2)));
                if (v != null && v.jvmFlags != null && !child) { results.addAll(runChild(v, suite)); continue; }
                int pass = 0, fail = 0;
                long t0 = System.nanoTime();
                for (Map<String, Object> c : cases) {
                    if (!kind.equals(c.get("kind"))) continue;
                    Alg alg = Alg.ALL.get((String) c.get("param"));
                    if (alg == null || !alg.byteMatch()) continue;
                    Map<String, Object> r = runCase(id, v, alg, c);
                    if (Boolean.TRUE.equals(r.get("pass"))) pass++; else fail++;
                    results.add(r);
                    if (child) stdout.println(Json.write(r));
                }
                System.err.printf("%-12s pass=%d fail=%d (%.1f s)%n", id, pass, fail, (System.nanoTime() - t0) / 1e9);
            }
        }
        if (child) { stdout.flush(); return; }

        Map<String, Object> summary = new TreeMap<>();
        for (Map<String, Object> r : results) {
            @SuppressWarnings("unchecked") Map<String, Object> s = (Map<String, Object>) summary.computeIfAbsent((String) r.get("variant"), k -> {
                Map<String, Object> m = new LinkedHashMap<>(); m.put("pass", 0L); m.put("fail", 0L); m.put("skipped", 0L); return m; });
            String k = Boolean.TRUE.equals(r.get("skipped")) ? "skipped" : Boolean.TRUE.equals(r.get("pass")) ? "pass" : "fail";
            s.put(k, (Long) s.get(k) + 1);
        }
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("lib", Bench.LIB); o.put("lib_version", Bench.LIB_VERSION); o.put("results", results); o.put("summary", summary);
        Files.writeString(Paths.get(out), Json.write(o) + "\n");
        System.err.println("summary: " + Json.write(summary));
        int failures = 0;
        for (Map<String, Object> r : results) if (!Boolean.TRUE.equals(r.get("pass")) && !Boolean.TRUE.equals(r.get("skipped"))) { failures++; if (failures <= 40) System.err.println("FAIL " + Json.write(r)); }
        System.err.println(results.size() + " results, " + failures + " failures");
        CaseOps.POOL.shutdownNow(); Stages.POOL.shutdownNow();
    }

    static Map<String, Object> runCase(String id, Variants.Variant v, Alg alg, Map<String, Object> c) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", c.get("id")); r.put("variant", id);
        String kind = (String) c.get("kind");
        try {
            switch (kind) {
                case "keygen": {
                    byte[][] kp = CaseOps.keygen(v, alg, Alg.unhex((String) c.get("seed_hex")));
                    String got = Alg.hex(kp[0]).equals(c.get("expect_pk_hex")) ? "pk-ok" : "pk-mismatch";
                    got += Alg.hex(kp[1]).equals(c.get("expect_sk_hex")) ? ",sk-ok" : ",sk-mismatch";
                    r.put("pass", got.equals("pk-ok,sk-ok")); r.put("got", got); r.put("error", null);
                    break;
                }
                case "siggen": {
                    byte[] sig = CaseOps.sign(v, alg, Alg.unhex((String) c.get("sk_hex")), Alg.unhex((String) c.get("msg_hex")), Alg.unhex((String) c.get("ctx_hex")));
                    boolean ok = Alg.hex(sig).equals(c.get("expect_sig_hex"));
                    r.put("pass", ok); r.put("got", "sig_sha256:" + Alg.sha256Hex(sig)); r.put("error", null);
                    break;
                }
                default: {
                    byte[] pk = Alg.unhex((String) c.get("pk_hex")), msg = Alg.unhex((String) c.get("msg_hex")), ctx = Alg.unhex((String) c.get("ctx_hex")), sig = Alg.unhex((String) c.get("sig_hex"));
                    boolean got;
                    String err = null;
                    try {
                        if (v != null) got = CaseOps.verify(v, alg, pk, msg, ctx, sig);
                        else got = Stages.pipelineVerify(alg, pk, msg, ctx, sig, id.equals("total.v0") ? Stages.v0Composition(alg.family == Alg.Family.MLDSA) : Stages.bestComposition(alg));
                    } catch (Exception e) { got = false; err = "exception treated as reject: " + e; }
                    boolean expect = Boolean.TRUE.equals(c.get("expect"));
                    r.put("pass", got == expect); r.put("got", got); r.put("error", err);
                    if (got != expect) r.put("reason", c.get("reason"));
                }
            }
        } catch (Throwable t) {
            r.put("pass", false); r.put("got", null); r.put("error", t.toString());
        }
        return r;
    }

    static List<Map<String, Object>> runChild(Variants.Variant v, String suite) throws Exception {
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>();
        cmd.add(java); cmd.addAll(Arrays.asList(v.jvmFlags));
        cmd.add("-Dpqc.common=" + Bench.COMMON);
        cmd.add("-cp"); cmd.add(System.getProperty("pqc.classpath", System.getProperty("java.class.path")));
        cmd.add("Bench"); cmd.add("validate"); cmd.add("--child"); cmd.add("--variants"); cmd.add(v.id); cmd.add(suite); cmd.add("-");
        System.err.println("[child] " + String.join(" ", cmd));
        Process p = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        List<Map<String, Object>> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) if (l.startsWith("{")) out.add(Json.obj(Json.parse(l)));
        }
        int rc = p.waitFor();
        if (rc != 0) System.err.println("[child] " + v.id + " exited with " + rc);
        return out;
    }
}
