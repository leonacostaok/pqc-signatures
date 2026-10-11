import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import bc.mldsa.MlStages;
import bc.slhdsa.FastHash;
import bc.slhdsa.SLHDSAEngine;
import bc.slhdsa.SlhStages;

/**
 * `stages`: verification split into canonical stages with v0 (BC's own code, vendored) and alternatives.
 * Also provides the end-to-end stage pipelines (total / total_best) used by `validate` and `memory`.
 */
final class Stages {
    static final int CORES = Runtime.getRuntime().availableProcessors();
    static final String[] C2_ONLY = {"-XX:-TieredCompilation"};

    static final class SVariant {
        final String stage, id, name, desc, impl;
        final int threads;
        final boolean cached, composable;
        final String[] jvmFlags;
        SVariant(String stage, int n, String name, String desc, String impl, int threads, boolean cached, boolean composable, String... jvmFlags) {
            this.stage = stage; this.id = stage + ".v" + n; this.name = name; this.desc = desc; this.impl = impl;
            this.threads = threads; this.cached = cached; this.composable = composable; this.jvmFlags = jvmFlags.length == 0 ? null : jvmFlags;
        }
    }

    static final String[] ML_STAGES = {"decode", "mu", "expandA", "w_approx", "hint_check"};
    static final String[] SLH_STAGES = {"hmsg", "fors", "ht_wots", "ht_auth"};

    static List<SVariant> variants(String stage) {
        List<SVariant> l = new ArrayList<>();
        switch (stage) {
            case "decode":
                l.add(new SVariant(stage, 0, "bc", "BC Packing.unpackPublicKey + Packing.unpackSignature (byte-wise bit unpacking, FIPS 204 hint validity rules).", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "wide-unpack", "Same decoding with 64-bit little-endian word loads (VarHandle) and shifts instead of byte-by-byte assembly of t1 and z.", "wide", 1, false, true));
                l.add(new SVariant(stage, 2, "c2-only", "BC decode in a child JVM with -XX:-TieredCompilation (C2 only).", "bc", 1, false, false, C2_ONLY));
                break;
            case "mu":
                l.add(new SVariant(stage, 0, "bc", "BC SHAKEDigest: tr = SHAKE256(pk, 64), mu = SHAKE256(tr || 0 || |ctx| || ctx || M, 64).", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "cached-tr", "tr = H(pk) precomputed once per public key; only the second SHAKE256 per message.", "cached-tr", 1, true, true));
                l.add(new SVariant(stage, 2, "own-keccak", "Both hashes on the harness's own Keccak-f[1600] sponge (bc.Keccak) instead of BC's SHAKEDigest.", "keccak", 1, false, true));
                break;
            case "expandA":
                l.add(new SVariant(stage, 0, "bc", "BC PolyVecMatrix.expandMatrix: SHAKE128(rho||j||i) squeezed in 168-byte blocks, 23-bit rejection sampling per polynomial.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "cached-A", "Matrix A cached per public key (expanded once, looked up per verification).", "cached", 1, true, true));
                l.add(new SVariant(stage, 2, "parallel-rows", "The k rows expanded concurrently on a fixed thread pool, one BC engine (own SHAKE state) per task.", "parallel", CORES, false, true));
                l.add(new SVariant(stage, 3, "own-keccak", "Own SHAKE128 sponge; the sampler reads 3-byte triples straight from the squeezed block without block copies.", "keccak", 1, false, true));
                l.add(new SVariant(stage, 4, "c2-only", "BC expandMatrix in a child JVM with -XX:-TieredCompilation.", "bc", 1, false, false, C2_ONLY));
                break;
            case "w_approx":
                l.add(new SVariant(stage, 0, "bc", "BC sequence: NTT(z); A o z (fused pointwise-accumulate); NTT(c); NTT(t1<<d); c o t1; sub; reduce32; invNTT; caddq.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "cached-ntt-t1", "NTT(t1 * 2^d) precomputed once per public key.", "cached-t1", 1, true, true));
                l.add(new SVariant(stage, 2, "parallel-rows", "NTT(z), NTT(c) once, then the k output rows (dot product, c*t1, invNTT) on a thread pool.", "parallel", CORES, false, true));
                l.add(new SVariant(stage, 3, "long-accum", "One 64-bit accumulator per coefficient over the l products and the -c*t1 term, a single Montgomery reduction instead of l+1.", "longacc", 1, false, true));
                break;
            case "hint_check":
                l.add(new SVariant(stage, 0, "bc", "BC checkNorm(z), PolyVec.useHint, packW1, SHAKEDigest(mu || w1Encode) and constant-time compare with c~.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "fused-usehint-pack", "Decompose + UseHint + w1Encode fused into one pass writing packed bytes directly (no intermediate PolyVec).", "fused", 1, false, true));
                l.add(new SVariant(stage, 2, "own-keccak", "BC UseHint/pack, challenge hash on the own Keccak sponge.", "keccak", 1, false, true));
                l.add(new SVariant(stage, 3, "c2-only", "BC hint_check in a child JVM with -XX:-TieredCompilation.", "bc", 1, false, false, C2_ONLY));
                break;
            case "hmsg":
                l.add(new SVariant(stage, 0, "bc", "BC engine H_msg: SHA2 sets SHA-256/512 + MGF1 (BC digests); SHAKE sets SHAKEDigest; then md / idx_tree / idx_leaf split.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "alt-backend", "Non-BC digest backend: JDK (intrinsified) SHA-256/SHA-512 + own MGF1 for SHA2 sets, own Keccak for SHAKE sets.", "alt", 1, false, true));
                l.add(new SVariant(stage, 2, "c2-only", "BC H_msg in a child JVM with -XX:-TieredCompilation.", "bc", 1, false, false, C2_ONLY));
                break;
            case "fors":
                l.add(new SVariant(stage, 0, "bc", "BC Fors.pkFromSig: BigInteger base-2^a, per-node F/H with allocated outputs, T_l over the k roots.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "alt-backend", "BC Fors.pkFromSig on the alternative engine (JDK SHA-2 with cloned PK.seed midstate / own Keccak).", "alt", 1, false, true));
                l.add(new SVariant(stage, 2, "parallel-trees", "The k FORS trees spread over a thread pool (BC engine per task), T_l on the caller's engine.", "parallel", CORES, false, true));
                l.add(new SVariant(stage, 3, "fused-fast", "Re-implementation on FastHash: flat ADRS, int base-2^a, every node hashed in place into one roots buffer (no per-node allocation).", "fast", 1, false, true));
                break;
            case "ht_wots":
                l.add(new SVariant(stage, 0, "bc", "BC WotsPlus.pkFromSig per layer: base_w, chain() with allocated outputs per step, T_l over the len chain ends.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "alt-backend", "BC WotsPlus.pkFromSig on the alternative engine (JDK SHA-2 midstate / own Keccak).", "alt", 1, false, true));
                l.add(new SVariant(stage, 2, "parallel-chains", "Per layer, the len WOTS+ chains split across a thread pool (BC engine per lane), T_l on the main engine.", "parchains", CORES, false, true));
                l.add(new SVariant(stage, 3, "parallel-layers", "The d layers' WOTS+ pkFromSig computed concurrently (inputs precomputed); not composable into a real verify since layer j's message is layer j-1's root.", "parlayers", CORES, false, false));
                l.add(new SVariant(stage, 4, "fused-fast", "Re-implementation on FastHash: chains hashed in place inside one len*n buffer with a flat ADRS.", "fast", 1, false, true));
                break;
            case "ht_auth":
                l.add(new SVariant(stage, 0, "bc", "The auth-path loop of BC HT.xmss_pkFromSig per layer (H per level with allocated node outputs), final compare with PK.root.", "bc", 1, false, true));
                l.add(new SVariant(stage, 1, "alt-backend", "Same loop on the alternative engine (JDK SHA-2 midstate / own Keccak).", "alt", 1, false, true));
                l.add(new SVariant(stage, 2, "parallel-layers", "The d layers' auth-path roots computed concurrently (inputs precomputed); not composable into a real verify.", "parlayers", CORES, false, false));
                l.add(new SVariant(stage, 3, "fused-fast", "Re-implementation on FastHash: node hashed in place into one buffer, flat ADRS.", "fast", 1, false, true));
                break;
            default: throw new IllegalArgumentException(stage);
        }
        return l;
    }

    static SVariant find(String id) {
        String stage = id.substring(0, id.indexOf('.'));
        for (SVariant v : variants(stage)) if (v.id.equals(id)) return v;
        throw new IllegalArgumentException("unknown stage variant " + id);
    }

    static final ExecutorService POOL = Executors.newFixedThreadPool(CORES, r -> { Thread t = new Thread(r, "stage-lane"); t.setDaemon(true); return t; });

    // ================================================================= per-param context (reference inputs + v0 intermediate outputs)

    static final class MlCtx {
        final MlStages st; final byte[] pk, msg, sig, ctx = new byte[0];
        MlStages.Decoded dec; byte[] mu, tr; Object A; Object w; Object t1Ntt;
        MlCtx(Alg alg, Variants.Inputs in) {
            st = new MlStages(alg.mldsa); pk = in.pk; msg = in.msg; sig = in.sig;
            dec = st.decode(pk, sig);
            if (dec == null) throw new IllegalStateException("reference signature does not decode");
            mu = MlStages.mu(pk, ctx, msg);
            tr = MlStages.tr(pk);
            A = st.expandA(dec.rho);
            w = st.wApprox(a(A), dec);
            t1Ntt = st.t1Ntt(dec);
        }
        bc.mldsa.PolyVecMatrix a(Object o) { return (bc.mldsa.PolyVecMatrix) o; }
        bc.mldsa.PolyVec pv(Object o) { return (bc.mldsa.PolyVec) o; }
    }

    static final class SlhCtx {
        final SlhStages st; final byte[] pk, pkSeed, pkRoot, msg, sig, ctx = new byte[0];
        final SLHDSAEngine bc, alt; final FastHash fast;
        SlhStages.Parsed parsed; SlhStages.HMsg hm; byte[] pkFors; byte[][] layerMsg, wotsPk, roots;
        SlhCtx(Alg alg, Variants.Inputs in) {
            st = new SlhStages(alg.name); pk = in.pk; msg = in.msg; sig = in.sig;
            pkSeed = Arrays.copyOf(pk, st.N); pkRoot = Arrays.copyOfRange(pk, st.N, 2 * st.N);
            bc = st.bcEngine(pkSeed); alt = st.altEngine(pkSeed); fast = st.fast(pkSeed);
            parsed = st.parse(sig);
            hm = st.hmsg(bc, parsed, pkSeed, pkRoot, ctx, msg);
            pkFors = st.fors(bc, parsed, hm, pkSeed);
            layerMsg = new byte[st.D][]; wotsPk = new byte[st.D][]; roots = new byte[st.D][];
            byte[] m = pkFors;
            for (int j = 0; j < st.D; j++) {
                layerMsg[j] = m;
                wotsPk[j] = st.wots(bc, parsed, hm, j, m, pkSeed);
                roots[j] = st.auth(bc, parsed, hm, j, wotsPk[j], pkSeed);
                m = roots[j];
            }
            if (!Arrays.equals(roots[st.D - 1], pkRoot)) throw new IllegalStateException("reference signature does not verify through stages");
        }
    }

    // ================================================================= stage ops: run() returns the stage object, canon() its canonical bytes

    interface StageOp { Object run() throws Exception; byte[] canon(Object o) throws Exception; }

    static StageOp mlOp(SVariant v, MlCtx c) {
        MlStages st = c.st;
        switch (v.stage) {
            case "decode": {
                StageOp op = new StageOp() {
                    public Object run() { return v.impl.equals("wide") ? st.decodeWide(c.pk, c.sig) : st.decode(c.pk, c.sig); }
                    public byte[] canon(Object o) { return o == null ? new byte[0] : MlStages.cTilde((MlStages.Decoded) o); }
                };
                return op;
            }
            case "mu":
                return new StageOp() {
                    public Object run() {
                        switch (v.impl) {
                            case "cached-tr": return MlStages.muFromTr(c.tr, c.ctx, c.msg);
                            case "keccak": return MlStages.muKeccak(c.pk, c.ctx, c.msg);
                            default: return MlStages.mu(c.pk, c.ctx, c.msg);
                        }
                    }
                    public byte[] canon(Object o) { return (byte[]) o; }
                };
            case "expandA":
                return new StageOp() {
                    public Object run() throws Exception {
                        switch (v.impl) {
                            case "cached": return c.A;
                            case "parallel": return st.expandAParallel(c.dec.rho, POOL, v.threads);
                            case "keccak": return st.expandAKeccak(c.dec.rho);
                            default: return st.expandA(c.dec.rho);
                        }
                    }
                    public byte[] canon(Object o) { return st.canon(c.a(o)); }
                };
            case "w_approx":
                return new StageOp() {
                    public Object run() throws Exception {
                        switch (v.impl) {
                            case "cached-t1": return st.wApproxCachedT1(c.a(c.A), c.dec, c.pv(c.t1Ntt));
                            case "parallel": return st.wApproxParallel(c.a(c.A), c.dec, POOL, v.threads);
                            case "longacc": return st.wApproxLongAccum(c.a(c.A), c.dec);
                            default: return st.wApprox(c.a(c.A), c.dec);
                        }
                    }
                    public byte[] canon(Object o) { return MlStages.canon(c.pv(o)); }
                };
            case "hint_check":
                return new StageOp() {
                    public Object run() {
                        switch (v.impl) {
                            case "fused": return st.hintCheckFused(c.mu, c.pv(c.w), c.dec);
                            case "keccak": return st.hintCheckKeccak(c.mu, c.pv(c.w), c.dec);
                            default: return st.hintCheck(c.mu, c.pv(c.w), c.dec);
                        }
                    }
                    public byte[] canon(Object o) { MlStages.HintResult r = (MlStages.HintResult) o; return r.ok ? r.w1Enc : new byte[0]; }
                };
        }
        throw new IllegalArgumentException(v.stage);
    }

    static StageOp slhOp(SVariant v, SlhCtx c) {
        SlhStages st = c.st;
        switch (v.stage) {
            case "hmsg":
                return new StageOp() {
                    public Object run() { return st.hmsg(v.impl.equals("alt") ? c.alt : c.bc, c.parsed, c.pkSeed, c.pkRoot, c.ctx, c.msg); }
                    public byte[] canon(Object o) { return ((SlhStages.HMsg) o).full; }
                };
            case "fors":
                return new StageOp() {
                    public Object run() throws Exception {
                        switch (v.impl) {
                            case "alt": return st.fors(c.alt, c.parsed, c.hm, c.pkSeed);
                            case "parallel": return st.forsParallel(c.bc, c.parsed, c.hm, c.pkSeed, POOL, v.threads);
                            case "fast": return st.forsFast(c.fast, c.parsed, c.hm);
                            default: return st.fors(c.bc, c.parsed, c.hm, c.pkSeed);
                        }
                    }
                    public byte[] canon(Object o) { return (byte[]) o; }
                };
            case "ht_wots": {
                final SLHDSAEngine[] lanes = v.impl.equals("parchains") ? lanes(c, v.threads) : null;
                return new StageOp() {
                    public Object run() throws Exception {
                        byte[][] out = new byte[st.D][];
                        switch (v.impl) {
                            case "alt": for (int j = 0; j < st.D; j++) out[j] = st.wots(c.alt, c.parsed, c.hm, j, c.layerMsg[j], c.pkSeed); break;
                            case "parchains": for (int j = 0; j < st.D; j++) out[j] = st.wotsParallelChains(c.bc, lanes, c.parsed, c.hm, j, c.layerMsg[j], c.pkSeed, POOL); break;
                            case "parlayers": parallelLayers(c, v.threads, (e, j) -> out[j] = st.wots(e, c.parsed, c.hm, j, c.layerMsg[j], c.pkSeed)); break;
                            case "fast": for (int j = 0; j < st.D; j++) out[j] = st.wotsFast(c.fast, c.parsed, c.hm, j, c.layerMsg[j]); break;
                            default: for (int j = 0; j < st.D; j++) out[j] = st.wots(c.bc, c.parsed, c.hm, j, c.layerMsg[j], c.pkSeed);
                        }
                        return out;
                    }
                    public byte[] canon(Object o) { return org.bouncycastle.util.Arrays.concatenate((byte[][]) o); }
                };
            }
            case "ht_auth":
                return new StageOp() {
                    public Object run() throws Exception {
                        byte[][] out = new byte[st.D][];
                        switch (v.impl) {
                            case "alt": for (int j = 0; j < st.D; j++) out[j] = st.auth(c.alt, c.parsed, c.hm, j, c.wotsPk[j], c.pkSeed); break;
                            case "parlayers": parallelLayers(c, v.threads, (e, j) -> out[j] = st.auth(e, c.parsed, c.hm, j, c.wotsPk[j], c.pkSeed)); break;
                            case "fast": for (int j = 0; j < st.D; j++) out[j] = st.authFast(c.fast, c.parsed, c.hm, j, c.wotsPk[j]); break;
                            default: for (int j = 0; j < st.D; j++) out[j] = st.auth(c.bc, c.parsed, c.hm, j, c.wotsPk[j], c.pkSeed);
                        }
                        if (!Arrays.equals(out[st.D - 1], c.pkRoot)) throw new IllegalStateException("root mismatch");
                        return out;
                    }
                    public byte[] canon(Object o) { return org.bouncycastle.util.Arrays.concatenate((byte[][]) o); }
                };
        }
        throw new IllegalArgumentException(v.stage);
    }

    static SLHDSAEngine[] lanes(SlhCtx c, int n) {
        SLHDSAEngine[] l = new SLHDSAEngine[n];
        for (int i = 0; i < n; i++) l[i] = c.st.bcEngine(c.pkSeed);
        return l;
    }

    interface LayerFn { void run(SLHDSAEngine e, int layer) throws Exception; }
    static void parallelLayers(SlhCtx c, int threads, LayerFn fn) throws Exception {
        List<Callable<Void>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int lane = t;
            tasks.add(() -> {
                SLHDSAEngine e = c.st.bcEngine(c.pkSeed);
                for (int j = lane; j < c.st.D; j += threads) fn.run(e, j);
                return null;
            });
        }
        for (Future<Void> f : POOL.invokeAll(tasks)) f.get();
    }

    // ================================================================= end-to-end pipelines (composition: stage -> variant impl)

    static Map<String, String> v0Composition(boolean ml) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String s : ml ? ML_STAGES : SLH_STAGES) m.put(s, s + ".v0");
        return m;
    }

    /** small per-key caches for the "cached" variants when used in a pipeline */
    static final Map<String, Object> CACHE = new java.util.concurrent.ConcurrentHashMap<>();
    static Object cached(String key, java.util.function.Supplier<Object> f) {
        Object o = CACHE.get(key);
        if (o == null) { if (CACHE.size() > 64) CACHE.clear(); o = f.get(); CACHE.put(key, o); }
        return o;
    }

    static boolean verifyMl(MlStages st, byte[] pk, byte[] msg, byte[] ctx, byte[] sig, Map<String, String> comp) throws Exception {
        if (ctx.length > 255) return false;
        String kp = Alg.hex(Alg.sha256(pk));
        MlStages.Decoded d = find(comp.get("decode")).impl.equals("wide") ? st.decodeWide(pk, sig) : st.decode(pk, sig);
        if (d == null) return false;
        byte[] mu;
        switch (find(comp.get("mu")).impl) {
            case "cached-tr": mu = MlStages.muFromTr((byte[]) cached("tr:" + kp, () -> MlStages.tr(pk)), ctx, msg); break;
            case "keccak": mu = MlStages.muKeccak(pk, ctx, msg); break;
            default: mu = MlStages.mu(pk, ctx, msg);
        }
        SVariant ea = find(comp.get("expandA"));
        bc.mldsa.PolyVecMatrix a;
        switch (ea.impl) {
            case "cached": a = (bc.mldsa.PolyVecMatrix) cached("A:" + kp, () -> st.expandA(d.rho)); break;
            case "parallel": a = st.expandAParallel(d.rho, POOL, ea.threads); break;
            case "keccak": a = st.expandAKeccak(d.rho); break;
            default: a = st.expandA(d.rho);
        }
        SVariant wa = find(comp.get("w_approx"));
        bc.mldsa.PolyVec w;
        switch (wa.impl) {
            case "cached-t1": w = st.wApproxCachedT1(a, d, (bc.mldsa.PolyVec) cached("t1:" + kp, () -> st.t1Ntt(d))); break;
            case "parallel": w = st.wApproxParallel(a, d, POOL, wa.threads); break;
            case "longacc": w = st.wApproxLongAccum(a, d); break;
            default: w = st.wApprox(a, d);
        }
        MlStages.HintResult r;
        switch (find(comp.get("hint_check")).impl) {
            case "fused": r = st.hintCheckFused(mu, w, d); break;
            case "keccak": r = st.hintCheckKeccak(mu, w, d); break;
            default: r = st.hintCheck(mu, w, d);
        }
        return r.ok;
    }

    static boolean verifySlh(SlhStages st, byte[] pk, byte[] msg, byte[] ctx, byte[] sig, Map<String, String> comp) throws Exception {
        if (ctx.length > 255 || pk.length != 2 * st.N) return false;
        SlhStages.Parsed p = st.parse(sig);
        if (p == null) return false;
        byte[] pkSeed = Arrays.copyOf(pk, st.N), pkRoot = Arrays.copyOfRange(pk, st.N, 2 * st.N);
        SLHDSAEngine bcE = st.bcEngine(pkSeed);
        SLHDSAEngine altE = null; FastHash fast = null;
        SVariant hv = find(comp.get("hmsg")), fv = find(comp.get("fors")), wv = find(comp.get("ht_wots")), av = find(comp.get("ht_auth"));
        if (hv.impl.equals("alt") || fv.impl.equals("alt") || wv.impl.equals("alt") || av.impl.equals("alt")) altE = st.altEngine(pkSeed);
        if (fv.impl.equals("fast") || wv.impl.equals("fast") || av.impl.equals("fast")) fast = st.fast(pkSeed);
        SlhStages.HMsg hm = st.hmsg(hv.impl.equals("alt") ? altE : bcE, p, pkSeed, pkRoot, ctx, msg);
        byte[] m;
        switch (fv.impl) {
            case "alt": m = st.fors(altE, p, hm, pkSeed); break;
            case "parallel": m = st.forsParallel(bcE, p, hm, pkSeed, POOL, fv.threads); break;
            case "fast": m = st.forsFast(fast, p, hm); break;
            default: m = st.fors(bcE, p, hm, pkSeed);
        }
        SLHDSAEngine[] lanes = wv.impl.equals("parchains") ? new SLHDSAEngine[wv.threads] : null;
        if (lanes != null) for (int i = 0; i < lanes.length; i++) lanes[i] = st.bcEngine(pkSeed);
        for (int j = 0; j < st.D; j++) {
            byte[] wpk;
            switch (wv.impl) {
                case "alt": wpk = st.wots(altE, p, hm, j, m, pkSeed); break;
                case "parchains": wpk = st.wotsParallelChains(bcE, lanes, p, hm, j, m, pkSeed, POOL); break;
                case "fast": wpk = st.wotsFast(fast, p, hm, j, m); break;
                case "parlayers": throw new IllegalStateException("parallel-layers is not composable");
                default: wpk = st.wots(bcE, p, hm, j, m, pkSeed);
            }
            switch (av.impl) {
                case "alt": m = st.auth(altE, p, hm, j, wpk, pkSeed); break;
                case "fast": m = st.authFast(fast, p, hm, j, wpk); break;
                case "parlayers": throw new IllegalStateException("parallel-layers is not composable");
                default: m = st.auth(bcE, p, hm, j, wpk, pkSeed);
            }
        }
        return Arrays.equals(m, pkRoot);
    }

    /** verify through a stage pipeline; exceptions are reported as false by callers */
    static boolean pipelineVerify(Alg alg, byte[] pk, byte[] msg, byte[] ctx, byte[] sig, Map<String, String> comp) throws Exception {
        if (alg.family == Alg.Family.MLDSA) return verifyMl(new MlStages(alg.mldsa), pk, msg, ctx, sig, comp);
        return verifySlh(new SlhStages(alg.name), pk, msg, ctx, sig, comp);
    }

    /** total_best composition: read from results/bouncycastle/stages.jsonl if present (per param), else defaults */
    static Map<String, String> bestComposition(Alg alg) {
        boolean ml = alg.family == Alg.Family.MLDSA;
        Map<String, String> comp = new LinkedHashMap<>();
        try {
            java.nio.file.Path f = Paths.get(System.getProperty("pqc.results", "results/bouncycastle"), "stages.jsonl");
            if (java.nio.file.Files.exists(f)) {
                for (String line : java.nio.file.Files.readAllLines(f)) {
                    if (!line.contains("\"stage\":\"total_best\"") || !line.contains("\"param\":\"" + alg.name + "\"")) continue;
                    Map<String, Object> r = Json.obj(Json.parse(line));
                    Map<String, Object> c = Json.obj(r.get("composition"));
                    for (Map.Entry<String, Object> e : c.entrySet()) comp.put(e.getKey(), (String) e.getValue());
                }
            }
        } catch (Exception ignored) {}
        if (comp.isEmpty()) {
            if (ml) { comp.put("decode", "decode.v1"); comp.put("mu", "mu.v0"); comp.put("expandA", "expandA.v3"); comp.put("w_approx", "w_approx.v3"); comp.put("hint_check", "hint_check.v1"); }
            else { comp.put("hmsg", "hmsg.v1"); comp.put("fors", "fors.v3"); comp.put("ht_wots", "ht_wots.v4"); comp.put("ht_auth", "ht_auth.v3"); }
        }
        return comp;
    }

    // ================================================================= driver

    static void main(String[] a) throws Exception {
        String out = null; long budget = 1000; boolean child = false;
        List<String> params = new ArrayList<>(), stages = null, variants = null;
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--out": out = a[++i]; break;
                case "--budget-ms": budget = Long.parseLong(a[++i]); break;
                case "--params": params = Arrays.asList(a[++i].split(",")); break;
                case "--stages": stages = Arrays.asList(a[++i].split(",")); break;
                case "--variants": variants = Arrays.asList(a[++i].split(",")); break;
                case "--child": child = true; break;
                default: Bench.usage();
            }
        }
        if (out == null) Bench.usage();
        if (params.isEmpty()) for (Alg alg : Alg.ALL.values()) if (alg.byteMatch()) params.add(alg.name);
        PrintStream sink = out.equals("-") ? new PrintStream(new FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8")
                                           : new PrintStream(new FileOutputStream(out, true), true, "UTF-8");
        if (!out.equals("-")) System.setOut(System.err);

        for (String pn : params) {
            Alg alg = Alg.get(pn);
            if (!alg.byteMatch()) continue;
            boolean ml = alg.family == Alg.Family.MLDSA;
            Variants.Inputs in = Bench.baseline(alg);
            String mm = Bench.refMismatch(in);
            if (mm != null) { System.err.println("WARNING " + alg.name + ": " + mm); }
            Object cx = ml ? new MlCtx(alg, in) : new SlhCtx(alg, in);
            String family = ml ? "ml-dsa" : "slh-dsa";
            Map<String, Long> medians = new LinkedHashMap<>();
            for (String stage : ml ? ML_STAGES : SLH_STAGES) {
                if (stages != null && !stages.contains(stage)) continue;
                StageOp v0 = ml ? mlOp(variants(stage).get(0), (MlCtx) cx) : slhOp(variants(stage).get(0), (SlhCtx) cx);
                String v0digest = Alg.sha256Hex(v0.canon(v0.run()));
                for (SVariant v : variants(stage)) {
                    if (variants != null && !variants.contains(v.id)) continue;
                    if (v.jvmFlags != null && !child) { runChild(v, pn, budget, sink); continue; }
                    StageOp op = ml ? mlOp(v, (MlCtx) cx) : slhOp(v, (SlhCtx) cx);
                    Map<String, Object> line = Timing.baseLine(v.id, v.name, v.desc);
                    line.put("family", family); line.put("stage", stage); line.put("param", alg.name);
                    String digest;
                    boolean match;
                    try {
                        Object first = op.run();
                        digest = Alg.sha256Hex(op.canon(first));
                        match = digest.equals(v0digest);
                        Timing.Stats s = Timing.measure(op::run, 1, budget, o -> Alg.sha256Hex(op.canon(o)).equals(v0digest));
                        if (!s.match) match = false;
                        s.put(line);
                        if (match && v.jvmFlags == null && v.composable && !v.cached) medians.merge(stage + "|" + v.id, s.wall[s.wall.length / 2], Math::min);
                    } catch (Throwable t) {
                        digest = ""; match = false; line.put("error", t.toString());
                        System.err.println("ERROR " + v.id + " " + alg.name + ": " + t);
                        t.printStackTrace();
                    }
                    line.put("threads", v.threads);
                    line.put("output_sha256", digest);
                    line.put("match", match);
                    if (v.jvmFlags != null) line.put("jvm_flags", String.join(" ", v.jvmFlags));
                    sink.println(Json.write(line)); sink.flush();
                    System.err.printf("%-16s %-18s %-20s n=%-6s median=%10.1f us match=%s%n", v.id, v.name, alg.name, line.get("iterations"),
                        ((Number) line.getOrDefault("wall_ns_median", 0L)).longValue() / 1e3, match);
                }
            }
            if (child || (stages != null && stages.size() < (ml ? ML_STAGES.length : SLH_STAGES.length))) continue;
            // ---- total (v0 pipeline) and total_best (fastest composable, non-cached, in-process alternative per stage)
            Map<String, String> best = new LinkedHashMap<>();
            for (String stage : ml ? ML_STAGES : SLH_STAGES) {
                String bestId = stage + ".v0"; long bestT = Long.MAX_VALUE;
                for (Map.Entry<String, Long> e : medians.entrySet())
                    if (e.getKey().startsWith(stage + "|") && e.getValue() < bestT) { bestT = e.getValue(); bestId = e.getKey().substring(stage.length() + 1); }
                best.put(stage, bestId);
            }
            totalLine(sink, alg, in, family, "total", "total.v0", "v0-pipeline", "End-to-end verify assembled from the v0 stages (BC's own code).", v0Composition(ml), budget);
            totalLine(sink, alg, in, family, "total_best", "total_best", "best-pipeline", "End-to-end verify assembled from the fastest correct, composable, non-cached stage alternatives of this run: " + best, best, budget);
        }
        sink.flush();
        POOL.shutdownNow();
    }

    static void totalLine(PrintStream sink, Alg alg, Variants.Inputs in, String family, String stage, String id, String name, String desc, Map<String, String> comp, long budget) throws Exception {
        Map<String, Object> line = Timing.baseLine(id, name, desc);
        line.put("family", family); line.put("stage", stage); line.put("param", alg.name);
        boolean ml = alg.family == Alg.Family.MLDSA;
        MlStages ms = ml ? new MlStages(alg.mldsa) : null;
        SlhStages ss = ml ? null : new SlhStages(alg.name);
        Callable<Object> op = () -> ml ? verifyMl(ms, in.pk, in.msg, new byte[0], in.sig, comp) : verifySlh(ss, in.pk, in.msg, new byte[0], in.sig, comp);
        boolean match;
        try {
            boolean ok = (Boolean) op.call();
            boolean tamper = !(ml ? verifyMl(ms, in.pk, in.msg, new byte[0], in.tamperedSig(), comp) : verifySlh(ss, in.pk, in.msg, new byte[0], in.tamperedSig(), comp));
            match = ok && tamper;
            Timing.Stats s = Timing.measure(op, 1, budget, o -> Boolean.TRUE.equals(o));
            if (!s.match) match = false;
            s.put(line);
        } catch (Throwable t) { match = false; line.put("error", t.toString()); System.err.println("ERROR " + id + " " + alg.name + ": " + t); }
        int threads = 1;
        for (String v : comp.values()) threads = Math.max(threads, find(v).threads);
        line.put("threads", threads);
        line.put("output_sha256", match ? "true" : "false");
        line.put("match", match);
        line.put("composition", comp);
        sink.println(Json.write(line)); sink.flush();
        System.err.printf("%-16s %-18s %-20s n=%-6s median=%10.1f us match=%s %s%n", id, name, alg.name, line.get("iterations"),
            ((Number) line.getOrDefault("wall_ns_median", 0L)).longValue() / 1e3, match, comp);
    }

    static void runChild(SVariant v, String param, long budget, PrintStream sink) throws Exception {
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>();
        cmd.add(java); cmd.addAll(Arrays.asList(v.jvmFlags));
        cmd.add("-Dpqc.common=" + Bench.COMMON);
        cmd.add("-cp"); cmd.add(System.getProperty("pqc.classpath", System.getProperty("java.class.path")));
        cmd.add("Bench"); cmd.add("stages"); cmd.add("--child"); cmd.add("--out"); cmd.add("-");
        cmd.add("--budget-ms"); cmd.add(Long.toString(budget));
        cmd.add("--stages"); cmd.add(v.stage); cmd.add("--variants"); cmd.add(v.id); cmd.add("--params"); cmd.add(param);
        System.err.println("[child] " + String.join(" ", cmd));
        Process p = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null) if (l.startsWith("{")) { sink.println(l); sink.flush(); }
        }
        int rc = p.waitFor();
        if (rc != 0) System.err.println("[child] " + v.id + " exited with " + rc);
    }
}
