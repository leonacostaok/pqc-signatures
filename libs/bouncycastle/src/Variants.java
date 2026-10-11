import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/**
 * The 18 benchmark variants (6 per process) and the code that runs one operation (or one batch) of each.
 *
 * Code paths ("impl"):
 *   jca-fresh   : java.security API (KeyPairGenerator / Signature.getInstance(..., "BC")), new engine object per op
 *   jca-reuse   : java.security API, one engine object created+initialised once and reused for every op
 *   ll-fresh    : BC lightweight API (MLDSAKeyPairGenerator / MLDSASigner / SLHDSA*), new object + init per op
 *   ll-reuse    : BC lightweight API, signer/verifier initialised once (key unpacking + tr absorption done once)
 *   internal    : keygen straight from the seed, no SecureRandom indirection
 *                 (new MLDSAPrivateKeyParameters(params, seed, null) / SLHDSAKeyPairGenerator.internalGenerateKeyPair)
 *   parallel    : batch of ops spread over all cores, one reused lightweight engine per lane
 * JVM-flag variants reuse one of these code paths in a child JVM started with extra flags.
 */
final class Variants {
    static final int CORES = Runtime.getRuntime().availableProcessors();

    static final class Variant {
        final String id, name, desc, op, impl;
        final String[] jvmFlags; // null = run in the parent JVM (default flags)
        final int threads;
        Variant(String op, int n, String name, String desc, String impl, int threads, String... jvmFlags) {
            this.op = op; this.id = op + ".v" + n; this.name = name; this.desc = desc; this.impl = impl;
            this.threads = threads; this.jvmFlags = jvmFlags.length == 0 ? null : jvmFlags;
        }
    }

    static final String[] PARALLEL_GC = {"-XX:+UseParallelGC", "-Xms2g", "-Xmx2g", "-Xmn1200m", "-XX:+AlwaysPreTouch"};
    static final String[] C2_ONLY = {"-XX:-TieredCompilation"};
    static final String[] EPSILON = {"-XX:+UnlockExperimentalVMOptions", "-XX:+UseEpsilonGC", "-Xms8g", "-Xmx8g"};
    static final String[] INLINE = {"-XX:MaxInlineLevel=30", "-XX:MaxInlineSize=120", "-XX:FreqInlineSize=1200", "-XX:InlineSmallCode=6000", "-XX:MaxNodeLimit=240000", "-XX:NodeLimitFudgeFactor=8000"};

    static List<Variant> forOp(String op) {
        List<Variant> l = new ArrayList<>();
        switch (op) {
            case "keygen":
                l.add(new Variant(op, 0, "jca", "Baseline: KeyPairGenerator.getInstance(\"ML-DSA\"/\"SLH-DSA\",\"BC\") + initialize(spec, seedRandom) + generateKeyPair(), new generator per op.", "jca-fresh", 1));
                l.add(new Variant(op, 1, "jca-reuse", "JCA KeyPairGenerator created and initialised once, generateKeyPair() reused for every op (no provider lookup / re-init per op).", "jca-reuse", 1));
                l.add(new Variant(op, 2, "lightweight", "BC lightweight API: MLDSAKeyPairGenerator / SLHDSAKeyPairGenerator with a seed-returning SecureRandom, no JCA layer or key wrapper objects.", "ll-fresh", 1));
                l.add(new Variant(op, 3, "internal-seed", "Expand the seed directly: new MLDSAPrivateKeyParameters(params, seed, null) / SLHDSAKeyPairGenerator.internalGenerateKeyPair(skSeed, skPrf, pkSeed); no SecureRandom at all.", "internal", 1));
                l.add(new Variant(op, 4, "parallel", "Batch of seed expansions (internal-seed path) spread over all cores with a fixed thread pool; throughput per op.", "parallel", CORES));
                l.add(new Variant(op, 5, "parallelgc", "Lightweight path in a child JVM with -XX:+UseParallelGC, 2g pre-touched heap and a 1.2g young generation (cheaper allocation/barriers for the PolyVec-heavy keygen).", "ll-fresh", 1, PARALLEL_GC));
                break;
            case "sign":
                l.add(new Variant(op, 0, "jca", "Baseline: Signature.getInstance(\"ML-DSA\"/\"SLH-DSA\",\"BC\"), initSign(privateKey) (no SecureRandom => deterministic), update(msg), sign(); new Signature per op.", "jca-fresh", 1));
                l.add(new Variant(op, 1, "lightweight", "BC lightweight API: new MLDSASigner()/SLHDSASigner(), init(true, privateKeyParams), generateSignature(); new signer per op.", "ll-fresh", 1));
                l.add(new Variant(op, 2, "reuse-signer", "Lightweight signer initialised once and reused: key fields cloned and tr absorbed into the SHAKE state once, only update()+generateSignature() per op.", "ll-reuse", 1));
                l.add(new Variant(op, 3, "parallel", "Batch of signatures spread over all cores, each lane owns one initialised lightweight signer; throughput per op.", "parallel", CORES));
                l.add(new Variant(op, 4, "c2-only", "Lightweight path in a child JVM with -XX:-TieredCompilation (skip C1, compile straight to C2 with full profiling-free optimisation).", "ll-fresh", 1, C2_ONLY));
                l.add(new Variant(op, 5, "epsilon-nogc", "Lightweight path in a child JVM with Epsilon (no-op) GC and an 8g heap: no collections, no barriers; measures pure algorithm cost (loop stops before the heap fills).", "ll-fresh", 1, EPSILON));
                break;
            case "verify":
                l.add(new Variant(op, 0, "jca", "Baseline: Signature.getInstance(\"ML-DSA\"/\"SLH-DSA\",\"BC\"), initVerify(publicKey), update(msg), verify(sig); new Signature per op.", "jca-fresh", 1));
                l.add(new Variant(op, 1, "lightweight", "BC lightweight API: new MLDSASigner()/SLHDSASigner(), init(false, publicKeyParams), verifySignature(); new verifier per op.", "ll-fresh", 1));
                l.add(new Variant(op, 2, "reuse-verifier", "Lightweight verifier initialised once and reused: tr = H(rho||t1) and the pk unpacking are done once, only update()+verifySignature() per op.", "ll-reuse", 1));
                l.add(new Variant(op, 3, "parallel", "Batch of verifications spread over all cores, each lane owns one initialised lightweight verifier; throughput per op.", "parallel", CORES));
                l.add(new Variant(op, 4, "parallelgc", "Lightweight path in a child JVM with -XX:+UseParallelGC, 2g pre-touched heap and 1.2g young generation.", "ll-fresh", 1, PARALLEL_GC));
                l.add(new Variant(op, 5, "inline-aggressive", "Lightweight path in a child JVM with larger C2 inlining budgets (MaxInlineLevel/MaxInlineSize/FreqInlineSize/InlineSmallCode/MaxNodeLimit) so the NTT / Keccak helpers inline into their callers.", "ll-fresh", 1, INLINE));
                break;
            default: throw new IllegalArgumentException("unknown op " + op);
        }
        return l;
    }

    // ------------------------------------------------------------------ inputs for one param set

    static final class Inputs {
        final Alg alg; final byte[] seed, msg, pk, sk, sig;
        Inputs(Alg alg, byte[] seed, byte[] msg, byte[] pk, byte[] sk, byte[] sig) {
            this.alg = alg; this.seed = seed; this.msg = msg; this.pk = pk; this.sk = sk; this.sig = sig;
        }
        byte[] tamperedSig() { byte[] t = sig.clone(); t[t.length / 2] ^= 0x01; return t; }
    }

    /** Runs one op (or one batch of `batch` ops) and checks its output against the expected bytes. */
    abstract static class Runner implements AutoCloseable {
        int batch = 1;
        /** output of the first (warm-up) op, from which the output digest is taken */
        abstract Object run() throws Exception;
        /** true iff the output of run() equals the expected output (pk+sk / sig / true) */
        abstract boolean check(Object out) throws Exception;
        /** for verify variants: must return false for a tampered signature */
        boolean tamperRejected() throws Exception { return true; }
        public void close() {}
    }

    static Runner make(Variant v, Inputs in) throws Exception {
        switch (v.op) {
            case "keygen": return keygen(v, in);
            case "sign": return sign(v, in);
            case "verify": return verify(v, in);
        }
        throw new IllegalArgumentException(v.op);
    }

    // ------------------------------------------------------------------ keygen

    private static Runner keygen(Variant v, Inputs in) throws Exception {
        final Alg alg = in.alg;
        final Alg.SeedRandom rnd = new Alg.SeedRandom(in.seed);
        final byte[] pkcs8Expected = org.bouncycastle.crypto.util.PrivateKeyInfoFactory
            .createPrivateKeyInfo(alg.privFromBytes(in.sk)).getEncoded();

        abstract class KeygenRunner extends Runner {
            boolean checkPair(AsymmetricCipherKeyPair kp) {
                return Arrays.equals(Alg.pubBytes(kp), in.pk) && Arrays.equals(Alg.privBytes(kp), in.sk);
            }
        }
        switch (v.impl) {
            case "jca-fresh":
                return new KeygenRunner() {
                    Object run() throws Exception {
                        KeyPairGenerator g = KeyPairGenerator.getInstance(alg.jcaAlg, "BC");
                        g.initialize(alg.jcaSpec, rnd.reset());
                        return g.generateKeyPair();
                    }
                    boolean check(Object o) throws Exception { return checkJca((KeyPair) o, alg, in, pkcs8Expected); }
                };
            case "jca-reuse": {
                final KeyPairGenerator g = KeyPairGenerator.getInstance(alg.jcaAlg, "BC");
                g.initialize(alg.jcaSpec, rnd);
                return new KeygenRunner() {
                    Object run() { rnd.reset(); return g.generateKeyPair(); }
                    boolean check(Object o) throws Exception { return checkJca((KeyPair) o, alg, in, pkcs8Expected); }
                };
            }
            case "ll-fresh":
                return new KeygenRunner() {
                    Object run() { return llKeygen(alg, rnd.reset()); }
                    boolean check(Object o) { return checkPair((AsymmetricCipherKeyPair) o); }
                };
            case "internal":
                return new KeygenRunner() {
                    Object run() { return internalKeygen(alg, in.seed); }
                    boolean check(Object o) { return checkPair((AsymmetricCipherKeyPair) o); }
                };
            case "parallel":
                return new Parallel(v.threads) {
                    Object lane(int lane, int k) { return internalKeygen(alg, in.seed); }
                    boolean checkOne(Object o) { return Arrays.equals(Alg.pubBytes((AsymmetricCipherKeyPair) o), in.pk) && Arrays.equals(Alg.privBytes((AsymmetricCipherKeyPair) o), in.sk); }
                };
        }
        throw new IllegalArgumentException(v.impl);
    }

    static boolean checkJca(KeyPair kp, Alg alg, Inputs in, byte[] pkcs8Expected) throws Exception {
        byte[] pk = alg.family == Alg.Family.MLDSA ? ((MLDSAPublicKey) kp.getPublic()).getPublicData()
                                                   : ((SLHDSAPublicKey) kp.getPublic()).getPublicData();
        if (!Arrays.equals(pk, in.pk)) return false;
        if (alg.family == Alg.Family.MLDSA) return Arrays.equals(((MLDSAPrivateKey) kp.getPrivate()).getPrivateData(), in.sk);
        // SLH-DSA JCA key has no raw accessor: compare the PKCS#8 encoding (cheap) to the expected one
        return Arrays.equals(kp.getPrivate().getEncoded(), pkcs8Expected);
    }

    static AsymmetricCipherKeyPair llKeygen(Alg alg, java.security.SecureRandom rnd) {
        if (alg.family == Alg.Family.MLDSA) {
            MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
            g.init(new MLDSAKeyGenerationParameters(rnd, alg.mldsa));
            return g.generateKeyPair();
        }
        SLHDSAKeyPairGenerator g = new SLHDSAKeyPairGenerator();
        g.init(new SLHDSAKeyGenerationParameters(rnd, alg.slhdsa));
        return g.generateKeyPair();
    }

    static AsymmetricCipherKeyPair internalKeygen(Alg alg, byte[] seed) {
        if (alg.family == Alg.Family.MLDSA) {
            MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(alg.mldsa, seed, null); // 32-byte seed => KeyGen_internal
            return new AsymmetricCipherKeyPair(sk.getPublicKeyParameters(), sk);
        }
        int n = alg.slhdsa.getN();
        SLHDSAKeyPairGenerator g = new SLHDSAKeyPairGenerator();
        g.init(new SLHDSAKeyGenerationParameters(null, alg.slhdsa));
        return g.internalGenerateKeyPair(Arrays.copyOfRange(seed, 0, n), Arrays.copyOfRange(seed, n, 2 * n), Arrays.copyOfRange(seed, 2 * n, 3 * n));
    }

    // ------------------------------------------------------------------ sign

    private static Runner sign(Variant v, Inputs in) throws Exception {
        final Alg alg = in.alg;
        final AsymmetricKeyParameter skp = alg.privFromBytes(in.sk);
        abstract class SignRunner extends Runner {
            boolean check(Object o) { return Arrays.equals((byte[]) o, in.sig); }
        }
        switch (v.impl) {
            case "jca-fresh": {
                final PrivateKey key = alg.jcaPrivate(in.sk);
                return new SignRunner() {
                    Object run() throws Exception {
                        Signature s = Signature.getInstance(alg.jcaAlg, "BC");
                        s.initSign(key);           // no SecureRandom => BC signs deterministically
                        s.update(in.msg);
                        return s.sign();
                    }
                };
            }
            case "ll-fresh":
                return new SignRunner() {
                    Object run() throws Exception { return llSign(alg, skp, in.msg); }
                };
            case "ll-reuse": {
                final Object signer = alg.family == Alg.Family.MLDSA ? new MLDSASigner() : new SLHDSASigner();
                if (signer instanceof MLDSASigner) ((MLDSASigner) signer).init(true, skp); else ((SLHDSASigner) signer).init(true, skp);
                return new SignRunner() {
                    Object run() throws Exception {
                        if (signer instanceof MLDSASigner) {
                            MLDSASigner s = (MLDSASigner) signer;
                            s.update(in.msg, 0, in.msg.length);
                            return s.generateSignature();
                        }
                        return ((SLHDSASigner) signer).generateSignature(in.msg);
                    }
                };
            }
            case "parallel": {
                final Object[] lanes = new Object[v.threads];
                for (int i = 0; i < lanes.length; i++) {
                    Object s = alg.family == Alg.Family.MLDSA ? new MLDSASigner() : new SLHDSASigner();
                    if (s instanceof MLDSASigner) ((MLDSASigner) s).init(true, skp); else ((SLHDSASigner) s).init(true, skp);
                    lanes[i] = s;
                }
                return new Parallel(v.threads) {
                    Object lane(int lane, int k) throws Exception {
                        if (lanes[lane] instanceof MLDSASigner) {
                            MLDSASigner s = (MLDSASigner) lanes[lane];
                            s.update(in.msg, 0, in.msg.length);
                            return s.generateSignature();
                        }
                        return ((SLHDSASigner) lanes[lane]).generateSignature(in.msg);
                    }
                    boolean checkOne(Object o) { return Arrays.equals((byte[]) o, in.sig); }
                };
            }
        }
        throw new IllegalArgumentException(v.impl);
    }

    static byte[] llSign(Alg alg, AsymmetricKeyParameter skp, byte[] msg) throws Exception {
        if (alg.family == Alg.Family.MLDSA) {
            MLDSASigner s = new MLDSASigner();
            s.init(true, skp);                 // no ParametersWithRandom => rnd = 0^32 (deterministic)
            s.update(msg, 0, msg.length);
            return s.generateSignature();
        }
        SLHDSASigner s = new SLHDSASigner();
        s.init(true, skp);                     // no ParametersWithRandom => opt_rand = PK.seed (deterministic)
        return s.generateSignature(msg);
    }

    // ------------------------------------------------------------------ verify

    private static Runner verify(Variant v, Inputs in) throws Exception {
        final Alg alg = in.alg;
        final AsymmetricKeyParameter pkp = alg.pubFromBytes(in.pk);
        final byte[] bad = in.tamperedSig();
        abstract class VerifyRunner extends Runner {
            boolean check(Object o) { return Boolean.TRUE.equals(o); }
            abstract boolean verify(byte[] sig) throws Exception;
            Object run() throws Exception { return verify(in.sig); }
            boolean tamperRejected() throws Exception { return !verify(bad); }
        }
        switch (v.impl) {
            case "jca-fresh": {
                final PublicKey key = alg.jcaPublic(in.pk);
                return new VerifyRunner() {
                    boolean verify(byte[] sig) throws Exception {
                        Signature s = Signature.getInstance(alg.jcaAlg, "BC");
                        s.initVerify(key);
                        s.update(in.msg);
                        return s.verify(sig);
                    }
                };
            }
            case "ll-fresh":
                return new VerifyRunner() {
                    boolean verify(byte[] sig) { return llVerify(alg, pkp, in.msg, sig); }
                };
            case "ll-reuse": {
                final Object ver = alg.family == Alg.Family.MLDSA ? new MLDSASigner() : new SLHDSASigner();
                if (ver instanceof MLDSASigner) ((MLDSASigner) ver).init(false, pkp); else ((SLHDSASigner) ver).init(false, pkp);
                return new VerifyRunner() {
                    boolean verify(byte[] sig) {
                        if (ver instanceof MLDSASigner) {
                            MLDSASigner s = (MLDSASigner) ver;
                            s.update(in.msg, 0, in.msg.length);
                            return s.verifySignature(sig);
                        }
                        return ((SLHDSASigner) ver).verifySignature(in.msg, sig);
                    }
                };
            }
            case "parallel": {
                final Object[] lanes = new Object[v.threads];
                for (int i = 0; i < lanes.length; i++) {
                    Object s = alg.family == Alg.Family.MLDSA ? new MLDSASigner() : new SLHDSASigner();
                    if (s instanceof MLDSASigner) ((MLDSASigner) s).init(false, pkp); else ((SLHDSASigner) s).init(false, pkp);
                    lanes[i] = s;
                }
                return new Parallel(v.threads) {
                    byte[] sig = in.sig;
                    Object lane(int lane, int k) {
                        if (lanes[lane] instanceof MLDSASigner) {
                            MLDSASigner s = (MLDSASigner) lanes[lane];
                            s.update(in.msg, 0, in.msg.length);
                            return s.verifySignature(sig);
                        }
                        return ((SLHDSASigner) lanes[lane]).verifySignature(in.msg, sig);
                    }
                    boolean checkOne(Object o) { return Boolean.TRUE.equals(o); }
                    boolean tamperRejected() throws Exception {
                        sig = bad;
                        try { for (Object o : (Object[]) run()) if (Boolean.TRUE.equals(o)) return false; return true; }
                        finally { sig = in.sig; }
                    }
                };
            }
        }
        throw new IllegalArgumentException(v.impl);
    }

    static boolean llVerify(Alg alg, AsymmetricKeyParameter pkp, byte[] msg, byte[] sig) {
        if (alg.family == Alg.Family.MLDSA) {
            MLDSASigner s = new MLDSASigner();
            s.init(false, pkp);
            s.update(msg, 0, msg.length);
            return s.verifySignature(sig);
        }
        if (alg.family == Alg.Family.SLHDSA) {
            SLHDSASigner s = new SLHDSASigner();
            s.init(false, pkp);
            return s.verifySignature(msg, sig);
        }
        org.bouncycastle.pqc.crypto.falcon.FalconSigner s = new org.bouncycastle.pqc.crypto.falcon.FalconSigner();
        s.init(false, pkp);
        return s.verifySignature(msg, alg.falconNormaliseSig(sig));
    }

    // ------------------------------------------------------------------ parallel batch runner

    /** One batch = `threads` lanes x `perLane` ops; batch size is tuned by the driver via setPerLane(). */
    abstract static class Parallel extends Runner {
        final int threads;
        final ExecutorService pool;
        int perLane = 1;
        Parallel(int threads) {
            this.threads = threads;
            this.batch = threads;
            pool = Executors.newFixedThreadPool(threads, r -> { Thread t = new Thread(r, "bench-lane"); t.setDaemon(true); return t; });
        }
        void setPerLane(int k) { perLane = k; batch = threads * k; }
        abstract Object lane(int lane, int k) throws Exception;
        abstract boolean checkOne(Object o) throws Exception;

        Object run() throws Exception {
            final Object[] out = new Object[batch];
            List<Callable<Void>> tasks = new ArrayList<>(threads);
            for (int l = 0; l < threads; l++) {
                final int lane = l;
                tasks.add(() -> { for (int k = 0; k < perLane; k++) out[lane * perLane + k] = lane(lane, k); return null; });
            }
            for (Future<Void> f : pool.invokeAll(tasks)) f.get();
            return out;
        }
        boolean check(Object o) throws Exception {
            for (Object x : (Object[]) o) if (!checkOne(x)) return false;
            return true;
        }
        public void close() { pool.shutdownNow(); }
    }

    /** Output bytes used for the output_sha256 field (first element for batches). */
    static Object first(Object out) { return out instanceof Object[] ? ((Object[]) out)[0] : out; }

    static byte[] keygenPk(Object out) {
        Object o = first(out);
        if (o instanceof KeyPair) {
            KeyPair kp = (KeyPair) o;
            return kp.getPublic() instanceof MLDSAPublicKey ? ((MLDSAPublicKey) kp.getPublic()).getPublicData() : ((SLHDSAPublicKey) kp.getPublic()).getPublicData();
        }
        return Alg.pubBytes((AsymmetricCipherKeyPair) o);
    }

    static byte[] keygenSk(Object out) throws Exception {
        Object o = first(out);
        if (o instanceof KeyPair) {
            KeyPair kp = (KeyPair) o;
            if (kp.getPrivate() instanceof MLDSAPrivateKey) return ((MLDSAPrivateKey) kp.getPrivate()).getPrivateData();
            return Alg.privBytes((AsymmetricKeyParameter) PrivateKeyFactory.createKey(kp.getPrivate().getEncoded()));
        }
        return Alg.privBytes((AsymmetricCipherKeyPair) o);
    }
}
