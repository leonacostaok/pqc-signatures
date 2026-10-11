import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;

/**
 * One-shot, context-aware keygen / sign / verify through each bench variant's code path, for the validation
 * suite. "reuse" variants keep their initialised engine per (key, context) in a cache, exactly as a long-lived
 * verifier would; "parallel" variants run the case on every lane and require all lanes to agree.
 */
final class CaseOps {
    static final Map<String, Object> CACHE = new ConcurrentHashMap<>();
    static final ExecutorService POOL = Executors.newFixedThreadPool(Variants.CORES, r -> { Thread t = new Thread(r, "case-lane"); t.setDaemon(true); return t; });

    static Object cached(String key, Callable<Object> f) throws Exception {
        Object o = CACHE.get(key);
        if (o == null) { if (CACHE.size() > 256) CACHE.clear(); o = f.call(); CACHE.put(key, o); }
        return o;
    }
    static String kkey(Variants.Variant v, Alg alg, byte[] key, byte[] ctx) {
        return v.id + "|" + alg.name + "|" + Alg.sha256Hex(key) + "|" + Alg.hex(ctx);
    }

    static <T> T allLanes(int threads, Callable<T> op, java.util.function.BiPredicate<T, T> eq) throws Exception {
        List<Callable<T>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) tasks.add(op);
        List<T> outs = new ArrayList<>();
        for (Future<T> f : POOL.invokeAll(tasks)) outs.add(f.get());
        for (T o : outs) if (!eq.test(outs.get(0), o)) throw new IllegalStateException("lanes disagree");
        return outs.get(0);
    }

    // ---------------------------------------------------------------- keygen

    static byte[][] keygen(Variants.Variant v, Alg alg, byte[] seed) throws Exception {
        switch (v.impl) {
            case "jca-fresh": {
                KeyPairGenerator g = KeyPairGenerator.getInstance(alg.jcaAlg, "BC");
                g.initialize(alg.jcaSpec, new Alg.SeedRandom(seed));
                return jcaPair(g.generateKeyPair());
            }
            case "jca-reuse": {
                Alg.SeedRandom rnd = new Alg.SeedRandom(seed);
                String key = v.id + "|" + alg.name;
                // one generator per param, re-seeded per case through a shared SeedRandom holder
                Object[] holder = (Object[]) cached(key, () -> {
                    Alg.SeedRandom r = new Alg.SeedRandom(new byte[0]);
                    KeyPairGenerator g = KeyPairGenerator.getInstance(alg.jcaAlg, "BC");
                    SwitchableRandom sr = new SwitchableRandom();
                    g.initialize(alg.jcaSpec, sr);
                    return new Object[]{g, sr};
                });
                ((SwitchableRandom) holder[1]).delegate = rnd;
                return jcaPair(((KeyPairGenerator) holder[0]).generateKeyPair());
            }
            case "ll-fresh": return llPair(Variants.llKeygen(alg, new Alg.SeedRandom(seed)));
            case "internal": return llPair(Variants.internalKeygen(alg, seed));
            case "parallel": return allLanes(v.threads, () -> llPair(Variants.internalKeygen(alg, seed)), (x, y) -> Arrays.equals(x[0], y[0]) && Arrays.equals(x[1], y[1]));
        }
        throw new IllegalArgumentException(v.impl);
    }

    /** SecureRandom whose byte source can be swapped: lets a reused JCA generator be fed a new seed per case */
    static final class SwitchableRandom extends java.security.SecureRandom {
        volatile Alg.SeedRandom delegate;
        @Override public void nextBytes(byte[] b) { delegate.nextBytes(b); }
    }

    static byte[][] jcaPair(java.security.KeyPair kp) throws Exception { return new byte[][]{Variants.keygenPk(kp), Variants.keygenSk(kp)}; }
    static byte[][] llPair(AsymmetricCipherKeyPair kp) { return new byte[][]{Alg.pubBytes(kp), Alg.privBytes(kp)}; }

    // ---------------------------------------------------------------- sign

    static CipherParameters withCtx(AsymmetricKeyParameter k, byte[] ctx) {
        return ctx.length == 0 ? k : new ParametersWithContext(k, ctx);
    }

    static Object newSigner(Alg alg, boolean forSigning, CipherParameters p) {
        if (alg.family == Alg.Family.MLDSA) { MLDSASigner s = new MLDSASigner(); s.init(forSigning, p); return s; }
        SLHDSASigner s = new SLHDSASigner(); s.init(forSigning, p); return s;
    }
    static byte[] signWith(Object signer, byte[] msg) throws Exception {
        if (signer instanceof MLDSASigner) { MLDSASigner s = (MLDSASigner) signer; s.update(msg, 0, msg.length); return s.generateSignature(); }
        return ((SLHDSASigner) signer).generateSignature(msg);
    }
    static boolean verifyWith(Object signer, byte[] msg, byte[] sig) {
        if (signer instanceof MLDSASigner) { MLDSASigner s = (MLDSASigner) signer; s.update(msg, 0, msg.length); return s.verifySignature(sig); }
        return ((SLHDSASigner) signer).verifySignature(msg, sig);
    }

    static byte[] sign(Variants.Variant v, Alg alg, byte[] sk, byte[] msg, byte[] ctx) throws Exception {
        switch (v.impl) {
            case "jca-fresh": {
                PrivateKey key = alg.jcaPrivate(sk);
                Signature s = Signature.getInstance(alg.jcaAlg, "BC");
                if (ctx.length > 0) s.setParameter(new ContextParameterSpec(ctx));
                s.initSign(key);
                s.update(msg);
                return s.sign();
            }
            case "ll-fresh": return signWith(newSigner(alg, true, withCtx(alg.privFromBytes(sk), ctx)), msg);
            case "ll-reuse": {
                Object signer = cached(kkey(v, alg, sk, ctx), () -> newSigner(alg, true, withCtx(alg.privFromBytes(sk), ctx)));
                synchronized (signer) { return signWith(signer, msg); }
            }
            case "parallel": {
                AsymmetricKeyParameter skp = alg.privFromBytes(sk);
                Object[] lanes = new Object[v.threads];
                for (int i = 0; i < lanes.length; i++) lanes[i] = newSigner(alg, true, withCtx(skp, ctx));
                List<Callable<byte[]>> tasks = new ArrayList<>();
                for (int i = 0; i < lanes.length; i++) { final Object s = lanes[i]; tasks.add(() -> signWith(s, msg)); }
                byte[] first = null;
                for (Future<byte[]> f : POOL.invokeAll(tasks)) { byte[] o = f.get(); if (first == null) first = o; else if (!Arrays.equals(first, o)) throw new IllegalStateException("lanes disagree"); }
                return first;
            }
        }
        throw new IllegalArgumentException(v.impl);
    }

    // ---------------------------------------------------------------- verify

    static boolean verify(Variants.Variant v, Alg alg, byte[] pk, byte[] msg, byte[] ctx, byte[] sig) throws Exception {
        switch (v.impl) {
            case "jca-fresh": {
                PublicKey key = alg.jcaPublic(pk);
                Signature s = Signature.getInstance(alg.jcaAlg, "BC");
                if (ctx.length > 0) s.setParameter(new ContextParameterSpec(ctx));
                s.initVerify(key);
                s.update(msg);
                return s.verify(sig);
            }
            case "ll-fresh": return verifyWith(newSigner(alg, false, withCtx(alg.pubFromBytes(pk), ctx)), msg, sig);
            case "ll-reuse": {
                Object ver = cached(kkey(v, alg, pk, ctx), () -> newSigner(alg, false, withCtx(alg.pubFromBytes(pk), ctx)));
                synchronized (ver) { return verifyWith(ver, msg, sig); }
            }
            case "parallel": {
                AsymmetricKeyParameter pkp = alg.pubFromBytes(pk);
                Object[] lanes = new Object[v.threads];
                for (int i = 0; i < lanes.length; i++) lanes[i] = newSigner(alg, false, withCtx(pkp, ctx));
                List<Callable<Boolean>> tasks = new ArrayList<>();
                for (int i = 0; i < lanes.length; i++) { final Object s = lanes[i]; tasks.add(() -> verifyWith(s, msg, sig)); }
                Boolean first = null;
                for (Future<Boolean> f : POOL.invokeAll(tasks)) { Boolean o = f.get(); if (first == null) first = o; else if (!first.equals(o)) throw new IllegalStateException("lanes disagree"); }
                return first;
            }
        }
        throw new IllegalArgumentException(v.impl);
    }
}
