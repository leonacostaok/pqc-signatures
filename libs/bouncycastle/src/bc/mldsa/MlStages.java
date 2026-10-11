package bc.mldsa;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.MLDSAParameters;

import bc.Keccak;

/**
 * ML-DSA verification split into the canonical stages (FIPS 204 Alg. 8 + external wrapper), built on the
 * vendored BC engine classes of this package, plus the stage alternatives. Each stage has a v0 that calls
 * exactly the code BC's MLDSAEngine.verifyInternal runs, and alternatives that re-implement the stage.
 */
public final class MlStages {
    private static final VarHandle LE_LONG = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
    private static final VarHandle LE_INT = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);
    static final int N = MLDSAEngine.DilithiumN, Q = MLDSAEngine.DilithiumQ, D = MLDSAEngine.DilithiumD;

    public final MLDSAParameters params;
    public final MLDSAEngine eng;
    public final int K, L, CTILDE, PKBYTES, SIGBYTES, GAMMA1, GAMMA2, BETA, OMEGA, ZPACKED, W1PACKED;

    public MlStages(MLDSAParameters params) {
        this.params = params;
        this.eng = MLDSAEngine.getInstance(params, null);
        K = eng.getDilithiumK(); L = eng.getDilithiumL(); CTILDE = eng.getDilithiumCTilde();
        PKBYTES = eng.getCryptoPublicKeyBytes();
        GAMMA1 = eng.getDilithiumGamma1(); GAMMA2 = eng.getDilithiumGamma2(); BETA = eng.getDilithiumBeta();
        OMEGA = eng.getDilithiumOmega(); ZPACKED = eng.getDilithiumPolyZPackedBytes(); W1PACKED = eng.getDilithiumPolyW1PackedBytes();
        SIGBYTES = CTILDE + L * ZPACKED + OMEGA + K;
    }

    /** a fresh engine for another thread (BC engines own a Symmetric with shared SHAKE state) */
    MLDSAEngine newEngine() { return MLDSAEngine.getInstance(params, null); }

    // ================================================================= stage 1: decode

    public static final class Decoded {
        public byte[] rho, cTilde;
        PolyVec t1, z, h;
    }

    /** v0: BC's Packing.unpackPublicKey + Packing.unpackSignature (hint validity included). null = malformed. */
    public Decoded decode(byte[] pk, byte[] sig) {
        if (pk.length != PKBYTES || sig.length != SIGBYTES) return null;
        Decoded d = new Decoded();
        d.rho = java.util.Arrays.copyOf(pk, MLDSAEngine.SeedBytes);
        d.t1 = Packing.unpackPublicKey(new PolyVec(eng, K), java.util.Arrays.copyOfRange(pk, MLDSAEngine.SeedBytes, pk.length), eng);
        d.z = new PolyVec(eng, L); d.h = new PolyVec(eng, K);
        if (!Packing.unpackSignature(d.z, d.h, sig, eng)) return null;
        d.cTilde = java.util.Arrays.copyOf(sig, CTILDE);
        return d;
    }

    /** v1: same decoding with 64-bit little-endian word loads (VarHandle) instead of byte-by-byte assembly. */
    public Decoded decodeWide(byte[] pk, byte[] sig) {
        if (pk.length != PKBYTES || sig.length != SIGBYTES) return null;
        Decoded d = new Decoded();
        d.rho = java.util.Arrays.copyOf(pk, MLDSAEngine.SeedBytes);
        d.t1 = new PolyVec(eng, K);
        for (int i = 0; i < K; i++) unpackT1Wide(d.t1.getVectorIndex(i).getCoeffs(), pk, MLDSAEngine.SeedBytes + i * MLDSAEngine.DilithiumPolyT1PackedBytes);
        d.z = new PolyVec(eng, L); d.h = new PolyVec(eng, K);
        for (int i = 0; i < L; i++) unpackZWide(d.z.getVectorIndex(i).getCoeffs(), sig, CTILDE + i * ZPACKED);
        if (!unpackHints(d.h, sig, CTILDE + L * ZPACKED)) return null;
        d.cTilde = java.util.Arrays.copyOf(sig, CTILDE);
        return d;
    }

    private static void unpackT1Wide(int[] c, byte[] a, int off) {
        for (int i = 0; i < N / 4; i++) {
            long v = (i < 63) ? (long) LE_LONG.get(a, off + 5 * i)
                              : ((int) LE_INT.get(a, off + 5 * i) & 0xffffffffL) | ((long) (a[off + 5 * i + 4] & 0xff) << 32);
            c[4 * i] = (int) (v & 0x3ff); c[4 * i + 1] = (int) ((v >>> 10) & 0x3ff);
            c[4 * i + 2] = (int) ((v >>> 20) & 0x3ff); c[4 * i + 3] = (int) ((v >>> 30) & 0x3ff);
        }
    }

    private void unpackZWide(int[] c, byte[] a, int off) {
        if (GAMMA1 == (1 << 17)) {
            for (int i = 0; i < N / 4; i++) {
                long v = (long) LE_LONG.get(a, off + 9 * i);
                int hi = a[off + 9 * i + 8] & 0xff;
                c[4 * i] = GAMMA1 - (int) (v & 0x3ffff);
                c[4 * i + 1] = GAMMA1 - (int) ((v >>> 18) & 0x3ffff);
                c[4 * i + 2] = GAMMA1 - (int) ((v >>> 36) & 0x3ffff);
                c[4 * i + 3] = GAMMA1 - ((int) (v >>> 54) | (hi << 10));
            }
        } else {
            for (int i = 0; i < N / 2; i++) {
                long v = (i < 127) ? (long) LE_LONG.get(a, off + 5 * i)
                                   : ((int) LE_INT.get(a, off + 5 * i) & 0xffffffffL) | ((long) (a[off + 5 * i + 4] & 0xff) << 32);
                c[2 * i] = GAMMA1 - (int) (v & 0xfffff);
                c[2 * i + 1] = GAMMA1 - (int) ((v >>> 20) & 0xfffff);
            }
        }
    }

    /** hint decoding with the FIPS 204 validity rules (same checks as BC's unpackSignature) */
    private boolean unpackHints(PolyVec h, byte[] sig, int end) {
        int k = 0;
        for (int i = 0; i < K; i++) {
            int[] hc = h.getVectorIndex(i).getCoeffs();
            java.util.Arrays.fill(hc, 0);
            int cnt = sig[end + OMEGA + i] & 0xff;
            if (cnt < k || cnt > OMEGA) return false;
            for (int j = k; j < cnt; j++) {
                int idx = sig[end + j] & 0xff;
                if (j > k && idx <= (sig[end + j - 1] & 0xff)) return false;
                hc[idx] = 1;
            }
            k = cnt;
        }
        for (int j = k; j < OMEGA; j++) if (sig[end + j] != 0) return false;
        return true;
    }

    // ================================================================= stage 2: mu

    private static byte[] mPrime(byte[] ctx, byte[] msg) {
        byte[] p = new byte[2 + ctx.length + msg.length];
        p[1] = (byte) ctx.length;
        System.arraycopy(ctx, 0, p, 2, ctx.length);
        System.arraycopy(msg, 0, p, 2 + ctx.length, msg.length);
        return p;
    }

    /** v0: BC SHAKEDigest; tr = H(pk, 64), mu = H(tr || 0 || |ctx| || ctx || M, 64) */
    public static byte[] mu(byte[] pk, byte[] ctx, byte[] msg) {
        SHAKEDigest d = new SHAKEDigest(256);
        byte[] tr = new byte[64];
        d.update(pk, 0, pk.length); d.doFinal(tr, 0, 64);
        return muFromTr(tr, ctx, msg);
    }

    /** v1 (cached tr): tr precomputed once per public key */
    public static byte[] tr(byte[] pk) {
        SHAKEDigest d = new SHAKEDigest(256);
        byte[] tr = new byte[64];
        d.update(pk, 0, pk.length); d.doFinal(tr, 0, 64);
        return tr;
    }
    public static byte[] muFromTr(byte[] tr, byte[] ctx, byte[] msg) {
        SHAKEDigest d = new SHAKEDigest(256);
        byte[] mu = new byte[64];
        d.update(tr, 0, 64);
        d.update((byte) 0); d.update((byte) ctx.length);
        d.update(ctx, 0, ctx.length); d.update(msg, 0, msg.length);
        d.doFinal(mu, 0, 64);
        return mu;
    }

    /** v2: own Keccak sponge (bc.Keccak) instead of BC's SHAKEDigest */
    public static byte[] muKeccak(byte[] pk, byte[] ctx, byte[] msg) {
        Keccak k = Keccak.shake256();
        k.update(pk);
        byte[] tr = k.squeeze(64);
        k.reset();
        k.update(tr).update((byte) 0).update((byte) ctx.length).update(ctx).update(msg);
        return k.squeeze(64);
    }

    // ================================================================= stage 3: expandA

    /** v0: BC PolyVecMatrix.expandMatrix (SHAKE128(rho || j || i) + rejection sampling per polynomial) */
    public PolyVecMatrix expandA(byte[] rho) {
        PolyVecMatrix a = new PolyVecMatrix(eng);
        a.expandMatrix(rho);
        return a;
    }

    /** v2: rows expanded concurrently, one BC engine per task */
    public PolyVecMatrix expandAParallel(byte[] rho, ExecutorService pool, int threads) throws Exception {
        PolyVecMatrix a = new PolyVecMatrix(eng);
        List<Callable<Void>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int lane = t;
            tasks.add(() -> {
                MLDSAEngine e = newEngine();
                for (int i = lane; i < K; i += threads) {
                    PolyVec row = new PolyVec(e, L);
                    row.uniformBlocks(rho, i << 8);
                    for (int j = 0; j < L; j++) System.arraycopy(row.getVectorIndex(j).getCoeffs(), 0, a.row(i).getVectorIndex(j).getCoeffs(), 0, N);
                }
                return null;
            });
        }
        for (Future<Void> f : pool.invokeAll(tasks)) f.get();
        return a;
    }

    /** v3: own SHAKE128 sponge, sampling 3-byte triples straight out of the squeezed block (no block copies) */
    public PolyVecMatrix expandAKeccak(byte[] rho) {
        PolyVecMatrix a = new PolyVecMatrix(eng);
        Keccak k = Keccak.shake128();
        for (int i = 0; i < K; i++) for (int j = 0; j < L; j++) {
            int[] c = a.row(i).getVectorIndex(j).getCoeffs();
            k.reset();
            k.update(rho).update((byte) j).update((byte) i);
            k.finish();
            byte[] blk = k.block; int pos = 0, ctr = 0;
            while (ctr < N) {
                if (pos + 3 > k.rate) { k.nextBlock(); pos = 0; }
                int t = ((blk[pos] & 0xff) | (blk[pos + 1] & 0xff) << 8 | (blk[pos + 2] & 0xff) << 16) & 0x7fffff;
                pos += 3;
                if (t < Q) c[ctr++] = t;
            }
        }
        return a;
    }

    // ================================================================= stage 4: w_approx

    private static PolyVec copy(MLDSAEngine e, PolyVec v) {
        PolyVec c = new PolyVec(e, v.length());
        v.copyTo(c);
        return c;
    }

    /** NTT(t1 * 2^d), precomputable per public key (used by the cached variant) */
    public PolyVec t1Ntt(Decoded d) {
        PolyVec t = copy(eng, d.t1);
        t.shiftLeft(); t.polyVecNtt();
        return t;
    }

    /** v0: exactly BC's sequence: NTT(z); A o z; NTT(c); t1<<d; NTT(t1); c o t1; sub; reduce; invNTT; caddq */
    public PolyVec wApprox(PolyVecMatrix a, Decoded d) {
        PolyVec z = copy(eng, d.z), t1 = copy(eng, d.t1);
        Poly cp = new Poly(eng);
        PolyVec w1 = new PolyVec(eng, K);
        cp.challenge(d.cTilde, 0, CTILDE);
        z.polyVecNtt();
        a.pointwiseMontgomery(w1, z);
        cp.polyNtt();
        t1.shiftLeft(); t1.polyVecNtt();
        t1.pointwisePolyMontgomery(cp, t1);
        w1.subtract(t1); w1.reduce(); w1.invNttToMont(); w1.conditionalAddQ();
        return w1;
    }

    /** v1: same, but NTT(t1 * 2^d) comes precomputed (cached per public key) */
    public PolyVec wApproxCachedT1(PolyVecMatrix a, Decoded d, PolyVec t1Ntt) {
        PolyVec z = copy(eng, d.z), t1 = copy(eng, t1Ntt);
        Poly cp = new Poly(eng);
        PolyVec w1 = new PolyVec(eng, K);
        cp.challenge(d.cTilde, 0, CTILDE);
        z.polyVecNtt();
        a.pointwiseMontgomery(w1, z);
        cp.polyNtt();
        t1.pointwisePolyMontgomery(cp, t1);
        w1.subtract(t1); w1.reduce(); w1.invNttToMont(); w1.conditionalAddQ();
        return w1;
    }

    /** v2: NTT(z), NTT(c) once, then the k output rows on a thread pool */
    public PolyVec wApproxParallel(PolyVecMatrix a, Decoded d, ExecutorService pool, int threads) throws Exception {
        PolyVec z = copy(eng, d.z);
        Poly cp = new Poly(eng);
        cp.challenge(d.cTilde, 0, CTILDE);
        z.polyVecNtt(); cp.polyNtt();
        PolyVec w1 = new PolyVec(eng, K);
        List<Callable<Void>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int lane = t;
            tasks.add(() -> {
                for (int i = lane; i < K; i += threads) {
                    Poly wi = w1.getVectorIndex(i);
                    wi.pointwiseAccountMontgomery(a.row(i), z);
                    Poly ti = new Poly(eng);
                    d.t1.getVectorIndex(i).copyTo(ti);
                    ti.shiftLeft(); ti.polyNtt(); ti.pointwiseMontgomery(cp, ti);
                    wi.subtract(ti); wi.reduce(); wi.invNttToMont(); wi.conditionalAddQ();
                }
                return null;
            });
        }
        for (Future<Void> f : pool.invokeAll(tasks)) f.get();
        return w1;
    }

    /** v3: one 64-bit accumulator per coefficient over all l products and the c*t1 term, one Montgomery reduction */
    public PolyVec wApproxLongAccum(PolyVecMatrix a, Decoded d) {
        PolyVec z = copy(eng, d.z), t1 = copy(eng, d.t1);
        Poly cp = new Poly(eng);
        cp.challenge(d.cTilde, 0, CTILDE);
        z.polyVecNtt(); cp.polyNtt();
        t1.shiftLeft(); t1.polyVecNtt();
        int[] c = cp.getCoeffs();
        PolyVec w1 = new PolyVec(eng, K);
        for (int i = 0; i < K; i++) {
            int[] w = w1.getVectorIndex(i).getCoeffs();
            int[] t = t1.getVectorIndex(i).getCoeffs();
            for (int n = 0; n < N; n++) {
                long acc = -(long) c[n] * t[n];
                for (int j = 0; j < L; j++) acc += (long) a.row(i).getVectorIndex(j).getCoeffs()[n] * z.getVectorIndex(j).getCoeffs()[n];
                w[n] = Reduce.montgomeryReduce(acc);
            }
        }
        w1.reduce(); w1.invNttToMont(); w1.conditionalAddQ();
        return w1;
    }

    // ================================================================= stage 5: hint_check

    public static final class HintResult { public boolean ok; public byte[] w1Enc; }

    /** v0: BC's checkNorm, PolyVec.useHint, packW1 and SHAKEDigest challenge recomputation */
    public HintResult hintCheck(byte[] mu, PolyVec w, Decoded d) {
        HintResult r = new HintResult();
        if (d.z.checkNorm(GAMMA1 - BETA)) { r.ok = false; r.w1Enc = new byte[0]; return r; }
        PolyVec w1 = copy(eng, w);
        w1.useHint(w1, d.h);
        byte[] buf = new byte[64 + K * W1PACKED];
        System.arraycopy(mu, 0, buf, 0, 64);
        w1.packW1(eng, buf, 64);
        SHAKEDigest sh = new SHAKEDigest(256);
        sh.update(buf, 0, buf.length);
        byte[] c2 = new byte[CTILDE];
        sh.doFinal(c2, 0, CTILDE);
        r.w1Enc = java.util.Arrays.copyOfRange(buf, 64, buf.length);
        r.ok = org.bouncycastle.util.Arrays.constantTimeAreEqual(c2, d.cTilde);
        return r;
    }

    /** v1: decompose + UseHint + w1Encode fused into one pass that writes the packed bytes directly */
    public HintResult hintCheckFused(byte[] mu, PolyVec w, Decoded d) {
        HintResult r = new HintResult();
        if (d.z.checkNorm(GAMMA1 - BETA)) { r.ok = false; r.w1Enc = new byte[0]; return r; }
        byte[] buf = new byte[64 + K * W1PACKED];
        System.arraycopy(mu, 0, buf, 0, 64);
        fusedUseHintPack(w, d.h, buf, 64);
        SHAKEDigest sh = new SHAKEDigest(256);
        sh.update(buf, 0, buf.length);
        byte[] c2 = new byte[CTILDE];
        sh.doFinal(c2, 0, CTILDE);
        r.w1Enc = java.util.Arrays.copyOfRange(buf, 64, buf.length);
        r.ok = org.bouncycastle.util.Arrays.constantTimeAreEqual(c2, d.cTilde);
        return r;
    }

    /** v2: BC's UseHint/pack, challenge hash with the own Keccak sponge */
    public HintResult hintCheckKeccak(byte[] mu, PolyVec w, Decoded d) {
        HintResult r = new HintResult();
        if (d.z.checkNorm(GAMMA1 - BETA)) { r.ok = false; r.w1Enc = new byte[0]; return r; }
        PolyVec w1 = copy(eng, w);
        w1.useHint(w1, d.h);
        byte[] w1b = new byte[K * W1PACKED];
        w1.packW1(eng, w1b, 0);
        Keccak k = Keccak.shake256();
        k.update(mu).update(w1b);
        byte[] c2 = k.squeeze(CTILDE);
        r.w1Enc = w1b;
        r.ok = org.bouncycastle.util.Arrays.constantTimeAreEqual(c2, d.cTilde);
        return r;
    }

    private void fusedUseHintPack(PolyVec w, PolyVec h, byte[] out, int off) {
        boolean g32 = GAMMA2 == (Q - 1) / 32;
        for (int i = 0; i < K; i++) {
            int[] wc = w.getVectorIndex(i).getCoeffs(), hc = h.getVectorIndex(i).getCoeffs();
            int o = off + i * W1PACKED;
            if (g32) {
                for (int n = 0; n < N; n += 2) {
                    int a = useHint(wc[n], hc[n], true), b = useHint(wc[n + 1], hc[n + 1], true);
                    out[o + (n >> 1)] = (byte) (a | (b << 4));
                }
            } else {
                for (int n = 0; n < N; n += 4) {
                    int a = useHint(wc[n], hc[n], false), b = useHint(wc[n + 1], hc[n + 1], false);
                    int c = useHint(wc[n + 2], hc[n + 2], false), e = useHint(wc[n + 3], hc[n + 3], false);
                    int p = o + 3 * (n >> 2);
                    out[p] = (byte) (a | (b << 6));
                    out[p + 1] = (byte) ((b >> 2) | (c << 4));
                    out[p + 2] = (byte) ((c >> 4) | (e << 2));
                }
            }
        }
    }

    private int useHint(int a, int hint, boolean g32) {
        int a1 = (a + 127) >> 7;
        if (g32) { a1 = (a1 * 1025 + (1 << 21)) >> 22; a1 &= 15; }
        else { a1 = (a1 * 11275 + (1 << 23)) >> 24; a1 ^= ((43 - a1) >> 31) & a1; }
        if (hint == 0) return a1;
        int a0 = a - a1 * 2 * GAMMA2;
        a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
        if (g32) return a0 > 0 ? (a1 + 1) & 15 : (a1 - 1) & 15;
        return a0 > 0 ? (a1 == 43 ? 0 : a1 + 1) : (a1 == 0 ? 43 : a1 - 1);
    }

    // ================================================================= canonical outputs

    /** coefficients reduced to [0,q), u32 little-endian */
    public static byte[] canon(PolyVec v) {
        byte[] out = new byte[v.length() * N * 4];
        for (int i = 0; i < v.length(); i++) putCoeffs(v.getVectorIndex(i).getCoeffs(), out, i * N * 4);
        return out;
    }
    public byte[] canon(PolyVecMatrix a) {
        byte[] out = new byte[K * L * N * 4];
        for (int i = 0; i < K; i++) for (int j = 0; j < L; j++) putCoeffs(a.row(i).getVectorIndex(j).getCoeffs(), out, (i * L + j) * N * 4);
        return out;
    }
    private static void putCoeffs(int[] c, byte[] out, int off) {
        for (int n = 0; n < N; n++) {
            int v = c[n] % Q; if (v < 0) v += Q;
            LE_INT.set(out, off + 4 * n, v);
        }
    }
    public static byte[] cTilde(Decoded d) { return d.cTilde; }
    public PolyVec zOf(Decoded d) { return d.z; }
}
