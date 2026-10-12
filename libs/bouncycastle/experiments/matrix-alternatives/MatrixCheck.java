package org.bouncycastle.crypto.signers.mldsa;

import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.*;
import org.bouncycastle.crypto.params.MLDSAParameters;

/** Arithmetic, stream and logical construction gates. Instrumented classes are never timed. */
public final class MatrixCheck
{
    static final int Q = 8380417;
    static final BigInteger MOD = BigInteger.valueOf(Q);
    static final BigInteger RINV = BigInteger.ONE.shiftLeft(32).modInverse(MOD);
    static final MLDSAParameters[] PARAMS = {MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87};
    static void require(boolean b, String why) { if (!b) throw new AssertionError(why); }
    static long counter(Class<?> c, String name, boolean clear) throws Exception
    { Field f = c.getDeclaredField(name); f.setAccessible(true); long n = f.getLong(null); if (clear) f.setLong(null, 0); return n; }
    static int canonical(long x) { return (int)Math.floorMod(x, Q); }
    static PolyVec[] rows(PolyVecMatrix a) throws Exception
    { Field f = PolyVecMatrix.class.getDeclaredField("matrix"); f.setAccessible(true); return (PolyVec[])f.get(a); }
    static int[][] saved(PolyVec v)
    { int[][] out = new int[v.length()][]; for (int i = 0; i < out.length; ++i) out[i] = v.getVectorIndex(i).getCoeffs().clone(); return out; }
    static final class Traced extends Symmetric
    {
        final Symmetric delegate; final boolean forced;
        final List<Integer> nonces = new ArrayList<Integer>();
        final List<String> requests = new ArrayList<String>();
        int position, nonce, refills;
        Traced(Symmetric delegate, boolean forced) { super(forced ? 167 : 168, 136); this.delegate = delegate; this.forced = forced; }
        void stream128init(byte[] seed, short n)
        { position = 0; nonce = n & 65535; nonces.add(nonce); delegate.stream128init(seed, n); }
        void stream256init(byte[] seed, short n) { delegate.stream256init(seed, n); }
        void stream128squeezeBlocks(byte[] out, int off, int len)
        {
            requests.add(nonce + ":" + position + ":" + off + ":" + len);
            if (position != 0) refills++;
            if (forced) for (int i = 0; i < len; ++i) out[off+i] = forcedByte(position+i, nonce);
            else delegate.stream128squeezeBlocks(out, off, len);
            position += len;
        }
        void stream256squeezeBlocks(byte[] out, int off, int len) { delegate.stream256squeezeBlocks(out, off, len); }
    }
    static byte forcedByte(int position, int nonce)
    {
        if (position < 835) return (byte)255;
        int value = ((position / 3) * 17 + nonce) & 0x7fffff;
        return (byte)(value >>> (8 * (position % 3)));
    }
    static int[] forcedExpected(int nonce)
    {
        int[] out = new int[256]; int n = 0;
        for (int p = 0; n != 256; p += 3)
        {
            int x = (forcedByte(p, nonce)&255) | ((forcedByte(p+1, nonce)&255)<<8) | ((forcedByte(p+2, nonce)&127)<<16);
            if (x < Q) out[n++] = x;
        }
        return out;
    }
    static Traced trace(MLDSAEngine e, boolean forced) throws Exception
    { Traced t = new Traced(e.GetSymmetric(), forced); Field f = MLDSAEngine.class.getDeclaredField("symmetric"); f.setAccessible(true); f.set(e, t); return t; }
    public static void main(String[] args) throws Exception
    {
        boolean lazy = Boolean.parseBoolean(args[0]), stream = Boolean.parseBoolean(args[1]);
        int arithmetic = 0, streamChecks = 0; long reductions = 0;
        Random rng = new Random(204);
        for (MLDSAParameters params : PARAMS)
        {
            MLDSAEngine e = MLDSAEngine.getInstance(params, null); int L = e.getDilithiumL();
            for (int test = 0; test < 24; ++test)
            {
                PolyVec u = new PolyVec(e, L), v = new PolyVec(e, L); Poly out = new Poly(e);
                for (int i = 0; i < L; ++i) for (int j = 0; j < 256; ++j)
                {
                    u.getVectorIndex(i).setCoeffIndex(j, test < 4 ? (test%2 == 0 ? 0 : Q-1) : rng.nextInt(Q));
                    v.getVectorIndex(i).setCoeffIndex(j, test < 4 ? (test < 2 ? 9*Q-1 : 1-9*Q) : rng.nextInt(18*Q-1) + 1-9*Q);
                }
                int[][] beforeU = saved(u), beforeV = saved(v);
                counter(Reduce.class, "probeCalls", true);
                out.pointwiseAccountMontgomery(u, v);
                long calls = counter(Reduce.class, "probeCalls", false); reductions += calls;
                require(calls == (lazy ? 256 : 256*L), "row reduction count " + calls + " expected " + (lazy ? 256 : 256*L));
                for (int j = 0; j < 256; ++j)
                {
                    BigInteger sum = BigInteger.ZERO;
                    for (int i = 0; i < L; ++i) sum = sum.add(BigInteger.valueOf(beforeU[i][j]).multiply(BigInteger.valueOf(beforeV[i][j])));
                    require(canonical(out.getCoeffIndex(j)) == sum.multiply(RINV).mod(MOD).intValue(), "row residue");
                    if (lazy) require(Math.abs((long)out.getCoeffIndex(j)) < Q, "lazy representative bound");
                    arithmetic++;
                }
                require(Arrays.deepEquals(beforeU, saved(u)) && Arrays.deepEquals(beforeV, saved(v)), "row input ownership");
            }
            for (boolean forced : new boolean[]{false, true})
            {
                MLDSAEngine old = MLDSAEngine.getInstance(params, null), changed = MLDSAEngine.getInstance(params, null);
                Traced before = trace(old, forced), after = trace(changed, forced);
                byte[] rho = new byte[32]; rng.nextBytes(rho); byte[] savedRho = rho.clone();
                PolyVec v = new PolyVec(changed, L), expected = new PolyVec(old, old.getDilithiumK()), actual = new PolyVec(changed, changed.getDilithiumK());
                for (int i=0; i<L; ++i) for (int j=0; j<256; ++j) v.getVectorIndex(i).setCoeffIndex(j, rng.nextInt(18*Q-1)+1-9*Q);
                int[][] savedV = saved(v);
                PolyVecMatrix full = new PolyVecMatrix(old); full.expandMatrix(rho); full.pointwiseMontgomery(expected, v);
                if (forced) for (int i=0; i<old.getDilithiumK(); ++i) for (int j=0; j<L; ++j)
                    require(Arrays.equals(rows(full)[i].getVectorIndex(j).getCoeffs(), forcedExpected((i<<8)+j)), "forced sampler coefficients");
                counter(Poly.class, "probeObjects", true);
                if (stream)
                {
                    Method helper;
                    try { helper = PolyVecMatrix.class.getDeclaredMethod("expandAndMultiply", MLDSAEngine.class, PolyVec.class, PolyVec.class, byte[].class); }
                    catch (NoSuchMethodException ex) { throw new AssertionError("streamed helper missing", ex); }
                    helper.setAccessible(true); helper.invoke(null, changed, actual, v, rho);
                    require(counter(Poly.class, "probeObjects", false) == L, "streamed row ownership count");
                }
                else { PolyVecMatrix copy = new PolyVecMatrix(changed); copy.expandMatrix(rho); copy.pointwiseMontgomery(actual,v); }
                require(before.nonces.equals(after.nonces) && before.requests.equals(after.requests), "uniform stream order/requests");
                if (forced) require(after.refills > old.getDilithiumK()*L, "carry1/carry2 refill coverage");
                require(Arrays.deepEquals(savedV, saved(v)) && Arrays.equals(savedRho,rho), "stream input ownership");
                int[][] retained = saved(actual);
                if (stream)
                {
                    byte[] otherRho = rho.clone(); otherRho[0] ^= 1;
                    Method helper = PolyVecMatrix.class.getDeclaredMethod("expandAndMultiply", MLDSAEngine.class, PolyVec.class, PolyVec.class, byte[].class);
                    helper.setAccessible(true);
                    helper.invoke(null, changed, new PolyVec(changed, changed.getDilithiumK()), v, otherRho);
                    require(Arrays.deepEquals(retained, saved(actual)), "retained output ownership");
                }
                expected.reduce(); actual.reduce(); expected.invNttToMont(); actual.invNttToMont(); expected.conditionalAddQ(); actual.conditionalAddQ();
                require(Arrays.deepEquals(saved(expected), saved(actual)), "stream caller canonical output");
                streamChecks++;
            }
        }
        System.out.println("{\"arithmetic_coefficients\":"+arithmetic+",\"stream_cases\":"+streamChecks+",\"logical_reductions\":"+reductions+",\"lazy\":"+lazy+",\"stream\":"+stream+"}");
    }
}
