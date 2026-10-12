package org.bouncycastle.crypto.signers.mldsa;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.IdentityHashMap;
import org.bouncycastle.crypto.params.MLDSAParameters;

/** Resource and poisoned-buffer checks only; never used by whole-operation timing. */
public final class SamplingCheck
{
    private static final MLDSAParameters[] PARAMS = {MLDSAParameters.ml_dsa_44,
        MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87};

    private static final class Traced extends Symmetric
    {
        final Symmetric delegate;
        final IdentityHashMap<byte[], Boolean> outputs = new IdentityHashMap<byte[], Boolean>();
        int calls, position, nonce;
        final boolean forced;
        Traced(Symmetric delegate, boolean forced)
        {
            super(forced ? 167 : 168, 136);
            this.delegate = delegate;
            this.forced = forced;
        }
        void stream128init(byte[] seed, short nonce)
        {
            position = 0; this.nonce = nonce & 65535;
            delegate.stream128init(seed, nonce);
        }
        void stream256init(byte[] seed, short nonce) { delegate.stream256init(seed, nonce); }
        void stream128squeezeBlocks(byte[] out, int off, int len)
        {
            outputs.put(out, Boolean.TRUE); calls++;
            if (!forced) { delegate.stream128squeezeBlocks(out, off, len); return; }
            for (int i = 0; i < len; ++i, ++position)
                out[off + i] = forcedByte(position, nonce);
        }
        void stream256squeezeBlocks(byte[] out, int off, int len)
        {
            outputs.put(out, Boolean.TRUE); calls++;
            delegate.stream256squeezeBlocks(out, off, len);
        }
    }
    private static byte forcedByte(int position, int nonce)
    {
        // The initial 835-byte request contains only rejected triples; its one-byte tail
        // must survive the next refill. Later bytes produce accepted coefficients.
        if (position < 835) return (byte)255;
        int value = ((position / 3) * 17 + nonce) & 0x7fffff;
        return (byte)(value >>> (8 * (position % 3)));
    }
    private static int[] forcedExpected(int nonce)
    {
        int[] out = new int[256]; int count = 0;
        for (int pos = 0; count < out.length; pos += 3)
        {
            int x = (forcedByte(pos, nonce) & 255) | ((forcedByte(pos + 1, nonce) & 255) << 8)
                | ((forcedByte(pos + 2, nonce) & 127) << 16);
            if (x < MLDSAEngine.DilithiumQ) out[count++] = x;
        }
        return out;
    }
    private static Traced trace(MLDSAEngine engine, boolean forced) throws Exception
    {
        Traced traced = new Traced(engine.GetSymmetric(), forced);
        Field field = MLDSAEngine.class.getDeclaredField("symmetric");
        field.setAccessible(true); field.set(engine, traced);
        return traced;
    }
    private static void require(boolean yes, String message)
    {
        if (!yes) throw new AssertionError(message);
    }
    public static void main(String[] args) throws Exception
    {
        boolean matrixShared = Boolean.parseBoolean(args[0]), gammaShared = Boolean.parseBoolean(args[1]);
        int checked = 0;
        for (MLDSAParameters params : PARAMS)
        {
            MLDSAEngine engine = MLDSAEngine.getInstance(params, null);
            Traced traced = trace(engine, false);
            byte[] seed = new byte[64];
            for (int i = 0; i < seed.length; ++i) seed[i] = (byte)(i * 31 + params.getK());
            byte[] saved = seed.clone();
            PolyVecMatrix matrix = new PolyVecMatrix(engine);
            byte[] rho = Arrays.copyOf(seed, 32), rhoSaved = rho.clone();
            matrix.expandMatrix(rho);
            require(Arrays.equals(rho, rhoSaved), "matrix seed ownership");
            require(traced.outputs.size() == (matrixShared ? 1 : engine.getDilithiumK() * engine.getDilithiumL()), "matrix buffer count");
            Field field = PolyVecMatrix.class.getDeclaredField("matrix"); field.setAccessible(true);
            PolyVec[] rows = (PolyVec[])field.get(matrix);
            for (int i = 0; i < rows.length; ++i) for (int j = 0; j < engine.getDilithiumL(); ++j)
            {
                Poly reference = new Poly(engine);
                reference.uniformBlocks(Arrays.copyOf(seed, 32), (short)((i << 8) + j));
                require(Arrays.equals(reference.getCoeffs(), rows[i].getVectorIndex(j).getCoeffs()), "matrix coefficients"); checked++;
            }
            traced.outputs.clear();
            PolyVec gamma = new PolyVec(engine, engine.getDilithiumL());
            gamma.uniformGamma1(seed, (short)37);
            require(traced.outputs.size() == (gammaShared ? 1 : engine.getDilithiumL()), "gamma buffer count");
            for (int j = 0; j < gamma.length(); ++j)
            {
                Poly reference = new Poly(engine);
                reference.uniformGamma1(seed, (short)(gamma.length() * 37 + j));
                require(Arrays.equals(reference.getCoeffs(), gamma.getVectorIndex(j).getCoeffs()), "gamma coefficients"); checked++;
            }
            require(Arrays.equals(seed, saved), "seed ownership");
            // Package-private scratch overloads exist only in candidates. Baseline uses the
            // identical allocating public entry points to establish the reference oracle.
            if (matrixShared || gammaShared)
            {
                MLDSAEngine forcedEngine = MLDSAEngine.getInstance(params, null);
                Traced forced = trace(forcedEngine, true);
                Poly p = new Poly(forcedEngine);
                java.lang.reflect.Method sampler = Poly.class.getDeclaredMethod("uniformBlocks", byte[].class, short.class, byte[].class);
                sampler.setAccessible(true);
                byte[] scratch = new byte[5 * 167 + 2];
                for (int nonce : new int[]{0, 1, 255, 256, 65535})
                {
                    Arrays.fill(scratch, (byte)0xA5); Arrays.fill(p.getCoeffs(), 0x5A5A5A5A);
                    int start = forced.calls;
                    sampler.invoke(p, Arrays.copyOf(seed, 32), (short)nonce, scratch);
                    require(forced.calls - start > 1, "forced refill was not exercised");
                    require(Arrays.equals(p.getCoeffs(), forcedExpected(nonce)), "poison/carry/refill coefficients"); checked++;
                }
                java.lang.reflect.Method gammaSampler = Poly.class.getDeclaredMethod("uniformGamma1", byte[].class, short.class, byte[].class);
                gammaSampler.setAccessible(true);
                Poly target = new Poly(engine), reference = new Poly(engine);
                scratch = new byte[engine.getPolyUniformGamma1NBlocks() * 136];
                for (int nonce : new int[]{0, 1, 255, 256, 65535})
                {
                    Arrays.fill(scratch, (byte)0xA5); Arrays.fill(target.getCoeffs(), 0x5A5A5A5A);
                    gammaSampler.invoke(target, seed, (short)nonce, scratch);
                    reference.uniformGamma1(seed, (short)nonce);
                    require(Arrays.equals(target.getCoeffs(), reference.getCoeffs()), "gamma poison coefficients"); checked++;
                }
            }
        }
        System.out.println("{\"checks\":" + checked + ",\"matrix_shared\":" + matrixShared + ",\"gamma_shared\":" + gammaShared + "}");
    }
}
