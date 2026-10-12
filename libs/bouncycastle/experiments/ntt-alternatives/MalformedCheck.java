package org.bouncycastle.crypto.signers.mldsa;

import java.util.Arrays;

/** Decoder-specific invalid inputs, beyond a final challenge mismatch. Never timed. */
public final class MalformedCheck
{
    static void require(boolean ok, String why) { if (!ok) throw new AssertionError(why); }
    static boolean decode(MLDSAEngine e, byte[] sig)
    {
        return Packing.unpackSignature(new PolyVec(e, e.getDilithiumL()), new PolyVec(e, e.getDilithiumK()), sig, e);
    }
    static void rejected(MLDeep.C c, byte[] sig, String why) throws Exception
    {
        byte[] saved = sig.clone(), pk = c.pk.getEncoded(), sk = c.sk.getEncoded();
        require(!MLDeep.verify(c, sig, c.d[1], c.d[2]), why);
        require(Arrays.equals(saved, sig), why + " signature ownership");
        require(Arrays.equals(pk, c.pk.getEncoded()) && Arrays.equals(sk, c.sk.getEncoded()), why + " key ownership");
    }
    public static void main(String[] args) throws Exception
    {
        int checks = 0, cases = 0;
        for (MLDeep.C c : MLDeep.read(args[0]))
        {
            MLDSAEngine e = MLDSAEngine.getInstance(c.params, null);
            int omega = e.getDilithiumOmega(), k = e.getDilithiumK();
            int end = e.getDilithiumCTilde() + e.getDilithiumL() * e.getDilithiumPolyZPackedBytes();
            byte[] original = c.d[6], before = original.clone();
            require(decode(e, original), "valid decoder control");
            for (int kind = 0; kind < 4; ++kind)
            {
                byte[] sig = original.clone();
                Arrays.fill(sig, end, sig.length, (byte)0);
                if (kind == 0) sig[end + omega] = (byte)(omega + 1);
                if (kind == 1) { sig[end + omega] = 1; sig[end + omega + 1] = 0; }
                if (kind == 2)
                {
                    sig[end] = sig[end + 1] = 3;
                    for (int i = 0; i < k; ++i) sig[end + omega + i] = 2;
                }
                if (kind == 3) sig[end] = 1;
                require(!decode(e, sig), "malformed hint accepted " + kind);
                rejected(c, sig, "malformed hint " + kind); checks++;
            }
            for (int sign : new int[]{-1, 1})
            {
                PolyVec z = new PolyVec(e, e.getDilithiumL()), h = new PolyVec(e, k);
                require(Packing.unpackSignature(z, h, original, e), "norm setup");
                int bound = e.getDilithiumGamma1() - e.getDilithiumBeta();
                z.getVectorIndex(0).setCoeffIndex(0, sign * bound);
                byte[] sig = original.clone(); Packing.packSignature(sig, z, h, e);
                PolyVec decoded = new PolyVec(e, e.getDilithiumL());
                require(Packing.unpackSignature(decoded, new PolyVec(e, k), sig, e), "norm encoding");
                require(decoded.getVectorIndex(0).getCoeffIndex(0) == sign * bound, "norm boundary roundtrip");
                require(decoded.checkNorm(bound), "norm equality accepted");
                rejected(c, sig, "norm boundary"); checks++;
                decoded.getVectorIndex(0).setCoeffIndex(0, sign * (bound - 1));
                require(!decoded.checkNorm(bound), "norm adjacent interior rejected"); checks++;
            }
            rejected(c, Arrays.copyOf(original, original.length - 1), "short signature"); checks++;
            rejected(c, Arrays.copyOf(original, original.length + 1), "long signature"); checks++;
            byte[] message = MLDeep.changed(c.d[1]), context = MLDeep.changed(c.d[2]);
            require(!MLDeep.verify(c, original, message, c.d[2]), "wrong message"); checks++;
            require(!MLDeep.verify(c, original, c.d[1], context), "wrong context"); checks++;
            require(Arrays.equals(original, before) && Arrays.equals(c.pk.getEncoded(), c.d[4]) && Arrays.equals(c.sk.getEncoded(), c.d[5]), "caller ownership");
            require(MLDeep.verify(c, original, c.d[1], c.d[2]), "valid after negatives"); checks++; cases++;
        }
        System.out.println("{\"cases\":" + cases + ",\"checks\":" + checks + ",\"ownership\":true}");
    }
}
