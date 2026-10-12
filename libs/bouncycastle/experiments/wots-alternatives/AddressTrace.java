package org.bouncycastle.crypto.signers.slhdsa;

import java.security.MessageDigest;
import java.util.Arrays;

/** Experiment-only transcript oracle. This engine is not cryptography for use. */
public final class AddressTrace
{
    static final class TraceEngine extends SLHDSAEngine
    {
        final MessageDigest trace;
        int calls;
        TraceEngine(int n) throws Exception
        {
            super(n, 16, 22, 6, 33, 66);
            trace = MessageDigest.getInstance("SHA-256");
        }
        void init(byte[] seed) {}
        byte[] record(int type, ADRS adrs, byte[]... inputs)
        {
            try
            {
                MessageDigest result = MessageDigest.getInstance("SHA-256");
                result.update((byte)type); result.update(adrs.value);
                trace.update((byte)type); trace.update(adrs.value);
                for (byte[] input : inputs)
                {
                    trace.update((byte)(input.length >>> 8)); trace.update((byte)input.length);
                    trace.update(input); result.update(input);
                }
                ++calls;
                return Arrays.copyOf(result.digest(), N);
            }
            catch (Exception e) { throw new AssertionError(e); }
        }
        byte[] F(byte[] seed, ADRS adrs, byte[] value) { return record(1, adrs, seed, value); }
        void F(byte[] seed, ADRS adrs, byte[] value, byte[] output) { byte[] result = F(seed, adrs, value); System.arraycopy(result, 0, output, 0, N); }
        byte[] PRF(byte[] seed, byte[] secret, ADRS adrs) { return record(2, adrs, seed, secret); }
        byte[] T_l(byte[] seed, ADRS adrs, byte[] value) { return record(3, adrs, seed, value); }
        byte[] H(byte[] a, ADRS b, byte[] c, byte[] d) { throw new AssertionError("unused"); }
        IndexedDigest H_msg(byte[] a, byte[] b, byte[] c, byte[] d, byte[] e) { throw new AssertionError("unused"); }
        byte[] PRF_msg(byte[] a, byte[] b, byte[] c, byte[] d) { throw new AssertionError("unused"); }
    }
    static void require(boolean ok) { if (!ok) throw new AssertionError("ownership"); }
    static String hex(byte[] data)
    {
        StringBuilder s = new StringBuilder();
        for (byte b : data) s.append(String.format("%02x", b & 255));
        return s.toString();
    }
    public static void main(String[] args) throws Exception
    {
        for (int n : new int[]{16,24,32}) for (int test = 0; test < 8; ++test)
        {
            byte[] seed = new byte[n], secret = new byte[n], msg = new byte[n];
            ADRS adrs = new ADRS();
            for (int i = 0; i < 32; ++i) adrs.value[i] = (byte)(i * 17 + test * 31 + 1);
            for (int i = 0; i < n; ++i)
            {
                seed[i] = (byte)(i + test); secret[i] = (byte)(i * 7 - test);
                msg[i] = test % 3 == 0 ? 0 : test % 3 == 1 ? (byte)255 : (byte)(i * 19 + test);
            }
            byte[] original = adrs.value.clone(), oldSeed = seed.clone(), oldSecret = secret.clone(), oldMsg = msg.clone();
            TraceEngine engine = new TraceEngine(n); WotsPlus wots = new WotsPlus(engine);
            byte[] pk = wots.pkGen(secret, seed, adrs), savedPk = pk.clone();
            byte[] sig = wots.sign(msg, secret, seed, adrs), savedSig = sig.clone();
            wots.pkGen(secret, seed, adrs); wots.sign(msg, secret, seed, adrs);
            require(Arrays.equals(pk, savedPk) && Arrays.equals(sig, savedSig));
            require(Arrays.equals(adrs.value, original) && Arrays.equals(seed, oldSeed)
                && Arrays.equals(secret, oldSecret) && Arrays.equals(msg, oldMsg));
            System.out.println("{\"n\":"+n+",\"case\":"+test+",\"calls\":"+engine.calls
                +",\"trace\":\""+hex(engine.trace.digest())+"\",\"pk\":\""+hex(pk)
                +"\",\"signature_digest\":\""+hex(MessageDigest.getInstance("SHA-256").digest(sig))+"\",\"ownership\":true}");
        }
    }
}
