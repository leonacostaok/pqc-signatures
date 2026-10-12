package org.bouncycastle.crypto.signers.slhdsa;

import java.lang.management.ManagementFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.HashSLHDSASigner;
import org.bouncycastle.crypto.signers.SLHDSASigner;

/** Compiled unchanged against each isolated upstream source tree. */
public final class ForsOperations
{
    private static volatile Object sink;
    private static final com.sun.management.OperatingSystemMXBean CPU =
        (com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();

    private static final class FixedRandom extends SecureRandom
    {
        final byte[] bytes;
        int pos;
        FixedRandom(byte[] bytes) { this.bytes = bytes; }
        public void nextBytes(byte[] output)
        {
            if (pos + output.length > bytes.length) throw new AssertionError("entropy overrun");
            System.arraycopy(bytes, pos, output, 0, output.length);
            pos += output.length;
        }
    }

    private static final class Case
    {
        final SLHDSAParameters parameters;
        final byte[][] data;
        final SLHDSAPrivateKeyParameters secretKey;
        final SLHDSAPublicKeyParameters publicKey;
        Case(String name, byte[][] data) throws Exception
        {
            this.parameters = (SLHDSAParameters)SLHDSAParameters.class.getField(name).get(null);
            this.data = data;
            secretKey = new SLHDSAPrivateKeyParameters(parameters, data[5]);
            publicKey = new SLHDSAPublicKeyParameters(parameters, data[4]);
        }
    }

    public static byte[] derive(String label, int length) throws Exception
    {
        byte[] output = new byte[length];
        int position = 0;
        for (int counter = 0; position < length; ++counter)
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] block = digest.digest(("fors-base2b-v1/" + label + "/" + counter).getBytes("UTF-8"));
            int amount = Math.min(block.length, length - position);
            System.arraycopy(block, 0, output, position, amount);
            position += amount;
        }
        return output;
    }

    private static byte[][] keygen(SLHDSAParameters parameters, byte[] seed)
    {
        SLHDSAKeyPairGenerator generator = new SLHDSAKeyPairGenerator();
        generator.init(new SLHDSAKeyGenerationParameters(new FixedRandom(seed), parameters));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        return new byte[][] { ((SLHDSAPublicKeyParameters)pair.getPublic()).getEncoded(),
            ((SLHDSAPrivateKeyParameters)pair.getPrivate()).getEncoded() };
    }

    private static byte[] sign(Case c) throws Exception
    {
        CipherParameters key = c.secretKey;
        if (c.data[3].length != 0) key = new ParametersWithRandom(key, new FixedRandom(c.data[3]));
        key = new ParametersWithContext(key, c.data[2]);
        if (c.parameters.isPreHash())
        {
            HashSLHDSASigner signer = new HashSLHDSASigner();
            signer.init(true, key);
            signer.update(c.data[1], 0, c.data[1].length);
            return signer.generateSignature();
        }
        SLHDSASigner signer = new SLHDSASigner();
        signer.init(true, key);
        return signer.generateSignature(c.data[1]);
    }

    private static boolean verify(Case c, byte[] signature, byte[] message, byte[] context)
    {
        CipherParameters key = new ParametersWithContext(c.publicKey, context);
        if (c.parameters.isPreHash())
        {
            HashSLHDSASigner verifier = new HashSLHDSASigner();
            verifier.init(false, key);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        }
        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(false, key);
        return verifier.verifySignature(message, signature);
    }

    private static String outcome(Case c, byte[] sig, byte[] msg, byte[] ctx)
    {
        try { return Boolean.toString(verify(c, sig, msg, ctx)); }
        catch (RuntimeException e) { return "throws:" + e.getClass().getName(); }
    }

    private static byte[] changed(byte[] value)
    {
        byte[] output = value.length == 0 ? new byte[1] : value.clone();
        output[output.length - 1] ^= 1;
        return output;
    }

    public static byte[][][] fixtures(String name, int corpus) throws Exception
    {
        SLHDSAParameters parameters = (SLHDSAParameters)SLHDSAParameters.class.getField(name).get(null);
        byte[][][] cases = new byte[2][][];
        for (int i = 0; i < cases.length; ++i)
        {
            String label = corpus + "/" + name + "/" + i;
            byte[][] data = new byte[7][];
            data[0] = derive(label + "/seed", parameters.getN() * 3);
            data[1] = derive(label + "/message", i == 0 ? 0 : 1024);
            data[2] = derive(label + "/context", i == 0 ? 0 : 255);
            data[3] = derive(label + "/random", i == 0 ? 0 : parameters.getN());
            byte[][] keys = keygen(parameters, data[0]);
            data[4] = keys[0]; data[5] = keys[1];
            Case c = new Case(name, data);
            data[6] = sign(c);
            if (!verify(c, data[6], data[1], data[2])) throw new AssertionError("fixture self verify");
            cases[i] = data;
        }
        return cases;
    }

    public static Object prepare(String name, byte[][][] fixtures) throws Exception
    {
        Case[] output = new Case[fixtures.length];
        for (int i = 0; i < output.length; ++i) output[i] = new Case(name, fixtures[i]);
        return output;
    }

    public static String[] validate(Object prepared) throws Exception
    {
        Case[] cases = (Case[])prepared;
        String[] outcomes = new String[cases.length * 5];
        int index = 0;
        for (Case c : cases)
        {
            byte[][] saved = new byte[c.data.length][];
            for (int i = 0; i < saved.length; ++i) saved[i] = c.data[i].clone();
            byte[][] keys = keygen(c.parameters, c.data[0]);
            if (!Arrays.equals(keys[0], c.data[4]) || !Arrays.equals(keys[1], c.data[5]))
                throw new AssertionError("keygen differential");
            if (!Arrays.equals(sign(c), c.data[6])) throw new AssertionError("signature differential");
            if (!verify(c, c.data[6], c.data[1], c.data[2])) throw new AssertionError("valid signature");
            outcomes[index++] = outcome(c, changed(c.data[6]), c.data[1], c.data[2]);
            outcomes[index++] = outcome(c, c.data[6], changed(c.data[1]), c.data[2]);
            outcomes[index++] = outcome(c, c.data[6], c.data[1], changed(c.data[2]));
            outcomes[index++] = outcome(c, Arrays.copyOf(c.data[6], c.data[6].length - 1), c.data[1], c.data[2]);
            outcomes[index++] = outcome(c, Arrays.copyOf(c.data[6], c.data[6].length + 1), c.data[1], c.data[2]);
            for (int i = 0; i < saved.length; ++i)
                if (!Arrays.equals(saved[i], c.data[i])) throw new AssertionError("caller input mutation");
        }
        for (String outcome : outcomes) if (outcome.equals("true")) throw new AssertionError("accepted malformed input");
        return outcomes;
    }

    public static long[] measure(String operation, Object prepared, long budgetNs) throws Exception
    {
        Case[] cases = (Case[])prepared;
        Object last = null;
        long iterations = 0, elapsed;
        long cpuStart = CPU.getProcessCpuTime(), start = System.nanoTime();
        do
        {
            for (Case c : cases)
            {
                last = operation.equals("sign") ? sign(c) : Boolean.valueOf(verify(c, c.data[6], c.data[1], c.data[2]));
                sink = last;
                ++iterations;
            }
            elapsed = System.nanoTime() - start;
        }
        while (elapsed < budgetNs);
        long cpu = CPU.getProcessCpuTime() - cpuStart;
        Case c = cases[cases.length - 1];
        if (operation.equals("sign") ? !Arrays.equals((byte[])last, c.data[6]) : !Boolean.TRUE.equals(last))
            throw new AssertionError("timed output mismatch");
        return new long[] {iterations, elapsed, cpu};
    }

    public static long[] measureHelper(int width, int count, byte[][] messages, long budgetNs)
    {
        int[] last = null;
        long iterations = 0, elapsed;
        long cpuStart = CPU.getProcessCpuTime(), start = System.nanoTime();
        do
        {
            for (byte[] message : messages)
            {
                last = Fors.base2B(message, width, count);
                sink = last;
                ++iterations;
            }
            elapsed = System.nanoTime() - start;
        }
        while (elapsed < budgetNs);
        long cpu = CPU.getProcessCpuTime() - cpuStart;
        byte[] message = messages[messages.length - 1];
        for (int i = 0; i < count; ++i)
        {
            int expected = 0;
            for (int j = 0; j < width; ++j)
            {
                int bit = i * width + j;
                expected = (expected << 1) | ((message[bit / 8] >>> (7 - bit % 8)) & 1);
            }
            if (last[i] != expected) throw new AssertionError("timed helper mismatch");
        }
        return new long[] {iterations, elapsed, cpu};
    }
}
