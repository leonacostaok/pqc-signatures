import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;

/** One keygen/sign/verify call per new key, using one implementation per fresh JVM. */
public final class TenKeyBenchmark
{
    private static final com.sun.management.OperatingSystemMXBean CPU =
        (com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
    private static final ThreadMXBean THREAD = ManagementFactory.getThreadMXBean();

    private static final class FixedRandom extends SecureRandom
    {
        private final byte[] bytes;
        private int position;
        FixedRandom(byte[] bytes) { this.bytes = bytes; }
        public void nextBytes(byte[] output)
        {
            if (position + output.length > bytes.length) throw new AssertionError("entropy overrun");
            System.arraycopy(bytes, position, output, 0, output.length);
            position += output.length;
        }
        void check() { if (position != bytes.length) throw new AssertionError("unused entropy"); }
    }

    private interface Operation<T> { T run() throws Exception; }

    private static final class Measured<T>
    {
        final T value;
        final long wall, cpu, thread;
        Measured(T value, long wall, long cpu, long thread)
        { this.value = value; this.wall = wall; this.cpu = cpu; this.thread = thread; }
        String json()
        { return "{\"elapsed_ns\":" + wall + ",\"cpu_ns\":" + cpu + ",\"thread_cpu_ns\":" + thread + "}"; }
    }

    private static <T> Measured<T> measure(boolean enabled, Operation<T> operation) throws Exception
    {
        if (!enabled) return new Measured<T>(operation.run(), 0, 0, 0);
        long cpu = CPU.getProcessCpuTime(), thread = THREAD.getCurrentThreadCpuTime(), start = System.nanoTime();
        T value = operation.run();
        long wall = System.nanoTime() - start;
        thread = THREAD.getCurrentThreadCpuTime() - thread;
        cpu = CPU.getProcessCpuTime() - cpu;
        if (wall <= 0 || cpu < 0 || thread < 0) throw new AssertionError("invalid clocks");
        return new Measured<T>(value, wall, cpu, thread);
    }

    private static byte[] decode(String hex)
    {
        if ((hex.length() & 1) != 0) throw new AssertionError("odd hex length");
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; ++i)
        {
            int a = Character.digit(hex.charAt(i * 2), 16), b = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (a < 0 || b < 0) throw new AssertionError("invalid hex");
            result[i] = (byte)((a << 4) | b);
        }
        return result;
    }

    private static String hex(byte[] bytes)
    {
        char[] result = new char[bytes.length * 2];
        char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; ++i)
        { result[i * 2] = digits[(bytes[i] >>> 4) & 15]; result[i * 2 + 1] = digits[bytes[i] & 15]; }
        return new String(result);
    }

    private static String quote(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }

    private static boolean verify(SLHDSAPublicKeyParameters key, byte[] message, byte[] context, byte[] signature)
    {
        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(false, new ParametersWithContext(key, context));
        return verifier.verifySignature(message, signature);
    }

    private static String execute(String[] data, String variant, boolean timed, boolean expected, String source) throws Exception
    {
        final SLHDSAParameters parameter = (SLHDSAParameters)SLHDSAParameters.class.getField(data[1]).get(null);
        if (parameter.isPreHash()) throw new AssertionError("pure parameters only");
        final byte[] seed = decode(data[3]), message = decode(data[4]), context = decode(data[5]), entropy = decode(data[6]);
        if (seed.length != parameter.getN() * 3 || entropy.length != parameter.getN() || context.length > 255)
            throw new AssertionError("invalid corpus dimensions");
        final FixedRandom keyRandom = new FixedRandom(seed);
        Measured<AsymmetricCipherKeyPair> keygen = measure(timed, new Operation<AsymmetricCipherKeyPair>() {
            public AsymmetricCipherKeyPair run()
            {
                SLHDSAKeyPairGenerator generator = new SLHDSAKeyPairGenerator();
                generator.init(new SLHDSAKeyGenerationParameters(keyRandom, parameter));
                return generator.generateKeyPair();
            }
        });
        keyRandom.check();
        byte[] pk = ((SLHDSAPublicKeyParameters)keygen.value.getPublic()).getEncoded();
        byte[] sk = ((SLHDSAPrivateKeyParameters)keygen.value.getPrivate()).getEncoded();
        if (expected && (!Arrays.equals(pk, decode(data[7])) || !Arrays.equals(sk, decode(data[8]))))
            throw new AssertionError("key output mismatch");
        final SLHDSAPrivateKeyParameters signingKey = new SLHDSAPrivateKeyParameters(parameter, sk);
        final FixedRandom signRandom = new FixedRandom(entropy);
        Measured<byte[]> sign = measure(timed, new Operation<byte[]>() {
            public byte[] run()
            {
                SLHDSASigner signer = new SLHDSASigner();
                signer.init(true, new ParametersWithContext(new ParametersWithRandom(signingKey, signRandom), context));
                return signer.generateSignature(message);
            }
        });
        signRandom.check();
        if (expected && !Arrays.equals(sign.value, decode(data[9]))) throw new AssertionError("signature output mismatch");
        final SLHDSAPublicKeyParameters publicKey = new SLHDSAPublicKeyParameters(parameter, pk);
        final byte[] signature = sign.value;
        Measured<Boolean> checked = measure(timed, new Operation<Boolean>() {
            public Boolean run() { return Boolean.valueOf(verify(publicKey, message, context, signature)); }
        });
        if (!checked.value.booleanValue()) throw new AssertionError("valid signature rejected");
        byte[] changed = signature.clone(); changed[0] ^= 1;
        if (verify(new SLHDSAPublicKeyParameters(parameter, pk), message, context, changed))
            throw new AssertionError("tampered signature accepted");
        String output = "{\"parameter\":" + quote(data[1]) + ",\"phase\":" + quote(data[0])
            + ",\"index\":" + Integer.parseInt(data[2]) + ",\"seed\":" + quote(data[3])
            + ",\"variant\":" + quote(variant) + ",\"class_source\":" + quote(source)
            + ",\"pk\":" + quote(hex(pk)) + ",\"sk\":" + quote(hex(sk))
            + ",\"signature\":" + quote(hex(signature)) + ",\"valid\":true,\"tamper_rejected\":true";
        if (timed) output += ",\"metrics\":{\"keygen\":" + keygen.json() + ",\"sign\":" + sign.json() + ",\"verify\":" + checked.json() + "}";
        return output + "}";
    }

    public static void main(String[] args) throws Exception
    {
        if (args.length != 4 || !(args[0].equals("check") || args[0].equals("bench"))
            || !(args[3].equals("baseline") || args[3].equals("candidate")))
            throw new IllegalArgumentException("check|bench INPUT PARAMETER VARIANT");
        if (!THREAD.isCurrentThreadCpuTimeSupported()) throw new AssertionError("thread CPU unsupported");
        if (!THREAD.isThreadCpuTimeEnabled()) THREAD.setThreadCpuTimeEnabled(true);
        List<String[]> cases = new ArrayList<String[]>();
        try (BufferedReader input = new BufferedReader(new FileReader(args[1])))
        {
            if (!"pqc-tenkeys-v1/bouncycastle".equals(input.readLine())) throw new AssertionError("corpus version");
            for (String line; (line = input.readLine()) != null; )
            {
                String[] fields = line.split("\t", -1);
                if (fields.length != 10) throw new AssertionError("corpus columns");
                if (fields[1].equals(args[2])) cases.add(fields);
            }
        }
        if (cases.size() != 12) throw new AssertionError("expected two warmup and ten measured keys");
        String source = Paths.get(Class.forName("org.bouncycastle.crypto.signers.slhdsa.Fors")
            .getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString();
        boolean bench = args[0].equals("bench");
        for (int i = 0; i < cases.size(); ++i)
        {
            String[] data = cases.get(i);
            if (!data[0].equals(i < 2 ? "warmup" : "measured") || Integer.parseInt(data[2]) != (i < 2 ? i : i - 2))
                throw new AssertionError("corpus ordering");
            boolean measured = bench && i >= 2;
            String output = execute(data, args[3], measured, bench, source);
            if (!bench || measured) System.out.println(output);
        }
    }
}
