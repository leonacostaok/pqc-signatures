package org.bouncycastle.crypto.signers.mldsa;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.*;

/** Fresh signer per call. Only immutable encoded fixtures cross operation boundaries. */
public final class MLDeep
{
    static final String[] NAMES = {"ml_dsa_44", "ml_dsa_65", "ml_dsa_87",
        "ml_dsa_44_with_sha512", "ml_dsa_65_with_sha512", "ml_dsa_87_with_sha512"};
    static final com.sun.management.ThreadMXBean THREAD =
        (com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
    static final com.sun.management.OperatingSystemMXBean PROCESS =
        (com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
    static long gc(boolean time) { long n = 0; for (java.lang.management.GarbageCollectorMXBean g : ManagementFactory.getGarbageCollectorMXBeans()) n += Math.max(0, time ? g.getCollectionTime() : g.getCollectionCount()); return n; }
    static final long TID = Thread.currentThread().threadId();
    static final class Fixed extends SecureRandom
    {
        final byte[] input; int pos;
        Fixed(byte[] input) { this.input = input; }
        public void nextBytes(byte[] out)
        {
            if (pos + out.length > input.length) throw new AssertionError("entropy exhausted");
            System.arraycopy(input, pos, out, 0, out.length); pos += out.length;
        }
    }
    static final class C
    {
        String name, id; byte[][] d;
        MLDSAParameters params;
        MLDSAPublicKeyParameters pk;
        MLDSAPrivateKeyParameters sk;
        void prepare() throws Exception
        {
            params = (MLDSAParameters)MLDSAParameters.class.getField(name).get(null);
            if (d[4].length != 0)
            {
                pk = new MLDSAPublicKeyParameters(params, d[4]);
                sk = new MLDSAPrivateKeyParameters(params, d[5], pk);
            }
        }
    }
    static byte[] derive(String label, int len) throws Exception
    {
        byte[] out = new byte[len]; int pos = 0;
        for (int n = 0; pos < len; ++n)
        {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(("bc-ml-deep-v1/" + label + "/" + n).getBytes("UTF-8"));
            int take = Math.min(h.length, len - pos); System.arraycopy(h, 0, out, pos, take); pos += take;
        }
        return out;
    }
    static String hash(byte[] data) throws Exception
    { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }
    static byte[] joined(byte[] a, byte[] b)
    { byte[] out = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, out, a.length, b.length); return out; }
    static void require(boolean ok, String why) { if (!ok) throw new AssertionError(why); }
    static Signer signer(C c) { return c.params.isPreHash() ? new HashMLDSASigner() : new MLDSASigner(); }
    static final class Call
    {
        final C c; final String op; final byte[][] inputs; final Fixed entropy;
        Call(C c, String op)
        {
            this.c = c; this.op = op;
            inputs = new byte[c.d.length][];
            for (int i = 0; i < inputs.length; ++i) inputs[i] = c.d[i].clone();
            entropy = new Fixed(op.equals("keygen") ? inputs[0] : inputs[3]);
        }
        Object perform() throws Exception
        {
            if (op.equals("keygen"))
            {
                MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();
                kpg.init(new MLDSAKeyGenerationParameters(entropy, c.params));
                return kpg.generateKeyPair();
            }
            if (op.equals("matrix_sample"))
            {
                MLDSAEngine engine = MLDSAEngine.getInstance(c.params, null);
                PolyVecMatrix matrix = new PolyVecMatrix(engine); matrix.expandMatrix(inputs[0]); return matrix;
            }
            if (op.equals("gamma_sample"))
            {
                MLDSAEngine engine = MLDSAEngine.getInstance(c.params, null);
                PolyVec vector = new PolyVec(engine, engine.getDilithiumL());
                vector.uniformGamma1(joined(inputs[0], inputs[0]), (short)42); return vector;
            }
            Signer s = signer(c);
            CipherParameters key = op.equals("sign") ? c.sk : c.pk;
            if (op.equals("sign") && inputs[3].length != 0) key = new ParametersWithRandom(key, entropy);
            s.init(op.equals("sign"), new ParametersWithContext(key, inputs[2]));
            s.update(inputs[1], 0, inputs[1].length);
            return op.equals("sign") ? s.generateSignature() : Boolean.valueOf(s.verifySignature(inputs[6]));
        }
        String check(Object output) throws Exception
        {
            byte[] bytes;
            if (op.equals("keygen"))
            {
                AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)output;
                byte[] pk = ((MLDSAPublicKeyParameters)pair.getPublic()).getEncoded();
                byte[] sk = ((MLDSAPrivateKeyParameters)pair.getPrivate()).getEncoded();
                require(entropy.pos == 32, "keygen entropy use");
                require(Arrays.equals(pk, c.d[4]) && Arrays.equals(sk, c.d[5]), "keygen mismatch");
                bytes = joined(pk, sk);
            }
            else if (op.equals("sign"))
            {
                bytes = (byte[])output;
                require(entropy.pos == c.d[3].length, "sign entropy use");
                require(Arrays.equals(bytes, c.d[6]), "signature mismatch");
                require(verify(c, bytes, c.d[1], c.d[2]), "signature rejected");
            }
            else if (op.equals("matrix_sample") || op.equals("gamma_sample"))
            {
                MLDSAEngine engine = MLDSAEngine.getInstance(c.params, null);
                ByteArrayOutputStream encoded = new ByteArrayOutputStream(); DataOutputStream packed = new DataOutputStream(encoded);
                PolyVec[] rows;
                if (op.equals("matrix_sample"))
                {
                    java.lang.reflect.Field field = PolyVecMatrix.class.getDeclaredField("matrix"); field.setAccessible(true);
                    rows = (PolyVec[])field.get(output);
                }
                else rows = new PolyVec[]{(PolyVec)output};
                for (int i = 0; i < rows.length; ++i) for (int j = 0; j < rows[i].length(); ++j)
                {
                    Poly reference = new Poly(engine);
                    if (op.equals("matrix_sample")) reference.uniformBlocks(inputs[0], (short)((i << 8) + j));
                    else reference.uniformGamma1(joined(inputs[0], inputs[0]), (short)(engine.getDilithiumL() * 42 + j));
                    int[] coefficients = rows[i].getVectorIndex(j).getCoeffs();
                    require(Arrays.equals(coefficients, reference.getCoeffs()), "sampler coefficients");
                    for (int coefficient : coefficients) packed.writeInt(coefficient);
                }
                bytes = encoded.toByteArray();
            }
            else { require(Boolean.TRUE.equals(output), "verification rejected"); bytes = new byte[]{1}; }
            require(Arrays.deepEquals(inputs, c.d), "caller input changed");
            if (c.sk != null) require(Arrays.equals(c.sk.getEncoded(), c.d[5]), "private key changed");
            if (c.pk != null) require(Arrays.equals(c.pk.getEncoded(), c.d[4]), "public key changed");
            return hash(bytes);
        }
    }
    static boolean verify(C c, byte[] sig, byte[] msg, byte[] context) throws Exception
    {
        Signer s = signer(c); s.init(false, new ParametersWithContext(c.pk, context));
        s.update(msg, 0, msg.length); return s.verifySignature(sig);
    }
    static void emit(String file, int count, String domain, boolean allModes) throws Exception
    {
        List<C> cases = new ArrayList<C>();
        for (String name : NAMES)
        {
            if (!allModes && name.contains("with")) continue;
            for (int i = 0; i < count; ++i)
            {
                C c = new C(); c.name = name; c.id = domain + "/" + name + "/" + i; c.d = new byte[7][];
                c.d[0] = derive(c.id + "/seed", 32);
                c.d[1] = derive(c.id + "/message", new int[]{0,1,32,256,1024,4096}[i % 6]);
                c.d[2] = derive(c.id + "/context", new int[]{0,1,255}[i % 3]);
                c.d[3] = derive(c.id + "/random", i % 2 == 0 ? 0 : 32);
                c.d[4] = c.d[5] = c.d[6] = new byte[0]; c.prepare();
                Call kg = new Call(c, "keygen"); AsymmetricCipherKeyPair pair = (AsymmetricCipherKeyPair)kg.perform();
                require(kg.entropy.pos == 32, "fixture seed consumption");
                c.d[4] = ((MLDSAPublicKeyParameters)pair.getPublic()).getEncoded();
                c.d[5] = ((MLDSAPrivateKeyParameters)pair.getPrivate()).getEncoded(); c.prepare();
                Call sign = new Call(c, "sign"); c.d[6] = (byte[])sign.perform();
                require(verify(c, c.d[6], c.d[1], c.d[2]), "fixture signature"); cases.add(c);
            }
        }
        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(Path.of(file), StandardOpenOption.CREATE_NEW)))
        {
            out.writeInt(0x4d4c4431); out.writeInt(cases.size());
            for (C c : cases) { out.writeUTF(c.name); out.writeUTF(c.id); for (byte[] d : c.d) { out.writeInt(d.length); out.write(d); } }
        }
        System.out.println("{\"fixture_cases\":" + cases.size() + "}");
    }
    static List<C> read(String file) throws Exception
    {
        List<C> out = new ArrayList<C>(); Set<String> ids = new HashSet<String>();
        try (DataInputStream in = new DataInputStream(Files.newInputStream(Path.of(file))))
        {
            require(in.readInt() == 0x4d4c4431, "corpus magic"); int count = in.readInt(); require(count > 0 && count <= 100000, "count");
            for (int i = 0; i < count; ++i)
            {
                C c = new C(); c.name = in.readUTF(); c.id = in.readUTF(); require(ids.add(c.id), "duplicate ID"); c.d = new byte[7][];
                for (int j = 0; j < c.d.length; ++j) { int n = in.readInt(); require(n >= 0 && n <= 100000, "length"); c.d[j] = new byte[n]; in.readFully(c.d[j]); }
                c.prepare(); out.add(c);
            }
            require(in.read() == -1, "trailing bytes");
        }
        return out;
    }
    static byte[] changed(byte[] b) { byte[] c = b.length == 0 ? new byte[1] : b.clone(); c[c.length - 1] ^= 1; return c; }
    static void check(String file) throws Exception
    {
        int n = 0, negative = 0;
        for (C c : read(file))
        {
            for (String op : new String[]{"keygen", "sign", "verify"})
            {
                Call call = new Call(c, op); call.check(call.perform()); n++;
                // Repeat from freshly cloned caller buffers, with no retained signer.
                call = new Call(c, op); call.check(call.perform()); n++;
            }
            require(!verify(c, changed(c.d[6]), c.d[1], c.d[2]), "bad signature"); negative++;
            require(!verify(c, c.d[6], changed(c.d[1]), c.d[2]), "bad message"); negative++;
            require(!verify(c, c.d[6], c.d[1], changed(c.d[2])), "bad context"); negative++;
            require(!verify(c, Arrays.copyOf(c.d[6], c.d[6].length - 1), c.d[1], c.d[2]), "truncated signature"); negative++;
            require(verify(c, c.d[6], c.d[1], c.d[2]), "valid after negatives");
        }
        System.out.println("{\"operation_checks\":" + n + ",\"negative_checks\":" + negative + ",\"inputs_preserved\":true}");
    }
    static void bench(String[] args) throws Exception
    {
        String parameter = args[3], operation = args[4];
        require(Arrays.asList("keygen", "sign", "verify", "matrix_sample", "gamma_sample").contains(operation), "operation");
        List<C> warm = read(args[1]), measured = read(args[2]);
        warm.removeIf(c -> !c.name.equals(parameter)); measured.removeIf(c -> !c.name.equals(parameter));
        require(!warm.isEmpty() && !measured.isEmpty(), "missing parameter");
        Set<String> seeds = new HashSet<String>(); for (C c : warm) seeds.add(hash(c.d[0]));
        for (C c : measured) require(seeds.add(hash(c.d[0])), "repeated/overlapping seed");
        THREAD.setThreadAllocatedMemoryEnabled(true); THREAD.setThreadCpuTimeEnabled(true);
        require(THREAD.getThreadAllocatedBytes(TID) >= 0 && THREAD.getCurrentThreadCpuTime() >= 0, "counters unavailable");
        String started = Instant.now().toString(); int iterations = 0; long warmStart = System.nanoTime();
        long compilation0 = ManagementFactory.getCompilationMXBean().getTotalCompilationTime();
        while (iterations < 1000) { C c = warm.get(iterations % warm.size()); Call call = new Call(c, operation); call.check(call.perform()); iterations++; }
        long warmNs = System.nanoTime() - warmStart;
        Collections.shuffle(measured, new Random(Long.parseLong(args[5])));
        StringBuilder rows = new StringBuilder();
        long driverCpu0 = PROCESS.getProcessCpuTime(), gc0 = gc(false), gcMs0 = gc(true);
        for (C c : measured)
        {
            // Key import/validation and caller copies are outside this core-operation clock.
            Call call = new Call(c, operation);
            long alloc0 = THREAD.getThreadAllocatedBytes(TID), cpu0 = THREAD.getCurrentThreadCpuTime();
            long start = System.nanoTime(); Object output = call.perform(); long wall = System.nanoTime() - start;
            long cpu = THREAD.getCurrentThreadCpuTime() - cpu0, allocated = THREAD.getThreadAllocatedBytes(TID) - alloc0;
            String digest = call.check(output);
            if (rows.length() != 0) rows.append(',');
            rows.append("{\"case_id\":\"").append(c.id).append("\",\"wall_ns\":").append(wall)
                .append(",\"cpu_ns\":").append(cpu).append(",\"allocated_bytes\":").append(allocated)
                .append(",\"output_sha256\":\"").append(digest).append("\",\"checked\":true,\"inputs_unchanged\":true}");
        }
        System.out.println("{\"schema\":\"bc-ml-deep-batch-v1\",\"parameter\":\"" + parameter + "\",\"operation\":\"" + operation
            + "\",\"started_at\":\"" + started + "\",\"completed_at\":\"" + Instant.now() + "\",\"keydecode_included\":false,"
            + "\"cpu_scope\":\"calling_thread\",\"caller_copies_included\":false,\"key_policy\":\"unique key per measured call; fresh signer\","
            + "\"driver_includes_checks\":true,\"driver_process_cpu_ns\":" + (PROCESS.getProcessCpuTime() - driverCpu0)
            + ",\"driver_gc_count\":" + (gc(false) - gc0) + ",\"driver_gc_ms\":" + (gc(true) - gcMs0)
            + ",\"compilation_ms_including_warmup\":" + (ManagementFactory.getCompilationMXBean().getTotalCompilationTime() - compilation0)
            + ",\"warmup\":{\"iterations\":" + iterations + ",\"wall_ns\":" + warmNs + "},\"samples\":[" + rows + "]}");
    }
    static void profile(String file, String parameter, String op) throws Exception
    {
        java.lang.reflect.Method reset = Class.forName("org.bouncycastle.crypto.signers.mldsa.StageProfile").getDeclaredMethod("reset");
        java.lang.reflect.Method mark = Class.forName("org.bouncycastle.crypto.signers.mldsa.StageProfile").getDeclaredMethod("mark", String.class);
        java.lang.reflect.Method json = Class.forName("org.bouncycastle.crypto.signers.mldsa.StageProfile").getDeclaredMethod("json");
        reset.setAccessible(true); mark.setAccessible(true); json.setAccessible(true);
        List<C> cases = read(file); cases.removeIf(c -> !c.name.equals(parameter));
        for (int i = 0; i < 1000; ++i) { Call call = new Call(cases.get(i % cases.size()), op); call.check(call.perform()); }
        reset.invoke(null);
        for (C c : cases)
        {
            Call call = new Call(c, op); mark.invoke(null, "public_setup_message_hash");
            Object output = call.perform(); mark.invoke(null, (String)null); call.check(output);
        }
        System.out.println("{\"schema\":\"bc-ml-deep-profile-v1\",\"parameter\":\"" + parameter
            + "\",\"operation\":\"" + op + "\",\"calls\":" + cases.size()
            + ",\"instrumented\":true,\"stages\":" + json.invoke(null) + "}");
    }
    public static void main(String[] args) throws Exception
    {
        switch (args[0])
        {
        case "emit": emit(args[1], Integer.parseInt(args[2]), args[3], Boolean.parseBoolean(args[4])); break;
        case "check": check(args[1]); break;
        case "bench": bench(args); break;
        case "profile": profile(args[1], args[2], args[3]); break;
        default: throw new IllegalArgumentException("unknown mode");
        }
    }
}
