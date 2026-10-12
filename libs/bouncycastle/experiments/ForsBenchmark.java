import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ForsBenchmark
{
    private static final String[] PURE = {"sha2_128f", "sha2_128s", "sha2_192f", "sha2_192s",
        "sha2_256f", "sha2_256s", "shake_128f", "shake_128s", "shake_192f", "shake_192s", "shake_256f", "shake_256s"};
    private static final String[] PREHASH = {"sha256", "sha256", "sha512", "sha512", "sha512", "sha512",
        "shake128", "shake128", "shake256", "shake256", "shake256", "shake256"};
    private static final int[][] SHAPES = {{6, 33}, {12, 14}, {8, 33}, {14, 17}, {9, 35}, {14, 22}};

    private static final class Variant implements AutoCloseable
    {
        final URLClassLoader loader;
        final Class<?> operations;
        Variant(String directory) throws Exception
        {
            loader = new URLClassLoader(new URL[] {Path.of(directory).toUri().toURL()}, ClassLoader.getPlatformClassLoader());
            operations = Class.forName("org.bouncycastle.crypto.signers.slhdsa.ForsOperations", true, loader);
        }
        Object prepare(String name, byte[][][] fixtures) throws Exception
        {
            return operations.getMethod("prepare", String.class, byte[][][].class).invoke(null, name, fixtures);
        }
        String[] validate(Object prepared) throws Exception
        {
            return (String[])operations.getMethod("validate", Object.class).invoke(null, prepared);
        }
        public void close() throws Exception { loader.close(); }
    }

    private static Map<String, byte[][][]> readFixtures(String file) throws Exception
    {
        Map<String, byte[][][]> output = new LinkedHashMap<>();
        try (DataInputStream in = new DataInputStream(Files.newInputStream(Path.of(file))))
        {
            if (in.readInt() != 0x464f5253 || in.readInt() != 24) throw new AssertionError("fixture header");
            for (int parameter = 0; parameter < 24; ++parameter)
            {
                String name = in.readUTF();
                byte[][][] cases = new byte[2][7][];
                for (byte[][] data : cases) for (int field = 0; field < data.length; ++field)
                {
                    int length = in.readInt();
                    if (length < 0 || length > 100000) throw new AssertionError("fixture length");
                    data[field] = new byte[length]; in.readFully(data[field]);
                }
                if (output.put(name, cases) != null) throw new AssertionError("duplicate fixture");
            }
            if (in.read() != -1) throw new AssertionError("trailing fixture data");
        }
        return output;
    }

    private static void fixtures(String directory, String file) throws Exception
    {
        try (Variant variant = new Variant(directory);
             DataOutputStream out = new DataOutputStream(Files.newOutputStream(Path.of(file), StandardOpenOption.CREATE_NEW)))
        {
            out.writeInt(0x464f5253); out.writeInt(24);
            Method create = variant.operations.getMethod("fixtures", String.class, int.class);
            for (int i = 0; i < PURE.length; ++i) for (int prehash = 0; prehash < 2; ++prehash)
            {
                String name = PURE[i] + (prehash == 0 ? "" : "_with_" + PREHASH[i]);
                System.err.println("Generating " + name);
                byte[][][] cases = (byte[][][])create.invoke(null, name, 204);
                out.writeUTF(name);
                for (byte[][] data : cases) for (byte[] bytes : data)
                {
                    out.writeInt(bytes.length); out.write(bytes);
                }
            }
        }
        System.out.println("{\"fixture_cases\":48,\"parameter_modes\":24,\"corpus\":\"fors-base2b-v1/204\"}");
    }

    private static void check(String baseline, String candidate, String file) throws Exception
    {
        Map<String, byte[][][]> fixtures = readFixtures(file);
        int cases = 0, negatives = 0;
        try (Variant before = new Variant(baseline); Variant after = new Variant(candidate))
        {
            for (Map.Entry<String, byte[][][]> entry : fixtures.entrySet())
            {
                System.err.println("Checking " + entry.getKey());
                String[] original = before.validate(before.prepare(entry.getKey(), entry.getValue()));
                String[] changed = after.validate(after.prepare(entry.getKey(), entry.getValue()));
                if (!Arrays.equals(original, changed)) throw new AssertionError("negative-result parity: " + entry.getKey());
                cases += entry.getValue().length;
                negatives += original.length;
            }
        }
        System.out.println("{\"differential_cases\":" + cases + ",\"negative_parity_cases\":" + negatives
            + ",\"operations\":[\"keygen\",\"sign\",\"verify\"],\"caller_inputs_unchanged\":true}");
    }

    private static long[] measure(Variant variant, Object prepared, String operation,
        int[] shape, byte[][] messages, long budgetNs) throws Exception
    {
        if (operation.equals("base2B"))
            return (long[])variant.operations.getMethod("measureHelper", int.class, int.class, byte[][].class, long.class)
                .invoke(null, shape[0], shape[1], messages, budgetNs);
        return (long[])variant.operations.getMethod("measure", String.class, Object.class, long.class)
            .invoke(null, operation, prepared, budgetNs);
    }

    private static String metrics(long[] values)
    {
        if (values[0] <= 0 || values[1] <= 0 || values[2] < 0) throw new AssertionError("invalid metrics");
        return "{\"iterations\":" + values[0] + ",\"elapsed_ns\":" + values[1]
            + ",\"ns_per_op\":" + ((double)values[1] / values[0])
            + ",\"cpu_ns_per_op\":" + ((double)values[2] / values[0]) + "}";
    }

    private static void bench(String[] args) throws Exception
    {
        int fork = Integer.parseInt(args[4]), rounds = Integer.parseInt(args[5]), budgetMs = Integer.parseInt(args[6]);
        String operation = args[7];
        if (fork < 0 || rounds < 2 || rounds > 100 || budgetMs < 100 || budgetMs > 10000
            || !Arrays.asList("base2B", "verify", "sign").contains(operation)) throw new AssertionError("invalid benchmark options");
        Map<String, byte[][][]> fixtures = readFixtures(args[3]);
        try (Variant before = new Variant(args[1]); Variant after = new Variant(args[2]))
        {
            Variant[] variants = {before, after};
            int count = operation.equals("base2B") ? SHAPES.length : PURE.length;
            for (int parameter = 0; parameter < count; ++parameter)
            {
                int[] shape = operation.equals("base2B") ? SHAPES[parameter] : null;
                String name = shape == null ? PURE[parameter] : shape[0] + "x" + shape[1];
                Object[] prepared = {null, null};
                byte[][] messages = null;
                if (shape != null)
                {
                    messages = new byte[8][];
                    Method derive = before.operations.getMethod("derive", String.class, int.class);
                    for (int i = 0; i < messages.length; ++i)
                        messages[i] = (byte[])derive.invoke(null, fork + "/" + name + "/" + i, (shape[0] * shape[1] + 7) / 8);
                }
                else for (int i = 0; i < variants.length; ++i)
                    prepared[i] = variants[i].prepare(name, fixtures.get(name));
                for (int step = 0; step < 2; ++step)
                {
                    int variant = (fork + step) % 2;
                    measure(variants[variant], prepared[variant], operation, shape, messages, 500000000L);
                }
                for (int round = 0; round < rounds; ++round)
                {
                    long[][] pair = new long[2][];
                    for (int step = 0; step < 2; ++step)
                    {
                        int variant = (fork + round + step) % 2;
                        pair[variant] = measure(variants[variant], prepared[variant], operation, shape, messages, budgetMs * 1000000L);
                    }
                    double ratio = ((double)pair[0][1] / pair[0][0]) / ((double)pair[1][1] / pair[1][0]);
                    String order = (fork + round) % 2 == 0 ? "[\"baseline\",\"candidate\"]" : "[\"candidate\",\"baseline\"]";
                    System.out.println("{\"fork\":" + fork + ",\"operation\":\"" + operation + "\",\"parameter\":\"" + name
                        + "\",\"round\":" + round + ",\"order\":" + order + ",\"baseline\":" + metrics(pair[0])
                        + ",\"candidate\":" + metrics(pair[1]) + ",\"speedup\":" + ratio + "}");
                }
            }
        }
    }

    public static void main(String[] args) throws Exception
    {
        if (args.length == 3 && args[0].equals("fixtures")) fixtures(args[1], args[2]);
        else if (args.length == 4 && args[0].equals("check")) check(args[1], args[2], args[3]);
        else if (args.length == 8 && args[0].equals("bench")) bench(args);
        else throw new IllegalArgumentException("fixtures BASE OUT | check BASE NEXT FIXTURES | bench BASE NEXT FIXTURES FORK ROUNDS MS OP");
    }
}
