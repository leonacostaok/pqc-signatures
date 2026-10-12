import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Map;

/** One production implementation and one parameter set per measured JVM. */
public final class ForsIsolatedBenchmark
{
    private static final String[] PARAMETERS = {"sha2_128f", "sha2_128s", "sha2_192f", "sha2_192s",
        "sha2_256f", "sha2_256s", "shake_128f", "shake_128s", "shake_192f", "shake_192s", "shake_256f", "shake_256s"};

    private static Object prepare(Class<?> operations, String name, byte[][][] fixtures) throws Exception
    {
        Object[] cases = (Object[])operations.getMethod("prepare", String.class, byte[][][].class)
            .invoke(null, name, fixtures);
        if (cases.length != 2)
        {
            throw new AssertionError("unexpected corpus size");
        }
        Method verify = operations.getDeclaredMethod("verify", cases[0].getClass(), byte[].class, byte[].class, byte[].class);
        verify.setAccessible(true);
        for (int i = 0; i < cases.length; ++i)
        {
            byte[][] data = fixtures[i];
            if (!Boolean.TRUE.equals(verify.invoke(null, cases[i], data[6], data[1], data[2])))
            {
                throw new AssertionError("valid signature rejected");
            }
            byte[] changed = data[6].clone();
            changed[0] ^= 1;
            if (!Boolean.FALSE.equals(verify.invoke(null, cases[i], changed, data[1], data[2])))
            {
                throw new AssertionError("changed signature accepted");
            }
        }
        return cases;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception
    {
        if (args.length != 3 && args.length != 8)
        {
            throw new IllegalArgumentException("check FIXTURES SIDE | bench FIXTURES SIDE PARAM FORK ROUNDS MS WARMUP_MS");
        }
        if (!args[2].equals("baseline") && !args[2].equals("candidate"))
        {
            throw new IllegalArgumentException("unknown side");
        }
        Class<?> operations = Class.forName("org.bouncycastle.crypto.signers.slhdsa.ForsOperations");
        String source = Path.of(operations.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString();
        Method read = Class.forName("ForsBenchmark").getDeclaredMethod("readFixtures", String.class);
        read.setAccessible(true);
        Map<String, byte[][][]> fixtures = (Map<String, byte[][][]>)read.invoke(null, args[1]);
        if (args[0].equals("check") && args.length == 3)
        {
            for (String name : PARAMETERS)
            {
                prepare(operations, name, fixtures.get(name));
            }
            System.out.println("{\"variant\":\"" + args[2] + "\",\"valid_cases\":24,\"tamper_cases\":24,\"class_source\":\"" + source + "\"}");
            return;
        }
        if (!args[0].equals("bench") || args.length != 8 || !java.util.Arrays.asList(PARAMETERS).contains(args[3]))
        {
            throw new IllegalArgumentException("invalid operation or parameter");
        }
        int fork = Integer.parseInt(args[4]), rounds = Integer.parseInt(args[5]);
        int budgetMs = Integer.parseInt(args[6]), warmupMs = Integer.parseInt(args[7]);
        if (fork < 0 || rounds < 2 || rounds > 100 || budgetMs < 100 || budgetMs > 10000
            || warmupMs < 1000 || warmupMs > 10000)
        {
            throw new IllegalArgumentException("invalid measurement bounds");
        }
        Object cases = prepare(operations, args[3], fixtures.get(args[3]));
        Method measure = operations.getMethod("measure", String.class, Object.class, long.class);
        measure.invoke(null, "verify", cases, warmupMs * 1000000L);
        for (int round = 0; round < rounds; ++round)
        {
            long[] values = (long[])measure.invoke(null, "verify", cases, budgetMs * 1000000L);
            if (values.length != 3 || values[0] <= 0 || values[0] % 2 != 0
                || values[1] < budgetMs * 1000000L || values[2] <= 0)
            {
                throw new AssertionError("invalid whole-corpus metrics");
            }
            System.out.println("{\"variant\":\"" + args[2] + "\",\"parameter\":\"" + args[3]
                + "\",\"fork\":" + fork + ",\"round\":" + round + ",\"iterations\":" + values[0]
                + ",\"elapsed_ns\":" + values[1] + ",\"cpu_ns\":" + values[2]
                + ",\"class_source\":\"" + source + "\"}");
        }
    }
}
