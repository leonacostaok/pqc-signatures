import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Map;

/** Separate allocation-only check; it does not modify or time the frozen experiment. */
public final class ForsVerifyAllocation
{
    private static final com.sun.management.ThreadMXBean BEAN =
        (com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();

    private static final class Variant implements AutoCloseable
    {
        final URLClassLoader loader;
        final Class<?> operations;
        Method verify;
        Object[][] arguments;

        Variant(String directory) throws Exception
        {
            loader = new URLClassLoader(new URL[]{Path.of(directory).toUri().toURL()},
                ClassLoader.getPlatformClassLoader());
            operations = Class.forName("org.bouncycastle.crypto.signers.slhdsa.ForsOperations", true, loader);
        }

        void prepare(String name, byte[][][] fixtures) throws Exception
        {
            Object[] cases = (Object[])operations.getMethod("prepare", String.class, byte[][][].class)
                .invoke(null, name, fixtures);
            verify = operations.getDeclaredMethod("verify", cases[0].getClass(), byte[].class, byte[].class, byte[].class);
            verify.setAccessible(true);
            arguments = new Object[cases.length][];
            for (int i = 0; i < cases.length; ++i)
            {
                arguments[i] = new Object[]{cases[i], fixtures[i][6], fixtures[i][1], fixtures[i][2]};
            }
        }

        long allocated(int cycles) throws Exception
        {
            long id = Thread.currentThread().threadId();
            long start = BEAN.getThreadAllocatedBytes(id);
            if (start < 0)
            {
                throw new AssertionError("allocation counter unavailable");
            }
            for (int cycle = 0; cycle < cycles; ++cycle)
            {
                for (Object[] args : arguments)
                {
                    if (!Boolean.TRUE.equals(verify.invoke(null, args)))
                    {
                        throw new AssertionError("verification failed");
                    }
                }
            }
            long bytes = BEAN.getThreadAllocatedBytes(id) - start;
            if (bytes < 0)
            {
                throw new AssertionError("allocation counter unavailable");
            }
            return bytes;
        }

        public void close() throws Exception
        {
            loader.close();
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception
    {
        if (args.length != 3 || !BEAN.isThreadAllocatedMemorySupported())
        {
            throw new AssertionError("unsupported invocation/runtime");
        }
        BEAN.setThreadAllocatedMemoryEnabled(true);
        Method read = Class.forName("ForsBenchmark").getDeclaredMethod("readFixtures", String.class);
        read.setAccessible(true);
        Map<String, byte[][][]> fixtures = (Map<String, byte[][][]>)read.invoke(null, args[2]);
        try (Variant baseline = new Variant(args[0]); Variant candidate = new Variant(args[1]))
        {
            int parameter = 0;
            for (Map.Entry<String, byte[][][]> entry : fixtures.entrySet())
            {
                if (entry.getKey().contains("_with_"))
                {
                    continue;
                }
                baseline.prepare(entry.getKey(), entry.getValue());
                candidate.prepare(entry.getKey(), entry.getValue());
                if (parameter % 2 == 0)
                {
                    baseline.allocated(128); candidate.allocated(128);
                }
                else
                {
                    candidate.allocated(128); baseline.allocated(128);
                }
                for (int round = 0; round < 4; ++round)
                {
                    long before, after;
                    boolean baselineFirst = (parameter + round) % 2 == 0;
                    if (baselineFirst)
                    {
                        before = baseline.allocated(64); after = candidate.allocated(64);
                    }
                    else
                    {
                        after = candidate.allocated(64); before = baseline.allocated(64);
                    }
                    System.out.println("{\"parameter\":\"" + entry.getKey() + "\",\"round\":" + round
                        + ",\"calls_per_side\":128,\"order\":\"" + (baselineFirst ? "AB" : "BA")
                        + "\",\"baseline_bytes\":" + before + ",\"candidate_bytes\":" + after + "}");
                }
                ++parameter;
            }
            if (parameter != 12)
            {
                throw new AssertionError("incomplete parameter corpus");
            }
        }
    }
}
