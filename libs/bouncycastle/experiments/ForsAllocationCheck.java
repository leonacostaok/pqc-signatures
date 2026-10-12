package org.bouncycastle.crypto.signers.slhdsa;

import java.lang.management.ManagementFactory;
import java.util.Random;

/** HotSpot-only allocation regression probe, deliberately separate from upstream tests. */
public final class ForsAllocationCheck
{
    private static volatile int[] sink;

    public static void main(String[] args)
    {
        com.sun.management.ThreadMXBean bean =
            (com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
        if (!bean.isThreadAllocatedMemorySupported())
        {
            throw new IllegalStateException("Thread allocation accounting is unavailable");
        }
        bean.setThreadAllocatedMemoryEnabled(true);
        int[][] shapes = {{6, 33}, {12, 14}, {8, 33}, {14, 17}, {9, 35}, {14, 22}};
        boolean withinBudget = true;
        for (int[] shape : shapes)
        {
            int b = shape[0], count = shape[1];
            byte[] message = new byte[(b * count + 7) / 8];
            new Random(204L + b * 100 + count).nextBytes(message);
            for (int i = 0; i < 2000; ++i)
            {
                sink = Fors.base2B(message, b, count);
            }
            long thread = Thread.currentThread().getId();
            long before = bean.getThreadAllocatedBytes(thread);
            for (int i = 0; i < 2000; ++i)
            {
                sink = Fors.base2B(message, b, count);
            }
            long allocated = bean.getThreadAllocatedBytes(thread) - before;
            double bytesPerCall = allocated / 2000.0;
            System.out.println("{\"b\":" + b + ",\"count\":" + count
                + ",\"calls\":2000,\"bytes_per_call\":" + bytesPerCall + "}");
            // The returned int[] is required; temporary arbitrary-precision objects are not.
            withinBudget &= bytesPerCall <= 512;
        }
        if (args.length > 0 && args[0].equals("require-bounded") && !withinBudget)
        {
            throw new AssertionError("base2B allocates more than 512 bytes per call");
        }
    }
}
