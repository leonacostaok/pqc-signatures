package org.bouncycastle.crypto.signers.mldsa;

import java.util.LinkedHashMap;
import java.util.Map;

/** Instrumented-build diagnostics only. Never loaded by the performance build. */
public final class StageProfile
{
    static final Map<String, Long> nanos = new LinkedHashMap<String, Long>();
    static final Map<String, Long> counts = new LinkedHashMap<String, Long>();
    static boolean enabled;
    static String current;
    static long start;
    static void mark(String name)
    {
        if ("public_setup_message_hash".equals(name)) enabled = true;
        if (!enabled) return;
        long now = System.nanoTime();
        if (current != null) nanos.put(current, nanos.getOrDefault(current, 0L) + now - start);
        current = name; start = now;
        if (name == null) enabled = false;
        if (name != null) counts.put(name, counts.getOrDefault(name, 0L) + 1);
    }
    static void reset() { enabled = false; current = null; nanos.clear(); counts.clear(); }
    static String json()
    {
        StringBuilder s = new StringBuilder("[");
        for (Map.Entry<String, Long> e : nanos.entrySet())
        {
            if (s.length() > 1) s.append(',');
            s.append("{\"stage\":\"").append(e.getKey()).append("\",\"wall_ns\":").append(e.getValue())
                .append(",\"entries\":").append(counts.get(e.getKey())).append('}');
        }
        return s.append(']').toString();
    }
}
