import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

/** Runs native test methods while proving that changed classes come from the variant. */
public final class NativeMethods {
    public static void main(String[] args) throws Exception {
        File expected = new File(args[0]).getCanonicalFile();
        for (String name : args[1].split(",")) {
            Class<?> type = Class.forName(name);
            File actual = new File(type.getProtectionDomain().getCodeSource().getLocation().toURI()).getCanonicalFile();
            if (!expected.equals(actual)) throw new AssertionError("wrong class origin: " + name + " " + actual);
            System.out.println("ORIGIN " + name + " " + actual);
        }
        int total = 0;
        List<Failure> failures = new ArrayList<Failure>();
        for (int i = 2; i < args.length; i++) {
            String[] item = args[i].split("#", 2);
            Class<?> type = Class.forName(item[0]);
            Request request = item.length == 1 ? Request.aClass(type) : Request.method(type, item[1]);
            Result result = new JUnitCore().run(request);
            total += result.getRunCount();
            failures.addAll(result.getFailures());
            System.out.println("TEST " + args[i] + " count=" + result.getRunCount() + " ignored=" + result.getIgnoreCount() + " failures=" + result.getFailureCount());
            if (result.getRunCount() == 0 || result.getIgnoreCount() != 0) throw new AssertionError("empty/ignored native suite");
        }
        for (Failure failure : failures) System.out.println(failure.getTrace());
        if (!failures.isEmpty()) throw new AssertionError("native failures: " + failures.size());
        System.out.println("PASS native methods=" + total);
    }
}
