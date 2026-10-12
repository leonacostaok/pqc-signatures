package org.bouncycastle.crypto.signers.slhdsa;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;

/** Ten distinct measured keys once per process; fresh operation objects, imports excluded. */
public final class WotsAlternativeProbe
{
    public static void main(String[] args) throws Exception
    {
        SlhDeepProbe.require(args.length == 7, "MODE FIXTURES PARAMETER VARIANT OP FORK WARMUP_CALLS");
        String mode=args[0], parameter=args[2], variant=args[3], operation=args[4];
        int fork=Integer.parseInt(args[5]), warm=Integer.parseInt(args[6]);
        SlhDeepProbe.require(mode.equals("check") || mode.equals("bench") || mode.equals("allocation"), "mode");
        List<String> lines=Files.readAllLines(Paths.get(args[1]));
        SlhDeepProbe.require(lines.remove(0).equals("pqc-tenkeys-v1/bouncycastle"), "header");
        List<SlhDeepProbe.Case> cases=new ArrayList<SlhDeepProbe.Case>(), measured=new ArrayList<SlhDeepProbe.Case>(), warmup=new ArrayList<SlhDeepProbe.Case>();
        HashSet<String> keys=new HashSet<String>();
        for(String line:lines) {
            String[] fields=line.split("\t",-1);
            if(fields[1].equals(parameter)) {
                SlhDeepProbe.Case c=new SlhDeepProbe.Case(fields); cases.add(c);
                SlhDeepProbe.require(keys.add(SlhDeepProbe.hash(c.pk)), "keys must be distinct");
                if(c.phase.equals("warmup"))warmup.add(c);else measured.add(c);
            }
        }
        SlhDeepProbe.require(cases.size()==12 && warmup.size()==2 && measured.size()==10, "corpus coverage");
        String source=Paths.get(WotsPlus.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString();
        if(mode.equals("check")) {
            for(SlhDeepProbe.Case c:cases) {
                if(parameter.endsWith("s") && !(c.phase.equals("measured") && c.index==0))continue;
                for(String op:SlhDeepProbe.TOTALS) {
                    Object result=c.execute(op); c.checked(op,result,c.expected(op));
                    System.out.println("{\"mode\":\"check\",\"variant\":"+SlhDeepProbe.quote(variant)+",\"parameter\":"+SlhDeepProbe.quote(parameter)+",\"phase\":"+SlhDeepProbe.quote(c.phase)+",\"case\":"+c.index+",\"operation\":"+SlhDeepProbe.quote(op)+",\"output_sha256\":"+SlhDeepProbe.quote(SlhDeepProbe.hash(SlhDeepProbe.flat(result)))+",\"class_source\":"+SlhDeepProbe.quote(source)+",\"checked\":true}");
                }
            }
            return;
        }
        SlhDeepProbe.require(warm>=2 && warm<=80 && warm%2==0, "bounded warmup");
        SlhDeepProbe.require(java.util.Arrays.asList(SlhDeepProbe.TOTALS).contains(operation), "operation");
        for(int i=0;i<warm;i++) {
            SlhDeepProbe.Case c=warmup.get(i%2);c.checked(operation,c.execute(operation),c.expected(operation));
        }
        long tid=Thread.currentThread().getId();
        SlhDeepProbe.require(SlhDeepProbe.THREAD.isCurrentThreadCpuTimeSupported() && SlhDeepProbe.THREAD.isThreadAllocatedMemorySupported(), "counter support");
        SlhDeepProbe.THREAD.setThreadAllocatedMemoryEnabled(true);SlhDeepProbe.THREAD.setThreadCpuTimeEnabled(true);
        for(SlhDeepProbe.Case c:measured) {
            byte[] expected=c.expected(operation);long wall=0,cpu=0,thread=0,allocated=0;
            if(mode.equals("allocation"))allocated=SlhDeepProbe.THREAD.getThreadAllocatedBytes(tid);
            else {cpu=SlhDeepProbe.CPU.getProcessCpuTime();thread=SlhDeepProbe.THREAD.getCurrentThreadCpuTime();wall=System.nanoTime();}
            Object result=c.execute(operation);
            if(mode.equals("allocation"))allocated=SlhDeepProbe.THREAD.getThreadAllocatedBytes(tid)-allocated;
            else {wall=System.nanoTime()-wall;thread=SlhDeepProbe.THREAD.getCurrentThreadCpuTime()-thread;cpu=SlhDeepProbe.CPU.getProcessCpuTime()-cpu;}
            SlhDeepProbe.require(wall>=0 && cpu>=0 && thread>=0 && allocated>=0, "counters");
            SlhDeepProbe.sink=result;c.checked(operation,result,expected);
            System.out.println("{\"mode\":"+SlhDeepProbe.quote(mode)+",\"variant\":"+SlhDeepProbe.quote(variant)+",\"parameter\":"+SlhDeepProbe.quote(parameter)+",\"operation\":"+SlhDeepProbe.quote(operation)+",\"fork\":"+fork+",\"case\":"+c.index+",\"warmup_calls\":"+warm+",\"wall_ns\":"+wall+",\"cpu_ns\":"+cpu+",\"thread_cpu_ns\":"+thread+",\"allocated_bytes\":"+allocated+",\"output_sha256\":"+SlhDeepProbe.quote(SlhDeepProbe.hash(SlhDeepProbe.flat(result)))+",\"class_source\":"+SlhDeepProbe.quote(source)+",\"checked\":true}");
        }
    }
}
