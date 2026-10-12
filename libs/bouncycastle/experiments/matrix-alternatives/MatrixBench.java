package org.bouncycastle.crypto.signers.mldsa;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.*;

/** Separate time/allocated-byte cohorts; fresh operation objects and unique measured keys. */
public final class MatrixBench {
    static final com.sun.management.ThreadMXBean THREAD=(com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
    static final com.sun.management.OperatingSystemMXBean PROCESS=(com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
    public static void main(String[] a)throws Exception{
        MLDeep.require(a.length==7,"mode warm measured parameter operation shuffle variant");
        boolean timing=a[0].equals("timing");MLDeep.require(timing||a[0].equals("allocation"),"mode");
        MLDeep.require(Arrays.asList("keygen","sign","verify").contains(a[4]),"operation");
        List<MLDeep.C>warm=MLDeep.read(a[1]),measured=MLDeep.read(a[2]);warm.removeIf(c->!c.name.equals(a[3]));measured.removeIf(c->!c.name.equals(a[3]));
        MLDeep.require(warm.size()>=2&&measured.size()==128,"corpus size");warm=new ArrayList<MLDeep.C>(warm.subList(0,2));
        Set<String>seeds=new HashSet<String>();for(MLDeep.C c:warm)MLDeep.require(seeds.add(MLDeep.hash(c.d[0])),"duplicate warmup seed");for(MLDeep.C c:measured)MLDeep.require(seeds.add(MLDeep.hash(c.d[0])),"overlapping key");
        if(timing){MLDeep.require(THREAD.isCurrentThreadCpuTimeSupported(),"CPU unavailable");THREAD.setThreadCpuTimeEnabled(true);}else{MLDeep.require(THREAD.isThreadAllocatedMemorySupported(),"allocation unavailable");THREAD.setThreadAllocatedMemoryEnabled(true);}
        String started=Instant.now().toString();
        for(int i=0;i<1000;i++){MLDeep.Call call=new MLDeep.Call(warm.get(i%2),a[4]);call.check(call.perform());}
        Collections.shuffle(measured,new Random(Long.parseLong(a[5])));
        long[][] values=new long[128][3];String[]hashes=new String[128];
        long tid=Thread.currentThread().threadId();
        for(int i=0;i<128;i++){
            MLDeep.C c=measured.get(i);MLDeep.Call call=new MLDeep.Call(c,a[4]);Object result;
            if(timing){long cpu=THREAD.getCurrentThreadCpuTime();long t=System.nanoTime();result=call.perform();values[i][0]=System.nanoTime()-t;values[i][1]=THREAD.getCurrentThreadCpuTime()-cpu;MLDeep.require(values[i][0]>0&&values[i][1]>0,"time counter");}
            else{long allocated=THREAD.getThreadAllocatedBytes(tid);result=call.perform();values[i][2]=THREAD.getThreadAllocatedBytes(tid)-allocated;MLDeep.require(values[i][2]>=0,"allocation counter");}
            hashes[i]=call.check(result);
            if(a[4].equals("verify"))MLDeep.require(!MLDeep.verify(c,MLDeep.changed(c.d[6]),c.d[1],c.d[2]),"tamper accepted");
        }
        StringBuilder rows=new StringBuilder();for(int i=0;i<128;i++){if(i!=0)rows.append(',');rows.append("{\"case_id\":\"").append(measured.get(i).id).append("\",\"output_sha256\":\"").append(hashes[i]).append("\",\"checked\":true,\"inputs_unchanged\":true");if(timing)rows.append(",\"wall_ns\":").append(values[i][0]).append(",\"cpu_ns\":").append(values[i][1]);else rows.append(",\"allocated_bytes\":").append(values[i][2]);rows.append('}');}
        System.out.println("{\"schema\":\"bc-ntt-batch-v1\",\"mode\":\""+a[0]+"\",\"variant\":\""+a[6]+"\",\"parameter\":\""+a[3]+"\",\"operation\":\""+a[4]+"\",\"started_at\":\""+started+"\",\"completed_at\":\""+Instant.now()+"\",\"warmup_calls\":1000,\"warmup_keys\":2,\"keydecode_included\":false,\"keygen_encoding_included\":false,\"caller_copies_included\":false,\"samples\":["+rows+"]}");
    }
}
