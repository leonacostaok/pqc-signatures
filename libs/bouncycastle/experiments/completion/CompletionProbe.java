import java.io.*;
import java.nio.file.*;
import java.lang.management.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.pqc.crypto.falcon.*;

/** Separate baseline completion and runtime-resource diagnostics, never a combined patch. */
public final class CompletionProbe {
 static final com.sun.management.ThreadMXBean THREAD=(com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
 static final com.sun.management.OperatingSystemMXBean OS=(com.sun.management.OperatingSystemMXBean)ManagementFactory.getOperatingSystemMXBean();
 static byte[] hash(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x&255));return s.toString();}
 static byte[] decode(String h){byte[] b=new byte[h.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(h.substring(2*i,2*i+2),16);return b;}
 static void require(boolean b,String s){if(!b)throw new AssertionError(s);}
 static byte[] cat(byte[]a,byte[]b){byte[]r=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,r,a.length,b.length);return r;}
 static String quote(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
 static final class Entropy extends SecureRandom {final byte[] seed;final boolean expand;int pos,counter;byte[]block=new byte[0];Entropy(byte[]s,boolean e){seed=s.clone();expand=e;}public void nextBytes(byte[]out){for(int i=0;i<out.length;i++){if(expand){if(pos==block.length){try{block=hash(cat(seed,new byte[]{(byte)(counter>>>24),(byte)(counter>>>16),(byte)(counter>>>8),(byte)counter}));}catch(Exception e){throw new RuntimeException(e);}counter++;pos=0;}out[i]=block[pos++];}else{require(pos<seed.length,"entropy exhausted");out[i]=seed[pos++];}}}void check(){if(!expand)require(pos==seed.length,"entropy unused");}}
 static final class Case {
  final String p;final int index;final byte[]seed,message,context,random;byte[]pk,sk,sig,keys;String[] hashes;
  Case(String p,int index,byte[]seed,byte[]message,byte[]context,byte[]random){this.p=p;this.index=index;this.seed=seed;this.message=message;this.context=context;this.random=random;}
  byte[] integrity()throws Exception{return hash(cat(cat(cat(cat(seed,message),cat(context,random)),cat(pk,sk)),sig));}
  Object param()throws Exception{if(p.startsWith("sha"))return SLHDSAParameters.class.getField(p).get(null);if(p.startsWith("ml_dsa"))return MLDSAParameters.class.getField(p).get(null);return p.equals("falcon_512")?FalconParameters.falcon_512:FalconParameters.falcon_1024;}
  byte[] keygen()throws Exception{Object p0=param();Entropy r=new Entropy(seed,p.startsWith("falcon"));AsymmetricCipherKeyPair pair;
   if(p0 instanceof SLHDSAParameters){SLHDSAKeyPairGenerator g=new SLHDSAKeyPairGenerator();g.init(new SLHDSAKeyGenerationParameters(r,(SLHDSAParameters)p0));pair=g.generateKeyPair();r.check();return cat(((SLHDSAPublicKeyParameters)pair.getPublic()).getEncoded(),((SLHDSAPrivateKeyParameters)pair.getPrivate()).getEncoded());}
   if(p0 instanceof MLDSAParameters){MLDSAKeyPairGenerator g=new MLDSAKeyPairGenerator();g.init(new MLDSAKeyGenerationParameters(r,(MLDSAParameters)p0));pair=g.generateKeyPair();r.check();return cat(((MLDSAPublicKeyParameters)pair.getPublic()).getEncoded(),((MLDSAPrivateKeyParameters)pair.getPrivate()).getEncoded());}
   FalconKeyPairGenerator g=new FalconKeyPairGenerator();g.init(new FalconKeyGenerationParameters(r,(FalconParameters)p0));pair=g.generateKeyPair();return cat(((FalconPublicKeyParameters)pair.getPublic()).getH(),((FalconPrivateKeyParameters)pair.getPrivate()).getEncoded());
  }
  int pklen()throws Exception {if(p.startsWith("sha"))return((SLHDSAParameters)param()).getN()*2;if(p.startsWith("ml_dsa"))return p.endsWith("44")?1312:p.endsWith("65")?1952:2592;return p.endsWith("512")?896:1792;}
  byte[] sign()throws Exception{Object p0=param();Entropy r=new Entropy(random,p.startsWith("falcon"));byte[]result;
   if(p0 instanceof SLHDSAParameters){SLHDSASigner s=new SLHDSASigner();s.init(true,new ParametersWithContext(new ParametersWithRandom(new SLHDSAPrivateKeyParameters((SLHDSAParameters)p0,sk),r),context));result=s.generateSignature(message);r.check();return result;}
   if(p0 instanceof MLDSAParameters){MLDSASigner s=new MLDSASigner();s.init(true,new ParametersWithContext(new ParametersWithRandom(new MLDSAPrivateKeyParameters((MLDSAParameters)p0,sk,new MLDSAPublicKeyParameters((MLDSAParameters)p0,pk)),r),context));s.update(message,0,message.length);result=s.generateSignature();r.check();return result;}
   int n=p.endsWith("512")?512:1024,part=(sk.length-n)/2;FalconPrivateKeyParameters k=new FalconPrivateKeyParameters((FalconParameters)p0,Arrays.copyOfRange(sk,0,part),Arrays.copyOfRange(sk,part,2*part),Arrays.copyOfRange(sk,2*part,sk.length),pk);FalconSigner s=new FalconSigner();s.init(true,new ParametersWithRandom(k,r));return s.generateSignature(message);
  }
  boolean verify(byte[]signature)throws Exception{Object p0=param();if(p0 instanceof SLHDSAParameters){SLHDSASigner s=new SLHDSASigner();s.init(false,new ParametersWithContext(new SLHDSAPublicKeyParameters((SLHDSAParameters)p0,pk),context));return s.verifySignature(message,signature);}if(p0 instanceof MLDSAParameters){MLDSASigner s=new MLDSASigner();s.init(false,new ParametersWithContext(new MLDSAPublicKeyParameters((MLDSAParameters)p0,pk),context));s.update(message,0,message.length);return s.verifySignature(signature);}FalconSigner s=new FalconSigner();s.init(false,new FalconPublicKeyParameters((FalconParameters)p0,pk));return s.verifySignature(message,signature);}
  byte[]execute(String op)throws Exception{if(op.equals("keygen"))return keygen();if(op.equals("sign"))return sign();return new byte[]{(byte)(verify(sig)?1:0)};}
  byte[]expected(String op){return op.equals("keygen")?keys:op.equals("sign")?sig:new byte[]{1};}
  void check(String op,byte[]actual)throws Exception{require(Arrays.equals(actual,expected(op)),"output mismatch "+p+" "+index+" "+op);if(op.equals("verify")){byte[]bad=sig.clone();bad[0]^=1;require(!verify(bad),"tamper accepted");}}
 }
 static byte[]derive(int index,int n,int tag){byte[]r=new byte[n];for(int j=0;j<n;j++)r[j]=(byte)((index+71)*37+j*13+tag);return r;}
 static List<Case>cases(String p,String fixture)throws Exception{List<Case>out=new ArrayList<Case>();if(p.startsWith("sha")){List<String>lines=Files.readAllLines(Paths.get(fixture));require(lines.remove(0).equals("pqc-tenkeys-v1/bouncycastle"),"fixture header");for(String line:lines){String[]d=line.split("\t",-1);if(d[1].equals(p)){Case c=new Case(p,out.size(),decode(d[3]),decode(d[4]),decode(d[5]),decode(d[6]));c.pk=decode(d[7]);c.sk=decode(d[8]);c.sig=decode(d[9]);out.add(c);}}}else for(int i=0;i<12;i++){Case c=new Case(p,i,derive(i,32,5),derive(i,new int[]{0,1,64,128,1024}[i%5],11),p.startsWith("falcon")?new byte[0]:derive(i,new int[]{0,1,31,255}[i%4],17),p.startsWith("falcon")?derive(i,32,23):new byte[32]);byte[]keys=c.keygen();c.pk=Arrays.copyOfRange(keys,0,c.pklen());c.sk=Arrays.copyOfRange(keys,c.pklen(),keys.length);c.sig=c.sign();require(c.verify(c.sig),"fixture invalid");out.add(c);}require(out.size()==12,"case count");for(Case c:out){c.keys=cat(c.pk,c.sk);c.hashes=new String[]{hex(hash(c.keys)),hex(hash(c.sig)),hex(hash(new byte[]{1}))};}return out;}
 static long[]gc(){long count=0,time=0;for(GarbageCollectorMXBean g:ManagementFactory.getGarbageCollectorMXBeans()){require(g.getCollectionCount()>=0&&g.getCollectionTime()>=0,"GC unsupported");count+=g.getCollectionCount();time+=g.getCollectionTime();}return new long[]{count,time};}
 static long heap(){return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();}
 static String source(String name)throws Exception{return Paths.get(Class.forName(name).getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath().toString();}
 public static void main(String[]a)throws Exception{require(a.length==7,"check|timing|resource PARAM VARIANT FIXTURE OP WARM CYCLES");require(Arrays.asList("check","timing","resource").contains(a[0]),"mode");require(THREAD.isCurrentThreadCpuTimeSupported()&&THREAD.isThreadAllocatedMemorySupported(),"thread counters");THREAD.setThreadCpuTimeEnabled(true);THREAD.setThreadAllocatedMemoryEnabled(true);List<Case>cases=cases(a[1],a[3]);String[]ops=a[4].equals("all")?new String[]{"keygen","sign","verify"}:new String[]{a[4]};int warm=Integer.parseInt(a[5]),cycles=Integer.parseInt(a[6]);require(warm>=0&&cycles>=1,"counts");String affected=a[1].startsWith("ml_dsa")?"org.bouncycastle.crypto.signers.mldsa.Poly":a[1].startsWith("sha")?"org.bouncycastle.crypto.signers.slhdsa.Fors":"org.bouncycastle.pqc.crypto.falcon.FalconSigner";
  for(String op:ops){byte[][]inputHashes=new byte[cases.size()][];for(int ci=0;ci<cases.size();ci++)inputHashes[ci]=cases.get(ci).integrity();require(Arrays.asList("keygen","sign","verify").contains(op),"operation");for(int j=0;j<warm;j++)for(Case c:cases.subList(0,2))c.check(op,c.execute(op));
   if(a[0].equals("resource")){System.gc();Thread.sleep(30);}long before=heap();long[]g0=gc();long totalWall=0,totalCpu=0,totalAllocated=0;long[][] records=new long[cycles*cases.size()][5];int rows=0;
   for(int cycle=0;cycle<cycles;cycle++)for(Case c:cases){if(!a[0].equals("check")&&c.index<2)continue;long t=0,cpu=0,allocated=0,wall=0;if(!a[0].equals("check")){allocated=THREAD.getThreadAllocatedBytes(Thread.currentThread().getId());cpu=THREAD.getCurrentThreadCpuTime();t=System.nanoTime();}byte[]value=c.execute(op);if(!a[0].equals("check")){wall=System.nanoTime()-t;cpu=THREAD.getCurrentThreadCpuTime()-cpu;allocated=THREAD.getThreadAllocatedBytes(Thread.currentThread().getId())-allocated;require(wall>0&&cpu>=0&&allocated>=0,"counter negative");}c.check(op,value);totalWall+=wall;totalCpu+=cpu;totalAllocated+=allocated;records[rows++]=new long[]{c.index,cycle,wall,cpu,allocated};}
   long[]g1=gc();long after=heap();long post=-1;if(a[0].equals("resource")){System.gc();Thread.sleep(30);post=heap();}for(int ci=0;ci<cases.size();ci++)require(Arrays.equals(inputHashes[ci],cases.get(ci).integrity()),"caller fixture mutated");for(int ri=0;ri<rows;ri++){long[]r=records[ri];Case c=cases.get((int)r[0]);int oi=op.equals("keygen")?0:op.equals("sign")?1:2;System.out.println("{\"type\":\"sample\",\"parameter\":"+quote(a[1])+",\"variant\":"+quote(a[2])+",\"operation\":"+quote(op)+",\"index\":"+r[0]+",\"cycle\":"+r[1]+",\"output_sha256\":"+quote(c.hashes[oi])+",\"wall_ns\":"+r[2]+",\"thread_cpu_ns\":"+r[3]+",\"allocated_bytes\":"+r[4]+",\"checked\":true,\"input_integrity\":true,\"class_source\":"+quote(source(affected))+"}");}
   System.out.println("{\"type\":\"batch\",\"parameter\":"+quote(a[1])+",\"variant\":"+quote(a[2])+",\"operation\":"+quote(op)+",\"warmup_calls\":"+(2*warm)+",\"cycles\":"+cycles+",\"wall_ns_sum\":"+totalWall+",\"thread_cpu_ns_sum\":"+totalCpu+",\"allocated_bytes_sum\":"+totalAllocated+",\"heap_before_bytes\":"+before+",\"heap_after_bytes\":"+after+",\"heap_post_requested_gc_bytes\":"+post+",\"gc_count\":"+(g1[0]-g0[0])+",\"gc_time_ms\":"+(g1[1]-g0[1])+"}");
  }
 }
}
