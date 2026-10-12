package org.bouncycastle.crypto.signers.mldsa;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/** Bounded independent arithmetic oracle; no performance counters. */
public final class NTTGate {
    static final int Q=8380417, QI=58728449, F=41978;
    static final BigInteger BQ=BigInteger.valueOf(Q), BQI=BigInteger.valueOf(QI);
    static int reductions, forwards, inverses, products, differentRepresentatives;
    static void require(boolean b,String s){if(!b)throw new AssertionError(s);}
    static int oracleMR(long x){BigInteger a=BigInteger.valueOf(x);int t=a.multiply(BQI).intValue();return a.subtract(BigInteger.valueOf(t).multiply(BQ)).shiftRight(32).intValue();}
    static int mr(long a){int t=(int)a*QI;return (int)((a-(long)t*Q)>>32);}
    static int canonical(int x){return x<0?x+Q:x;}
    static void intRange(long x){require(x>=Integer.MIN_VALUE&&x<=Integer.MAX_VALUE,"int overflow");}
    static int[] forward(int[] in){
        int[] a=in.clone();int k=0;
        for(int len=128;len>0;len>>=1)for(int start=0;start<256;start+=2*len){int z=Ntt.nttZetas[++k];for(int j=start;j<start+len;j++){int t=mr((long)z*a[j+len]),u=a[j];intRange((long)u+t);intRange((long)u-t);a[j]=u+t;a[j+len]=u-t;}}
        return a;
    }
    static int[] inverse(int[] in){
        int[] a=in.clone();int k=256;
        for(int len=1;len<256;len<<=1)for(int start=0;start<256;start+=2*len){int z=-Ntt.nttZetas[--k];for(int j=start;j<start+len;j++){int u=a[j],v=a[j+len];intRange((long)u+v);intRange((long)u-v);a[j]=u+v;a[j+len]=mr((long)z*(u-v));}}
        for(int j=0;j<256;j++)a[j]=mr((long)F*a[j]);return a;
    }
    static void transforms(int[] in){
        int[] a=in.clone();Ntt.ntt(a);require(Arrays.equals(a,forward(in)),"forward raw representatives");forwards++;
        a=in.clone();Ntt.invNttToMont(a);int[] b=inverse(in);
        for(int i=0;i<256;i++){require(Math.abs(a[i])<Q,"inverse output bound");require(canonical(a[i])==canonical(b[i]),"inverse canonical mismatch");if(a[i]!=b[i])differentRepresentatives++;for(int s:new int[]{-11,-5,0,2,4,11}){require(Math.abs(a[i]+s)<Q,"keygen addition bound");require(canonical(a[i]+s)==canonical(b[i]+s),"keygen representative");}}inverses++;
    }
    static int[] schoolbook(int[] c,int[] s){int[] out=new int[256];for(int i=0;i<256;i++)if(c[i]!=0)for(int j=0;j<256;j++){int n=i+j;out[n&255]+=c[i]*s[j]*(n<256?1:-1);}return out;}
    public static void main(String[] args){
        require(mr(41978L*-25847)==3975713,"folded constant");
        long limit=(long)Q*(1L<<31);
        for(long x:new long[]{-limit,-limit+1,-81L*Q*Q,-1,0,1,81L*Q*Q,limit-1,limit}){require(Reduce.montgomeryReduce(x)==oracleMR(x),"signed reduction endpoints");reductions++;}
        for(int z:Ntt.nttZetas)for(int x:new int[]{-256*Q+1,-9*Q+1,-Q,-1,0,1,Q,9*Q-1,256*Q-1}){
            long a=(long)z*x;int t=x*(z*QI);int companion=(int)((a-(long)t*Q)>>32);
            require(companion==oracleMR(a)&&companion==Reduce.montgomeryReduce(a),"twiddle companion");reductions++;
        }
        Random random=new Random(0x204L);
        int[] zero=new int[256],pos=new int[256],neg=new int[256],alt=new int[256];Arrays.fill(pos,Q-1);Arrays.fill(neg,1-Q);for(int i=0;i<256;i++)alt[i]=(i%2==0?Q-1:1-Q);
        for(int[] a:new int[][]{zero,pos,neg,alt})transforms(a);
        for(int n=0;n<512;n++){int[] a=new int[256];for(int i=0;i<256;i++)a[i]=random.nextInt(2*Q-1)-(Q-1);transforms(a);}
        for(int tau:new int[]{39,49,60})for(int[] bounds:new int[][]{{-5,2},{-11,4},{-4095,4096}})for(int n=0;n<12;n++){
            int[] c=new int[256],s=new int[256];for(int j=0;j<tau;){int i=random.nextInt(256);if(c[i]==0){c[i]=random.nextBoolean()?1:-1;j++;}}
            for(int i=0;i<256;i++)s[i]=n<2?(((i+n)%2==0)?bounds[0]:bounds[1]):bounds[0]+random.nextInt(bounds[1]-bounds[0]+1);
            int[] expected=schoolbook(c,s),a=c.clone(),b=s.clone();Ntt.ntt(a);Ntt.ntt(b);for(int i=0;i<256;i++){a[i]=Reduce.montgomeryReduce((long)a[i]*b[i]);require(Math.abs(a[i])<Q,"pointwise input bound");}Ntt.invNttToMont(a);require(Arrays.equals(a,expected),"exact sparse product");products++;
        }
        System.out.println("{\"reductions\":"+reductions+",\"forward_vectors\":"+forwards+",\"inverse_vectors\":"+inverses+",\"sparse_products\":"+products+",\"different_representatives\":"+differentRepresentatives+",\"passed\":true}");
    }
}
