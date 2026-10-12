package org.bouncycastle.crypto.signers.mldsa;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Random;

/** Direct production table/helper checks; independent signed-integer oracle. */
public final class DirectCompanionGate {
    private static final BigInteger R = BigInteger.ONE.shiftLeft(32);
    private static final BigInteger HALF = BigInteger.ONE.shiftLeft(31);
    private static final BigInteger Q = BigInteger.valueOf(8380417);
    private static final BigInteger QINV = BigInteger.valueOf(58728449);
    private static int lowSigned(BigInteger x) {
        BigInteger t = x.mod(R);
        return (t.compareTo(HALF) >= 0 ? t.subtract(R) : t).intValueExact();
    }
    private static int oracle(int x, int z) {
        BigInteger a = BigInteger.valueOf(x).multiply(BigInteger.valueOf(z));
        BigInteger t = BigInteger.valueOf(lowSigned(a.multiply(QINV)));
        BigInteger[] qr = a.subtract(t.multiply(Q)).divideAndRemainder(R);
        if (qr[1].signum() != 0) throw new AssertionError("not divisible");
        return qr[0].intValueExact();
    }
    public static void main(String[] args) throws Exception {
        if (!new File(args[0]).getCanonicalFile().equals(new File(Ntt.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getCanonicalFile())) throw new AssertionError("wrong production origin");
        Field zf = Ntt.class.getDeclaredField("nttZetas"); zf.setAccessible(true);
        Field cf = Ntt.class.getDeclaredField("nttZetasQInv"); cf.setAccessible(true);
        int[] z = (int[])zf.get(null), c = (int[])cf.get(null);
        if (z.length != 256 || c.length != 256) throw new AssertionError("table size");
        Method helper = Ntt.class.getDeclaredMethod("multiplyTwiddle", int.class, int.class, int.class); helper.setAccessible(true);
        int[] inputs = new int[152];
        int[] edges = {Integer.MIN_VALUE,Integer.MIN_VALUE+1,Integer.MAX_VALUE,Integer.MAX_VALUE-1,0,1,-1,8380416,-8380416,8380417,-8380417,75423752,-75423752,2145386496,-2145386496,1072693248,-1072693248,5514722,-5514722,4259832,-4259832,245760,-245760,660};
        System.arraycopy(edges,0,inputs,0,edges.length);
        Random random = new Random(170412711L);
        for (int i=edges.length;i<inputs.length;i++) inputs[i]=random.nextInt();
        int checks=0;
        for (int i=0;i<256;i++) {
            if (c[i] != lowSigned(BigInteger.valueOf(z[i]).multiply(QINV))) throw new AssertionError("companion table " + i);
            for (int sign : new int[]{1,-1}) for (int x : inputs) {
                int zz=sign*z[i], cc=sign*c[i];
                if (((Integer)helper.invoke(null,x,zz,cc)).intValue() != oracle(x,zz)) throw new AssertionError("helper mismatch " + i + " " + x);
                checks++;
            }
        }
        int[] scale={41978,3975713}, companions={-8395782,151046689};
        for (int i=0;i<2;i++) {
            if (companions[i] != lowSigned(BigInteger.valueOf(scale[i]).multiply(QINV))) throw new AssertionError("scale companion");
            for (int x:inputs) {
                if (((Integer)helper.invoke(null,x,scale[i],companions[i])).intValue() != oracle(x,scale[i])) throw new AssertionError("scale helper mismatch");
                checks++;
            }
        }
        System.out.println("{\"passed\":true,\"production_origin_checked\":true,\"stored_companions\":256,\"final_scale_constants\":2,\"helper_checks\":"+checks+",\"signed_inputs\":"+inputs.length+"}");
    }
}
