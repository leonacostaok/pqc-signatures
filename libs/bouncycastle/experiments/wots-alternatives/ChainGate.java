package org.bouncycastle.crypto.signers.slhdsa;



import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.util.Arrays;

public class ChainGate
{
    static int cases;
    static void assertTrue(boolean ok) { if (!ok) throw new AssertionError("chain oracle"); }
    static void assertNull(Object value) { assertTrue(value == null); }
    public static void main(String[] args) {
        ChainGate test = new ChainGate(); test.testChains(); test.quirks();
        System.out.println("{\"checked\":true,\"cases\":" + cases + "}");
    }
    public void testChains()
    {
        SLHDSAParameters[] parameters = {
            SLHDSAParameters.sha2_128f, SLHDSAParameters.sha2_192f, SLHDSAParameters.sha2_256f,
            SLHDSAParameters.shake_128f, SLHDSAParameters.shake_192f, SLHDSAParameters.shake_256f
        };
        for (int p = 0; p < parameters.length; ++p)
        {
            int n = parameters[p].getN();
            for (int trial = 0; trial < 3; ++trial)
            {
                byte[] seed = new byte[n];
                byte[] input = new byte[n];
                for (int j = 0; j < n; ++j)
                {
                    seed[j] = (byte)(trial * 97 + j * 23);
                    input[j] = (byte)(trial == 0 ? 0 : trial == 1 ? 255 : j * 71);
                }
                byte[] savedSeed = Arrays.clone(seed);
                byte[] savedInput = Arrays.clone(input);
                SLHDSAEngine engine = parameters[p].getEngine();
                engine.init(seed);
                WotsPlus wots = new WotsPlus(engine);
                for (int start = 0; start < 16; ++start)
                {
                    for (int steps = 0; steps <= 15 - start; ++steps)
                    {
                        ++cases;
                        ADRS address = address();
                        ADRS expectedAddress = new ADRS(address);
                        byte[] expected = Arrays.clone(input);
                        for (int j = 0; j < steps; ++j)
                        {
                            expectedAddress.setHashAddress(start + j);
                            expected = hash(p < 3, seed, expectedAddress, expected);
                        }
                        byte[] actual = wots.chain(input, start, steps, seed, address);
                        assertTrue(Arrays.areEqual(expected, actual));
                        assertTrue(Arrays.areEqual(expectedAddress.value, address.value));
                        assertTrue(Arrays.areEqual(savedInput, input));
                        assertTrue(Arrays.areEqual(savedSeed, seed));
                        byte[] retained = Arrays.clone(actual);
                        wots.chain(input, 0, 15, seed, address());
                        assertTrue(Arrays.areEqual(retained, actual));
                        actual[0] ^= 1;
                        assertTrue(Arrays.areEqual(savedInput, input));
                    }
                }
                ADRS invalidAddress = address();
                byte[] savedAddress = Arrays.clone(invalidAddress.value);
                assertNull(wots.chain(input, 15, 1, seed, invalidAddress));
                assertTrue(Arrays.areEqual(savedAddress, invalidAddress.value));
            }
        }
    }

    void quirks() {
        SLHDSAParameters[] parameters = {SLHDSAParameters.sha2_128f, SLHDSAParameters.sha2_192f, SLHDSAParameters.sha2_256f, SLHDSAParameters.shake_128f, SLHDSAParameters.shake_192f, SLHDSAParameters.shake_256f};
        int[][] ranges = {{0,-1},{0,Integer.MIN_VALUE},{100,-1},{Integer.MAX_VALUE,0},{Integer.MIN_VALUE,0},{-1,1},{Integer.MAX_VALUE,1},{Integer.MAX_VALUE,2},{15,1},{16,0},{-1,17}};
        for(int p=0;p<parameters.length;p++) {
            int n=parameters[p].getN(); byte[] seed=new byte[n], input=new byte[n];
            for(int j=0;j<n;j++) {seed[j]=(byte)(j*23+5);input[j]=(byte)(j*31+7);}
            SLHDSAEngine engine=parameters[p].getEngine();engine.init(seed);WotsPlus wots=new WotsPlus(engine);
            for(int[] pair:ranges) {
                ++cases;int start=pair[0],steps=pair[1];ADRS a=address(),expectedAddress=new ADRS(a);byte[] saved=input.clone();
                byte[] expected;
                if(steps==0) expected=input.clone();
                else if(start+steps>15) expected=null;
                else {expected=input;for(int j=0;j<steps;j++){expectedAddress.setHashAddress(start+j);expected=hash(p<3,seed,expectedAddress,expected);}}
                byte[] actual=wots.chain(input,start,steps,seed,a);
                assertTrue(java.util.Arrays.equals(expected,actual));assertTrue(java.util.Arrays.equals(a.value,expectedAddress.value));assertTrue(java.util.Arrays.equals(input,saved));
                if(steps==0)assertTrue(actual!=input);
                if(steps<0 && start+steps<=15)assertTrue(actual==input);
                if(steps>0 && start+steps<=15)assertTrue(actual!=input);
            }
        }
    }
    private static ADRS address()
    {
        ADRS address = new ADRS();
        address.setLayerAddress(3);
        address.setTreeAddress(0x0123456789abcdefL);
        address.setTypeAndClear(ADRS.WOTS_HASH);
        address.setKeyPairAddress(37);
        address.setChainAddress(5);
        address.setHashAddress(11);
        return address;
    }

    private static byte[] hash(boolean sha2, byte[] seed, ADRS address, byte[] input)
    {
        if (sha2)
        {
            SHA256Digest digest = new SHA256Digest();
            digest.update(seed, 0, seed.length);
            byte[] padding = new byte[64 - seed.length];
            digest.update(padding, 0, padding.length);
            byte[] compressed = new byte[22];
            compressed[0] = address.value[3];
            System.arraycopy(address.value, 8, compressed, 1, 8);
            compressed[9] = address.value[19];
            System.arraycopy(address.value, 20, compressed, 10, 12);
            digest.update(compressed, 0, compressed.length);
            digest.update(input, 0, input.length);
            byte[] output = new byte[32];
            digest.doFinal(output, 0);
            return Arrays.copyOf(output, seed.length);
        }
        SHAKEDigest digest = new SHAKEDigest(256);
        digest.update(seed, 0, seed.length);
        digest.update(address.value, 0, address.value.length);
        digest.update(input, 0, input.length);
        byte[] output = new byte[seed.length];
        digest.doFinal(output, 0, output.length);
        return output;
    }
}
