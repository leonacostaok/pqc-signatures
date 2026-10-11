package bc.slhdsa;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * SLHDSAEngine implementations with a non-BC hash backend (FastHash: JDK SHA-2 or bc.Keccak), so that
 * BC's own Fors / WotsPlus / HT stage code can be run unchanged on a different digest implementation.
 * Verify-only: PRF and PRF_msg are not implemented.
 */
public final class AltEngines {
    private AltEngines() {}

    public static SLHDSAEngine create(boolean sha2, int n, int w, int d, int a, int k, int h) {
        return new Engine(sha2, n, w, d, a, k, h);
    }

    static final class Engine extends SLHDSAEngine {
        private final boolean sha2;
        private FastHash fh;
        private final byte[] out;

        Engine(boolean sha2, int n, int w, int d, int a, int k, int h) {
            super(n, w, d, a, k, h);
            this.sha2 = sha2;
            this.out = new byte[n];
        }

        public void init(byte[] pkSeed) { fh = FastHash.create(sha2, N, pkSeed); }

        public byte[] F(byte[] pkSeed, ADRS adrs, byte[] m1) {
            byte[] o = new byte[N]; fh.F(adrs.value, m1, 0, o, 0); return o;
        }
        public byte[] H(byte[] pkSeed, ADRS adrs, byte[] m1, byte[] m2) {
            byte[] o = new byte[N]; fh.H(adrs.value, m1, 0, m2, 0, o, 0); return o;
        }
        public byte[] T_l(byte[] pkSeed, ADRS adrs, byte[] m) {
            byte[] o = new byte[N]; fh.T(adrs.value, m, 0, m.length, o, 0); return o;
        }
        public IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] msgPrefix, byte[] msg) {
            int forsMsgBytes = ((A * K) + 7) / 8;
            int leafBits = H / D, treeBits = H - leafBits;
            int leafBytes = (leafBits + 7) / 8, treeBytes = (treeBits + 7) / 8;
            int m = forsMsgBytes + leafBytes + treeBytes;
            byte[] full = fh.Hmsg(R, pkSeed, pkRoot, msgPrefix, msg, m);
            byte[] treeIndexBuf = new byte[8];
            System.arraycopy(full, forsMsgBytes, treeIndexBuf, 8 - treeBytes, treeBytes);
            long treeIndex = Pack.bigEndianToLong(treeIndexBuf, 0) & ((~0L) >>> (64 - treeBits));
            byte[] leafIndexBuf = new byte[4];
            System.arraycopy(full, forsMsgBytes + treeBytes, leafIndexBuf, 4 - leafBytes, leafBytes);
            int leafIndex = Pack.bigEndianToInt(leafIndexBuf, 0) & ((~0) >>> (32 - leafBits));
            return new IndexedDigest(treeIndex, leafIndex, Arrays.copyOfRange(full, 0, forsMsgBytes), full);
        }
        byte[] PRF(byte[] pkSeed, byte[] skSeed, ADRS adrs) { throw new UnsupportedOperationException("verify-only engine"); }
        byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] msgPrefix, byte[] msg) { throw new UnsupportedOperationException("verify-only engine"); }
    }
}
