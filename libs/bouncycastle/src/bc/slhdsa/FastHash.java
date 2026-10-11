package bc.slhdsa;

import java.security.MessageDigest;

import bc.Keccak;

/**
 * Allocation-free SLH-DSA tweakable hash primitives (F, H, T_l) writing into caller buffers, with a flat
 * 32-byte ADRS. Two backends that are NOT Bouncy Castle code: the JDK's intrinsified SHA-256/SHA-512
 * (with the PK.seed block kept as a cloned midstate) for the SHA2 parameter sets, and the bc.Keccak
 * sponge for the SHAKE parameter sets. Verify-only (no PRF / PRF_msg).
 */
public abstract class FastHash {
    public final int n;
    FastHash(int n) { this.n = n; }

    /** out[outOff..+n) = F(PK.seed, ADRS, in[inOff..+n)) */
    public abstract void F(byte[] adrs, byte[] in, int inOff, byte[] out, int outOff);
    /** out = H(PK.seed, ADRS, l[lOff..+n) || r[rOff..+n)) */
    public abstract void H(byte[] adrs, byte[] l, int lOff, byte[] r, int rOff, byte[] out, int outOff);
    /** out = T_l(PK.seed, ADRS, in[inOff..+len)) */
    public abstract void T(byte[] adrs, byte[] in, int inOff, int len, byte[] out, int outOff);
    /** full H_msg output (m bytes) */
    public abstract byte[] Hmsg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] prefix, byte[] msg, int m);

    public static FastHash create(boolean sha2, int n, byte[] pkSeed) {
        return sha2 ? new Sha2(n, pkSeed) : new Shake(n, pkSeed);
    }

    // ------------------------------------------------------------------ SHA2 (JDK MessageDigest)
    static final class Sha2 extends FastHash {
        private final MessageDigest sha256Seeded, bigSeeded; // midstates: SHA-256(pkSeed||0^(64-n)), SHA-x(pkSeed||0^(bl-n))
        private final MessageDigest big;                      // SHA-256 (n=16) or SHA-512 (n=24,32), for H/T/H_msg
        private final byte[] tmp = new byte[64];
        private final boolean big512;

        Sha2(int n, byte[] pkSeed) {
            super(n);
            try {
                big512 = n > 16;
                MessageDigest s = MessageDigest.getInstance("SHA-256");
                s.update(pkSeed); s.update(new byte[64 - n]);
                sha256Seeded = s;
                big = MessageDigest.getInstance(big512 ? "SHA-512" : "SHA-256");
                MessageDigest b = MessageDigest.getInstance(big512 ? "SHA-512" : "SHA-256");
                b.update(pkSeed); b.update(new byte[(big512 ? 128 : 64) - n]);
                bigSeeded = b;
            } catch (Exception e) { throw new RuntimeException(e); }
        }

        private static void adrsc(MessageDigest d, byte[] a) {
            d.update(a, 3, 1); d.update(a, 8, 8); d.update(a, 19, 1); d.update(a, 20, 12);
        }

        public void F(byte[] adrs, byte[] in, int inOff, byte[] out, int outOff) {
            try {
                MessageDigest d = (MessageDigest) sha256Seeded.clone();
                adrsc(d, adrs); d.update(in, inOff, n);
                d.digest(tmp, 0, 32);
                System.arraycopy(tmp, 0, out, outOff, n);
            } catch (Exception e) { throw new RuntimeException(e); }
        }

        public void H(byte[] adrs, byte[] l, int lOff, byte[] r, int rOff, byte[] out, int outOff) {
            try {
                MessageDigest d = (MessageDigest) bigSeeded.clone();
                adrsc(d, adrs); d.update(l, lOff, n); d.update(r, rOff, n);
                d.digest(tmp, 0, big512 ? 64 : 32);
                System.arraycopy(tmp, 0, out, outOff, n);
            } catch (Exception e) { throw new RuntimeException(e); }
        }

        public void T(byte[] adrs, byte[] in, int inOff, int len, byte[] out, int outOff) {
            try {
                MessageDigest d = (MessageDigest) bigSeeded.clone();
                adrsc(d, adrs); d.update(in, inOff, len);
                d.digest(tmp, 0, big512 ? 64 : 32);
                System.arraycopy(tmp, 0, out, outOff, n);
            } catch (Exception e) { throw new RuntimeException(e); }
        }

        public byte[] Hmsg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] prefix, byte[] msg, int m) {
            big.reset();
            big.update(R); big.update(pkSeed); big.update(pkRoot);
            if (prefix != null) big.update(prefix);
            big.update(msg);
            byte[] dig = big.digest();
            // MGF1-SHA-x(R || PK.seed || dig, m)
            byte[] out = new byte[m];
            int dl = big512 ? 64 : 32;
            byte[] ctr = new byte[4];
            for (int c = 0, off = 0; off < m; c++) {
                big.reset(); big.update(R); big.update(pkSeed); big.update(dig);
                ctr[0] = (byte) (c >>> 24); ctr[1] = (byte) (c >>> 16); ctr[2] = (byte) (c >>> 8); ctr[3] = (byte) c;
                big.update(ctr);
                byte[] blk = big.digest();
                int k = Math.min(dl, m - off);
                System.arraycopy(blk, 0, out, off, k);
                off += k;
            }
            return out;
        }
    }

    // ------------------------------------------------------------------ SHAKE256 (bc.Keccak)
    static final class Shake extends FastHash {
        private final Keccak k = Keccak.shake256();
        private final byte[] pkSeed;
        Shake(int n, byte[] pkSeed) { super(n); this.pkSeed = pkSeed; }

        public void F(byte[] adrs, byte[] in, int inOff, byte[] out, int outOff) {
            k.reset(); k.update(pkSeed).update(adrs).update(in, inOff, n); k.squeeze(out, outOff, n);
        }
        public void H(byte[] adrs, byte[] l, int lOff, byte[] r, int rOff, byte[] out, int outOff) {
            k.reset(); k.update(pkSeed).update(adrs).update(l, lOff, n).update(r, rOff, n); k.squeeze(out, outOff, n);
        }
        public void T(byte[] adrs, byte[] in, int inOff, int len, byte[] out, int outOff) {
            k.reset(); k.update(pkSeed).update(adrs).update(in, inOff, len); k.squeeze(out, outOff, n);
        }
        public byte[] Hmsg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] prefix, byte[] msg, int m) {
            k.reset(); k.update(R).update(pkSeed).update(pkRoot);
            if (prefix != null) k.update(prefix);
            k.update(msg);
            return k.squeeze(m);
        }
    }
}
