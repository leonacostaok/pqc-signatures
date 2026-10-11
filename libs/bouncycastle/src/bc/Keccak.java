package bc;

/**
 * Minimal, self-contained Keccak-f[1600] / SHAKE128 / SHAKE256 (and SHA3-style) sponge used by the
 * "own-keccak" stage alternatives, so that those stages do not go through BC's KeccakDigest/SHAKEDigest.
 * The state is 25 little-endian 64-bit lanes; absorb/squeeze operate on whole blocks with a lane-level
 * XOR, and the squeeze side exposes the raw block so samplers can read it without an extra copy.
 * Verified against BC's SHAKEDigest by the stage match checks on every run.
 */
public final class Keccak {
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    private static final int[] ROT = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
    // pi: lane (x,y) moves to (y, 2x+3y)
    private static final int[] PI = new int[25];
    static { for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5); }

    public final int rate;         // bytes
    private final byte domain;     // 0x1f for SHAKE, 0x06 for SHA3
    private final long[] s = new long[25];
    public final byte[] block;     // one rate-sized block: absorb buffer / last squeezed block
    private int pos;               // absorb: bytes in block; squeeze: bytes consumed from block
    private boolean squeezing;

    public Keccak(int securityBits) { this(securityBits, (byte) 0x1f); }
    public Keccak(int securityBits, byte domain) {
        this.rate = 200 - 2 * (securityBits / 8);
        this.domain = domain;
        this.block = new byte[rate];
    }

    public static Keccak shake128() { return new Keccak(128); }
    public static Keccak shake256() { return new Keccak(256); }

    public void reset() { java.util.Arrays.fill(s, 0L); java.util.Arrays.fill(block, (byte) 0); pos = 0; squeezing = false; }

    public Keccak update(byte b) {
        if (squeezing) throw new IllegalStateException("absorb after squeeze");
        block[pos++] = b;
        if (pos == rate) { absorbBlock(); pos = 0; }
        return this;
    }

    public Keccak update(byte[] in, int off, int len) {
        if (squeezing) throw new IllegalStateException("absorb after squeeze");
        while (len > 0) {
            int n = Math.min(rate - pos, len);
            System.arraycopy(in, off, block, pos, n);
            pos += n; off += n; len -= n;
            if (pos == rate) { absorbBlock(); pos = 0; }
        }
        return this;
    }
    public Keccak update(byte[] in) { return update(in, 0, in.length); }

    private void absorbBlock() {
        for (int i = 0; i < rate / 8; i++) s[i] ^= le64(block, 8 * i);
        permute(s);
    }

    /** Pads and switches to squeezing; the first output block is then available in {@link #block}. */
    public void finish() {
        if (squeezing) return;
        java.util.Arrays.fill(block, pos, rate, (byte) 0);
        block[pos] ^= domain;
        block[rate - 1] ^= (byte) 0x80;
        absorbBlock();
        squeezing = true;
        extract();
        pos = 0;
    }

    private void extract() { for (int i = 0; i < rate / 8; i++) putLe64(block, 8 * i, s[i]); }

    /** Replaces {@link #block} with the next rate bytes of output (call after the block has been consumed). */
    public void nextBlock() { permute(s); extract(); pos = 0; }

    public void squeeze(byte[] out, int off, int len) {
        if (!squeezing) finish();
        while (len > 0) {
            if (pos == rate) nextBlock();
            int n = Math.min(rate - pos, len);
            System.arraycopy(block, pos, out, off, n);
            pos += n; off += n; len -= n;
        }
    }
    public byte[] squeeze(int len) { byte[] o = new byte[len]; squeeze(o, 0, len); return o; }

    public static long le64(byte[] b, int o) {
        return (b[o] & 0xffL) | (b[o + 1] & 0xffL) << 8 | (b[o + 2] & 0xffL) << 16 | (b[o + 3] & 0xffL) << 24
            | (b[o + 4] & 0xffL) << 32 | (b[o + 5] & 0xffL) << 40 | (b[o + 6] & 0xffL) << 48 | (b[o + 7] & 0xffL) << 56;
    }
    public static void putLe64(byte[] b, int o, long v) {
        for (int i = 0; i < 8; i++) { b[o + i] = (byte) v; v >>>= 8; }
    }

    public static void permute(long[] a) {
        long[] b = new long[25];
        long[] c = new long[5];
        for (int round = 0; round < 24; round++) {
            // theta
            for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[x + y] ^= d;
            }
            // rho + pi
            for (int i = 0; i < 25; i++) b[PI[i]] = Long.rotateLeft(a[i], ROT[i]);
            // chi
            for (int y = 0; y < 25; y += 5)
                for (int x = 0; x < 5; x++)
                    a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
            // iota
            a[0] ^= RC[round];
        }
    }
}
