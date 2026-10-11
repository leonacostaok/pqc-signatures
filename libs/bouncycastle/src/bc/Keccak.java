package bc;

/**
 * Minimal, self-contained Keccak-f[1600] / SHAKE128 / SHAKE256 sponge used by the "own-keccak" stage
 * alternatives, so that those stages do not go through BC's KeccakDigest/SHAKEDigest. The state is 25
 * little-endian 64-bit lanes; the permutation keeps all 25 lanes in locals (theta/rho/pi/chi/iota written out
 * per plane) so the JIT can keep them in registers. Absorb/squeeze operate on whole blocks with lane-level
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

    public final int rate;         // bytes
    private final byte domain;     // 0x1f for SHAKE
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

    public void reset() { java.util.Arrays.fill(s, 0L); pos = 0; squeezing = false; }

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

    /** Keccak-f[1600] with the 25 lanes in locals (lane index = x + 5*y). */
    public static void permute(long[] A) {
        long a00 = A[0], a01 = A[1], a02 = A[2], a03 = A[3], a04 = A[4];
        long a05 = A[5], a06 = A[6], a07 = A[7], a08 = A[8], a09 = A[9];
        long a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
        long a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
        long a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];
        for (int r = 0; r < 24; r++) {
            // theta
            long c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
            long c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
            long c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
            long c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
            long c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;
            long d0 = c4 ^ Long.rotateLeft(c1, 1);
            long d1 = c0 ^ Long.rotateLeft(c2, 1);
            long d2 = c1 ^ Long.rotateLeft(c3, 1);
            long d3 = c2 ^ Long.rotateLeft(c4, 1);
            long d4 = c3 ^ Long.rotateLeft(c0, 1);
            a00 ^= d0; a05 ^= d0; a10 ^= d0; a15 ^= d0; a20 ^= d0;
            a01 ^= d1; a06 ^= d1; a11 ^= d1; a16 ^= d1; a21 ^= d1;
            a02 ^= d2; a07 ^= d2; a12 ^= d2; a17 ^= d2; a22 ^= d2;
            a03 ^= d3; a08 ^= d3; a13 ^= d3; a18 ^= d3; a23 ^= d3;
            a04 ^= d4; a09 ^= d4; a14 ^= d4; a19 ^= d4; a24 ^= d4;
            // rho + pi: B[y][2x+3y] = rot(A[x][y]); written as b(x',y') with x' = y, y' = (2x+3y) mod 5
            long b00 = a00;
            long b10 = Long.rotateLeft(a01, 1);
            long b20 = Long.rotateLeft(a02, 62);
            long b05 = Long.rotateLeft(a03, 28);
            long b15 = Long.rotateLeft(a04, 27);
            long b16 = Long.rotateLeft(a05, 36);
            long b01 = Long.rotateLeft(a06, 44);
            long b11 = Long.rotateLeft(a07, 6);
            long b21 = Long.rotateLeft(a08, 55);
            long b06 = Long.rotateLeft(a09, 20);
            long b07 = Long.rotateLeft(a10, 3);
            long b17 = Long.rotateLeft(a11, 10);
            long b02 = Long.rotateLeft(a12, 43);
            long b12 = Long.rotateLeft(a13, 25);
            long b22 = Long.rotateLeft(a14, 39);
            long b23 = Long.rotateLeft(a15, 41);
            long b08 = Long.rotateLeft(a16, 45);
            long b18 = Long.rotateLeft(a17, 15);
            long b03 = Long.rotateLeft(a18, 21);
            long b13 = Long.rotateLeft(a19, 8);
            long b14 = Long.rotateLeft(a20, 18);
            long b24 = Long.rotateLeft(a21, 2);
            long b09 = Long.rotateLeft(a22, 61);
            long b19 = Long.rotateLeft(a23, 56);
            long b04 = Long.rotateLeft(a24, 14);
            // chi (per plane) + iota
            a00 = b00 ^ (~b01 & b02); a01 = b01 ^ (~b02 & b03); a02 = b02 ^ (~b03 & b04); a03 = b03 ^ (~b04 & b00); a04 = b04 ^ (~b00 & b01);
            a05 = b05 ^ (~b06 & b07); a06 = b06 ^ (~b07 & b08); a07 = b07 ^ (~b08 & b09); a08 = b08 ^ (~b09 & b05); a09 = b09 ^ (~b05 & b06);
            a10 = b10 ^ (~b11 & b12); a11 = b11 ^ (~b12 & b13); a12 = b12 ^ (~b13 & b14); a13 = b13 ^ (~b14 & b10); a14 = b14 ^ (~b10 & b11);
            a15 = b15 ^ (~b16 & b17); a16 = b16 ^ (~b17 & b18); a17 = b17 ^ (~b18 & b19); a18 = b18 ^ (~b19 & b15); a19 = b19 ^ (~b15 & b16);
            a20 = b20 ^ (~b21 & b22); a21 = b21 ^ (~b22 & b23); a22 = b22 ^ (~b23 & b24); a23 = b23 ^ (~b24 & b20); a24 = b24 ^ (~b20 & b21);
            a00 ^= RC[r];
        }
        A[0] = a00; A[1] = a01; A[2] = a02; A[3] = a03; A[4] = a04;
        A[5] = a05; A[6] = a06; A[7] = a07; A[8] = a08; A[9] = a09;
        A[10] = a10; A[11] = a11; A[12] = a12; A[13] = a13; A[14] = a14;
        A[15] = a15; A[16] = a16; A[17] = a17; A[18] = a18; A[19] = a19;
        A[20] = a20; A[21] = a21; A[22] = a22; A[23] = a23; A[24] = a24;
    }
}
