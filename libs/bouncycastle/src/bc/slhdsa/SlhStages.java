package bc.slhdsa;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * SLH-DSA verification split into the canonical stages (FIPS 205 Alg. 20 + external wrapper) on the
 * vendored BC classes (Fors, WotsPlus, HT logic, engines) plus alternatives: a different hash backend
 * (AltEngines on FastHash), parallel trees/chains/layers, and fused allocation-free re-implementations.
 */
public final class SlhStages {
    public final String name;
    public final boolean sha2;
    public final int N, D, A, K, H, HP, LEN, LEN1, LEN2, M, SIGLEN;
    private static final int W = 16;

    public SlhStages(String paramName) {
        // SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}
        String[] p = paramName.split("-");
        sha2 = p[2].equals("SHA2");
        String set = p[3];
        int[] t;
        switch (set) {                 // n, d, a, k, h  (BC's SLHDSAParameters table, w = 16)
            case "128f": t = new int[]{16, 22, 6, 33, 66}; break;
            case "128s": t = new int[]{16, 7, 12, 14, 63}; break;
            case "192f": t = new int[]{24, 22, 8, 33, 66}; break;
            case "192s": t = new int[]{24, 7, 14, 17, 63}; break;
            case "256f": t = new int[]{32, 17, 9, 35, 68}; break;
            case "256s": t = new int[]{32, 8, 14, 22, 64}; break;
            default: throw new IllegalArgumentException(paramName);
        }
        name = paramName; N = t[0]; D = t[1]; A = t[2]; K = t[3]; H = t[4]; HP = H / D;
        LEN1 = 2 * N; LEN2 = 3; LEN = LEN1 + LEN2;
        M = (A * K + 7) / 8 + (H - HP + 7) / 8 + (HP + 7) / 8;
        SIGLEN = (1 + K * (1 + A) + H + D * LEN) * N;
    }

    public SLHDSAEngine bcEngine(byte[] pkSeed) {
        SLHDSAEngine e = sha2 ? new SLHDSAEngine.Sha2Engine(N, W, D, A, K, H) : new SLHDSAEngine.Shake256Engine(N, W, D, A, K, H);
        e.init(pkSeed);
        return e;
    }
    public SLHDSAEngine altEngine(byte[] pkSeed) {
        SLHDSAEngine e = AltEngines.create(sha2, N, W, D, A, K, H);
        e.init(pkSeed);
        return e;
    }
    public FastHash fast(byte[] pkSeed) { return FastHash.create(sha2, N, pkSeed); }

    public static byte[] prefix(byte[] ctx) {
        byte[] p = new byte[2 + ctx.length];
        p[1] = (byte) ctx.length;
        System.arraycopy(ctx, 0, p, 2, ctx.length);
        return p;
    }

    // ================================================================= parse

    public static final class Parsed {
        byte[] R; SIG_FORS[] fors; SIG_XMSS[] ht;
    }
    public Parsed parse(byte[] sig) {
        if (sig.length != SIGLEN) return null;
        SIG s = new SIG(N, K, A, D, HP, LEN, sig);
        Parsed p = new Parsed();
        p.R = s.getR(); p.fors = s.getSIG_FORS(); p.ht = s.getSIG_HT();
        return p;
    }

    // ================================================================= hmsg

    public static final class HMsg {
        public byte[] full, md;
        public long[] tree; public int[] leaf;  // per layer
    }
    private HMsg split(IndexedDigest d) {
        HMsg h = new HMsg();
        h.full = d.full; h.md = d.digest;
        h.tree = new long[D]; h.leaf = new int[D];
        long t = d.idx_tree; int l = d.idx_leaf;
        for (int j = 0; j < D; j++) {
            h.tree[j] = t; h.leaf[j] = l;
            l = (int) (t & ((1L << HP) - 1)); t >>>= HP;
        }
        return h;
    }
    /** v0 / v1: engine.H_msg (BC engine or alt engine) */
    public HMsg hmsg(SLHDSAEngine e, Parsed p, byte[] pkSeed, byte[] pkRoot, byte[] ctx, byte[] msg) {
        return split(e.H_msg(p.R, pkSeed, pkRoot, prefix(ctx), msg));
    }

    // ================================================================= fors

    private ADRS forsAdrs(HMsg h) {
        ADRS a = new ADRS();
        a.setTypeAndClear(ADRS.FORS_TREE); a.setLayerAddress(0); a.setTreeAddress(h.tree[0]); a.setKeyPairAddress(h.leaf[0]);
        return a;
    }
    /** v0 / v1: BC's Fors.pkFromSig on the given engine */
    public byte[] fors(SLHDSAEngine e, Parsed p, HMsg h, byte[] pkSeed) {
        return new Fors(e).pkFromSig(p.fors, h.md, pkSeed, forsAdrs(h));
    }

    /** v2: the k FORS trees on a thread pool (one BC engine per task), T_l on the caller's engine */
    public byte[] forsParallel(SLHDSAEngine e0, Parsed p, HMsg h, byte[] pkSeed, ExecutorService pool, int threads) throws Exception {
        int[] idxs = Fors.base2B(h.md, A, K);
        byte[][] root = new byte[K][];
        ADRS base = forsAdrs(h);
        List<Callable<Void>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int lane = t;
            tasks.add(() -> {
                SLHDSAEngine e = bcEngine(pkSeed);
                ADRS adrs = new ADRS(base);
                for (int i = lane; i < K; i += threads) {
                    int idx = idxs[i];
                    adrs.setTreeHeight(0); adrs.setTreeIndex((i << A) + idx);
                    byte[] node = e.F(pkSeed, adrs, p.fors[i].getSK());
                    byte[][] auth = p.fors[i].getAuthPath();
                    for (int j = 0; j < A; j++) {
                        adrs.setTreeHeight(j + 1);
                        if ((idx & (1 << j)) == 0) { adrs.setTreeIndex(adrs.getTreeIndex() / 2); node = e.H(pkSeed, adrs, node, auth[j]); }
                        else { adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2); node = e.H(pkSeed, adrs, auth[j], node); }
                    }
                    root[i] = node;
                }
                return null;
            });
        }
        for (Future<Void> f : pool.invokeAll(tasks)) f.get();
        ADRS pkAdrs = new ADRS(base);
        pkAdrs.setTypeAndClear(ADRS.FORS_PK); pkAdrs.setKeyPairAddress(h.leaf[0]);
        return e0.T_l(pkSeed, pkAdrs, Arrays.concatenate(root));
    }

    /** v3: fused, allocation-free FORS pkFromSig on FastHash (flat ADRS, int base-2^a, roots in one buffer) */
    public byte[] forsFast(FastHash fh, Parsed p, HMsg h) {
        byte[] adrs = new byte[32];
        setTree(adrs, h.tree[0]); setType(adrs, ADRS.FORS_TREE); setInt(adrs, 20, h.leaf[0]);
        byte[] roots = new byte[K * N];
        byte[] md = h.md;
        int acc = 0, bits = 0, pos = 0;
        for (int i = 0; i < K; i++) {
            while (bits < A) { acc = (acc << 8) | (md[pos++] & 0xff); bits += 8; }
            bits -= A;
            int idx = (acc >>> bits) & ((1 << A) - 1);
            acc &= (1 << bits) - 1;
            int treeIndex = (i << A) + idx;
            setInt(adrs, 24, 0); setInt(adrs, 28, treeIndex);
            fh.F(adrs, p.fors[i].sk, 0, roots, i * N);
            byte[][] auth = p.fors[i].authPath;
            for (int j = 0; j < A; j++) {
                setInt(adrs, 24, j + 1);
                if ((idx & (1 << j)) == 0) { treeIndex /= 2; setInt(adrs, 28, treeIndex); fh.H(adrs, roots, i * N, auth[j], 0, roots, i * N); }
                else { treeIndex = (treeIndex - 1) / 2; setInt(adrs, 28, treeIndex); fh.H(adrs, auth[j], 0, roots, i * N, roots, i * N); }
            }
        }
        setType(adrs, ADRS.FORS_PK); setInt(adrs, 20, h.leaf[0]);
        byte[] pk = new byte[N];
        fh.T(adrs, roots, 0, roots.length, pk, 0);
        return pk;
    }

    // ================================================================= ht_wots

    private ADRS wotsAdrs(HMsg h, int layer) {
        ADRS a = new ADRS();
        a.setLayerAddress(layer); a.setTreeAddress(h.tree[layer]);
        a.setTypeAndClear(ADRS.WOTS_HASH); a.setKeyPairAddress(h.leaf[layer]);
        return a;
    }
    /** v0 / v1: BC's WotsPlus.pkFromSig for one layer */
    public byte[] wots(SLHDSAEngine e, Parsed p, HMsg h, int layer, byte[] msg, byte[] pkSeed) {
        return new WotsPlus(e).pkFromSig(p.ht[layer].sig, msg, pkSeed, wotsAdrs(h, layer));
    }

    private int[] baseW(byte[] msg) {
        int[] m = new int[LEN];
        for (int i = 0; i < LEN1; i++) m[i] = (msg[i >> 1] >> (4 * (1 - (i & 1)))) & 15;
        int csum = 0;
        for (int i = 0; i < LEN1; i++) csum += W - 1 - m[i];
        csum <<= 8 - ((LEN2 * 4) % 8);
        byte[] cb = Pack.intToBigEndian(csum);
        int len2Bytes = (LEN2 * 4 + 7) / 8;
        for (int i = 0; i < LEN2; i++) m[LEN1 + i] = (cb[4 - len2Bytes + (i >> 1)] >> (4 * (1 - (i & 1)))) & 15;
        return m;
    }

    /** v2: the WOTS+ chains of one layer spread over a thread pool (BC engine per task), T_l on e0 */
    public byte[] wotsParallelChains(SLHDSAEngine e0, SLHDSAEngine[] lanes, Parsed p, HMsg h, int layer, byte[] msg, byte[] pkSeed, ExecutorService pool) throws Exception {
        int[] m = baseW(msg);
        byte[] sig = p.ht[layer].sig;
        byte[][] tmp = new byte[LEN][];
        ADRS base = wotsAdrs(h, layer);
        int threads = lanes.length;
        List<Callable<Void>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int lane = t;
            tasks.add(() -> {
                SLHDSAEngine e = lanes[lane];
                WotsPlus w = new WotsPlus(e);
                ADRS adrs = new ADRS(base);
                byte[] sigI = new byte[N];
                for (int i = lane; i < LEN; i += threads) {
                    adrs.setChainAddress(i);
                    System.arraycopy(sig, i * N, sigI, 0, N);
                    tmp[i] = w.chain(sigI, m[i], W - 1 - m[i], pkSeed, adrs);
                }
                return null;
            });
        }
        for (Future<Void> f : pool.invokeAll(tasks)) f.get();
        ADRS pkAdrs = new ADRS(base);
        pkAdrs.setTypeAndClear(ADRS.WOTS_PK); pkAdrs.setKeyPairAddress(h.leaf[layer]);
        return e0.T_l(pkSeed, pkAdrs, Arrays.concatenate(tmp));
    }

    /** v4: fused WOTS+ pkFromSig on FastHash: chains hashed in place inside one LEN*n buffer */
    public byte[] wotsFast(FastHash fh, Parsed p, HMsg h, int layer, byte[] msg) {
        int[] m = baseW(msg);
        byte[] adrs = new byte[32];
        setInt(adrs, 0, layer); setTree(adrs, h.tree[layer]); setType(adrs, ADRS.WOTS_HASH); setInt(adrs, 20, h.leaf[layer]);
        byte[] tmp = p.ht[layer].sig.clone();
        for (int i = 0; i < LEN; i++) {
            setInt(adrs, 24, i);
            for (int j = m[i]; j < W - 1; j++) { setInt(adrs, 28, j); fh.F(adrs, tmp, i * N, tmp, i * N); }
        }
        setType(adrs, ADRS.WOTS_PK); setInt(adrs, 20, h.leaf[layer]);
        byte[] pk = new byte[N];
        fh.T(adrs, tmp, 0, tmp.length, pk, 0);
        return pk;
    }

    // ================================================================= ht_auth

    /** v0 / v1: the auth-path loop of BC's HT.xmss_pkFromSig for one layer, from the layer's WOTS pk */
    public byte[] auth(SLHDSAEngine e, Parsed p, HMsg h, int layer, byte[] wotsPk, byte[] pkSeed) {
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(layer); adrs.setTreeAddress(h.tree[layer]);
        adrs.setTypeAndClear(ADRS.TREE);
        int idx = h.leaf[layer];
        adrs.setTreeIndex(idx);
        byte[][] auth = p.ht[layer].auth;
        byte[] node = wotsPk;
        for (int k = 0; k < HP; k++) {
            adrs.setTreeHeight(k + 1);
            if ((idx & (1 << k)) == 0) { adrs.setTreeIndex(adrs.getTreeIndex() / 2); node = e.H(pkSeed, adrs, node, auth[k]); }
            else { adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2); node = e.H(pkSeed, adrs, auth[k], node); }
        }
        return node;
    }

    /** v3: fused auth-path hashing on FastHash into one node buffer */
    public byte[] authFast(FastHash fh, Parsed p, HMsg h, int layer, byte[] wotsPk) {
        byte[] adrs = new byte[32];
        setInt(adrs, 0, layer); setTree(adrs, h.tree[layer]); setType(adrs, ADRS.TREE);
        int idx = h.leaf[layer], ti = idx;
        byte[][] auth = p.ht[layer].auth;
        byte[] node = wotsPk.clone();
        for (int k = 0; k < HP; k++) {
            setInt(adrs, 24, k + 1);
            if ((idx & (1 << k)) == 0) { ti /= 2; setInt(adrs, 28, ti); fh.H(adrs, node, 0, auth[k], 0, node, 0); }
            else { ti = (ti - 1) / 2; setInt(adrs, 28, ti); fh.H(adrs, auth[k], 0, node, 0, node, 0); }
        }
        return node;
    }

    // ================================================================= flat ADRS helpers
    static void setInt(byte[] a, int off, int v) { Pack.intToBigEndian(v, a, off); }
    static void setTree(byte[] a, long t) { Pack.longToBigEndian(t, a, 8); }
    static void setType(byte[] a, int type) { Pack.intToBigEndian(type, a, 16); java.util.Arrays.fill(a, 20, 32, (byte) 0); }
}
