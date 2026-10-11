import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/** Parameter-set table and byte<->key-object helpers for Bouncy Castle. */
final class Alg {
    enum Family { MLDSA, SLHDSA, FALCON }

    static final BouncyCastleProvider BC = new BouncyCastleProvider();
    static { if (Security.getProvider("BC") == null) Security.addProvider(BC); }

    final String name;
    final Family family;
    final MLDSAParameters mldsa;
    final SLHDSAParameters slhdsa;
    final FalconParameters falcon;
    final AlgorithmParameterSpec jcaSpec;
    final String jcaAlg; // KeyPairGenerator/Signature/KeyFactory algorithm name

    private Alg(String name, MLDSAParameters p) {
        this.name = name; family = Family.MLDSA; mldsa = p; slhdsa = null; falcon = null;
        jcaSpec = MLDSAParameterSpec.fromName(name); jcaAlg = "ML-DSA";
    }
    private Alg(String name, SLHDSAParameters p) {
        this.name = name; family = Family.SLHDSA; mldsa = null; slhdsa = p; falcon = null;
        jcaSpec = SLHDSAParameterSpec.fromName(name); jcaAlg = "SLH-DSA";
    }
    private Alg(String name, FalconParameters p) {
        this.name = name; family = Family.FALCON; mldsa = null; slhdsa = null; falcon = p;
        jcaSpec = null; jcaAlg = "FALCON";
    }

    static final Map<String, Alg> ALL = new LinkedHashMap<>();
    static {
        add(new Alg("ML-DSA-44", MLDSAParameters.ml_dsa_44));
        add(new Alg("ML-DSA-65", MLDSAParameters.ml_dsa_65));
        add(new Alg("ML-DSA-87", MLDSAParameters.ml_dsa_87));
        add(new Alg("SLH-DSA-SHA2-128s", SLHDSAParameters.sha2_128s));
        add(new Alg("SLH-DSA-SHA2-128f", SLHDSAParameters.sha2_128f));
        add(new Alg("SLH-DSA-SHA2-192s", SLHDSAParameters.sha2_192s));
        add(new Alg("SLH-DSA-SHA2-192f", SLHDSAParameters.sha2_192f));
        add(new Alg("SLH-DSA-SHA2-256s", SLHDSAParameters.sha2_256s));
        add(new Alg("SLH-DSA-SHA2-256f", SLHDSAParameters.sha2_256f));
        add(new Alg("SLH-DSA-SHAKE-128s", SLHDSAParameters.shake_128s));
        add(new Alg("SLH-DSA-SHAKE-128f", SLHDSAParameters.shake_128f));
        add(new Alg("SLH-DSA-SHAKE-192s", SLHDSAParameters.shake_192s));
        add(new Alg("SLH-DSA-SHAKE-192f", SLHDSAParameters.shake_192f));
        add(new Alg("SLH-DSA-SHAKE-256s", SLHDSAParameters.shake_256s));
        add(new Alg("SLH-DSA-SHAKE-256f", SLHDSAParameters.shake_256f));
        add(new Alg("Falcon-512", FalconParameters.falcon_512));
        add(new Alg("Falcon-1024", FalconParameters.falcon_1024));
    }
    private static void add(Alg a) { ALL.put(a.name, a); }

    static Alg get(String name) {
        Alg a = ALL.get(name);
        if (a == null) throw new IllegalArgumentException("unknown param " + name);
        return a;
    }

    boolean byteMatch() { return family != Family.FALCON; }

    // ---------------------------------------------------------------- seeded "SecureRandom"s

    /**
     * SecureRandom that hands out exactly the bytes of a fixed seed, in order. BC's
     * MLDSAKeyPairGenerator pulls one 32-byte xi; SLHDSAKeyPairGenerator pulls SK.seed, SK.prf, PK.seed
     * (n bytes each, in that order) - which is exactly the layout of vectors.json's SLH-DSA seed.
     * Running out of seed bytes throws, so a change of BC's consumption pattern cannot go unnoticed.
     */
    static final class SeedRandom extends SecureRandom {
        private final byte[] seed;
        private int off;
        SeedRandom(byte[] seed) { this.seed = seed; }
        SeedRandom reset() { off = 0; return this; }
        @Override public void nextBytes(byte[] out) {
            if (off + out.length > seed.length) throw new IllegalStateException("seed exhausted: BC requested more random bytes than the seed holds");
            System.arraycopy(seed, off, out, 0, out.length);
            off += out.length;
        }
        @Override public byte[] generateSeed(int n) { byte[] b = new byte[n]; nextBytes(b); return b; }
    }

    /** Deterministic SHAKE256 stream for Falcon (no byte-match expected, only reproducibility). */
    static final class ShakeRandom extends SecureRandom {
        private final SHAKEDigest d = new SHAKEDigest(256);
        ShakeRandom(byte[] seed) { d.update(seed, 0, seed.length); }
        @Override public void nextBytes(byte[] out) { d.doOutput(out, 0, out.length); }
    }

    // ---------------------------------------------------------------- low-level key objects

    AsymmetricKeyParameter privFromBytes(byte[] sk) {
        switch (family) {
            case MLDSA: return new MLDSAPrivateKeyParameters(mldsa, sk, null);
            case SLHDSA: return new SLHDSAPrivateKeyParameters(slhdsa, sk);
            default: {
                // f || g || F  (sizes: f,g = 1<<logn * (6 or 5 bits), F = n bytes)
                int n = 1 << falcon.getLogN();
                int fgLen = (falcon.getLogN() == 9) ? (n * 6 / 8) : (n * 5 / 8);
                if (sk.length == 2 * fgLen + n + 1) sk = java.util.Arrays.copyOfRange(sk, 1, sk.length); // strip 0x50|logn header
                byte[] f = java.util.Arrays.copyOfRange(sk, 0, fgLen);
                byte[] g = java.util.Arrays.copyOfRange(sk, fgLen, 2 * fgLen);
                byte[] F = java.util.Arrays.copyOfRange(sk, 2 * fgLen, sk.length);
                return new FalconPrivateKeyParameters(falcon, f, g, F, null);
            }
        }
    }

    AsymmetricKeyParameter pubFromBytes(byte[] pk) {
        switch (family) {
            case MLDSA: return new MLDSAPublicKeyParameters(mldsa, pk);
            case SLHDSA: return new SLHDSAPublicKeyParameters(slhdsa, pk);
            default: return new FalconPublicKeyParameters(falcon, falconStripPkHeader(pk));
        }
    }

    static byte[] privBytes(AsymmetricKeyParameter p) {
        if (p instanceof MLDSAPrivateKeyParameters) return ((MLDSAPrivateKeyParameters) p).getEncoded(); // expanded FIPS 204 sk
        if (p instanceof SLHDSAPrivateKeyParameters) return ((SLHDSAPrivateKeyParameters) p).getEncoded();
        FalconPrivateKeyParameters f = (FalconPrivateKeyParameters) p;
        byte[] body = f.getEncoded();                       // f || g || F
        byte[] out = new byte[body.length + 1];             // standard Falcon sk: 0x50|logn header
        out[0] = (byte) (0x50 + f.getParameters().getLogN());
        System.arraycopy(body, 0, out, 1, body.length);
        return out;
    }

    static byte[] pubBytes(AsymmetricKeyParameter p) {
        if (p instanceof MLDSAPublicKeyParameters) return ((MLDSAPublicKeyParameters) p).getEncoded();
        if (p instanceof SLHDSAPublicKeyParameters) return ((SLHDSAPublicKeyParameters) p).getEncoded();
        FalconPublicKeyParameters f = (FalconPublicKeyParameters) p;
        byte[] h = f.getH();
        byte[] out = new byte[h.length + 1];              // standard Falcon pk: 0x00|logn header + modq(h)
        out[0] = (byte) f.getParameters().getLogN();
        System.arraycopy(h, 0, out, 1, h.length);
        return out;
    }

    static byte[] pubBytes(AsymmetricCipherKeyPair kp) { return pubBytes(kp.getPublic()); }
    static byte[] privBytes(AsymmetricCipherKeyPair kp) { return privBytes(kp.getPrivate()); }

    /** Accepts the standard 897/1793-byte pk (with header) or BC's bare 896/1792-byte h. */
    byte[] falconStripPkHeader(byte[] pk) {
        int hLen = 14 * (1 << falcon.getLogN()) / 8;
        if (pk.length == hLen + 1) return java.util.Arrays.copyOfRange(pk, 1, pk.length);
        return pk;
    }

    /**
     * Normalises a Falcon signature from another library for BC's verifier: BC wants
     * (0x30+logn) || nonce(40) || compressed-sig with no trailing padding. Accepts the NIST/PQClean padded
     * fixed-length format (666/1280 bytes, trailing zero bytes) and either 0x20+logn or 0x30+logn headers.
     */
    byte[] falconNormaliseSig(byte[] sig) {
        int end = sig.length;
        while (end > 41 && sig[end - 1] == 0) end--;      // compressed encoding never ends in 0x00
        byte[] out = java.util.Arrays.copyOf(sig, end);
        int logn = falcon.getLogN();
        if (out[0] == (byte) (0x20 + logn)) out[0] = (byte) (0x30 + logn);
        return out;
    }

    /** Pads BC's variable-length Falcon signature to the standard fixed CRYPTO_BYTES length (666/1280). */
    byte[] falconPadSig(byte[] sig) {
        int target = falcon.getLogN() == 9 ? 666 : 1280;
        return sig.length >= target ? sig : java.util.Arrays.copyOf(sig, target);
    }

    // ---------------------------------------------------------------- JCA key objects

    PrivateKey jcaPrivate(byte[] sk) throws Exception {
        byte[] pkcs8 = PrivateKeyInfoFactory.createPrivateKeyInfo(privFromBytes(sk)).getEncoded();
        return KeyFactory.getInstance(jcaAlg, "BC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    PublicKey jcaPublic(byte[] pk) throws Exception {
        byte[] x509 = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubFromBytes(pk)).getEncoded();
        return KeyFactory.getInstance(jcaAlg, "BC").generatePublic(new X509EncodedKeySpec(x509));
    }

    // ---------------------------------------------------------------- misc

    static byte[] sha256(byte[] in) {
        try { return MessageDigest.getInstance("SHA-256").digest(in); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static String sha256Hex(byte[] in) { return hex(sha256(in)); }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return sb.toString();
    }
    static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
