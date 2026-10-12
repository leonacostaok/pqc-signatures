"""Add diagnostic marks to copied source only; production snapshots remain untouched."""
from pathlib import Path

def instrument(root):
    package=Path(root)/'core/src/main/java/org/bouncycastle/crypto/signers/mldsa'
    p=package/'MLDSAEngine.java';s=p.read_text()
    def replace(old,new):
        nonlocal s
        assert s.count(old)==1, (old,s.count(old))
        s=s.replace(old,new)
    replace('''        byte[] outSig = new byte[CryptoBytes];''','''        StageProfile.mark("secret_decode_setup");
        byte[] outSig = new byte[CryptoBytes];''')
    replace('''        byte[] keyMu = Arrays.copyOf(key, SeedBytes + RndBytes + CrhBytes);''','''        StageProfile.mark("rhoPrime_hash");
        byte[] keyMu = Arrays.copyOf(key, SeedBytes + RndBytes + CrhBytes);''')
    replace('''        aMatrix.expandMatrix(rho);

        s1.polyVecNtt();''','''        StageProfile.mark("matrix_sample");
        aMatrix.expandMatrix(rho);

        StageProfile.mark("secret_ntt");
        s1.polyVecNtt();''')
    marks=[('            y.uniformGamma1(rhoPrime, nonce++);','gamma_sample'),
        ('            y.copyTo(z);','y_copy_ntt'),('            aMatrix.pointwiseMontgomery(w1, z);','matrix_product'),
        ('            w1.reduce();','matrix_reduce_inverse'),('            w1.conditionalAddQ();','decomposition_challenge'),
        ('            z.pointwisePolyMontgomery(cp, s1);','response_rejection'),
        ('            h.pointwisePolyMontgomery(cp, t0);','hint_rejection'),
        ('            Packing.packSignature(outSig, z, h, this);','signature_encode')]
    for token,name in marks: replace(token,'            StageProfile.mark("'+name+'");\n'+token)
    replace('''        if (siglen != CryptoBytes)''','''        StageProfile.mark("signature_decode_norm");
        if (siglen != CryptoBytes)''')
    marks=[('        t1 = Packing.unpackPublicKey(t1, encT1, this);','public_key_decode'),
        ('        cp.challenge(sig, 0, DilithiumCTilde);','challenge_sample'),
        ('        aMatrix.expandMatrix(rho);\n\n        z.polyVecNtt();','matrix_sample'),
        ('        z.polyVecNtt();','z_ntt'),('        aMatrix.pointwiseMontgomery(w1, z);','matrix_product'),
        ('        cp.polyNtt();','challenge_t1_ntt'),('        t1.pointwisePolyMontgomery(cp, t1);','challenge_product_subtract'),
        ('        w1.invNttToMont();','inverse_canonicalize'),('        w1.useHint(w1, h);','hint_encode'),
        ('        shake256Digest.update(buf, 0, CrhBytes + DilithiumK * DilithiumPolyW1PackedBytes);','challenge_hash_compare')]
    # Restrict replacements to verifier body; signing has matching arithmetic statements.
    prefix,verify=s.split('    private boolean doVerifyInternal(',1)
    for token,name in marks:
        assert verify.count(token)==1,(token,verify.count(token))
        verify=verify.replace(token,'        StageProfile.mark("'+name+'");\n'+token)
    s=prefix+'    private boolean doVerifyInternal('+verify;p.write_text(s)
