"""Generate isolated patches from the pinned sources; no sampling or NTT edits."""
import sys
if sys.flags.optimize:
    raise RuntimeError('Python optimization disables required checks; run without -O')
from pathlib import Path

PACKAGE = Path('core/src/main/java/org/bouncycastle/crypto/signers/mldsa')
VARIANTS = ['baseline', 'lazy', 'stream', 'combined']

def function_span(source, signature):
    start = source.index(signature)
    body = source.index('{', start)
    depth = 1; end = body + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return start, end

def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(('replacement count', source.count(old), old))
    return source.replace(old, new)

def change(source_root, variant):
    if variant not in VARIANTS:
        raise ValueError(variant)
    directory = source_root / PACKAGE
    if variant in ['lazy', 'combined']:
        p = directory/'Poly.java'; s = p.read_text()
        start, end = function_span(s, '    public void pointwiseAccountMontgomery(PolyVec u, PolyVec v)')
        s = s[:start] + '''    public void pointwiseAccountMontgomery(PolyVec u, PolyVec v)
    {
        int[] thisCoeffs = this.coeffs;
        int L = engine.getDilithiumL();
        for (int k = 0; k < DilithiumN; ++k)
        {
            long sum = 0;
            for (int i = 0; i < L; ++i)
            {
                sum += (long)u.getVectorIndex(i).coeffs[k] * (long)v.getVectorIndex(i).coeffs[k];
            }
            thisCoeffs[k] = Reduce.montgomeryReduce(sum);
        }
    }''' + s[end:]
        p.write_text(s)
    if variant in ['stream', 'combined']:
        p = directory/'PolyVecMatrix.java'; s = p.read_text(); end = s.rfind('}')
        s = s[:end] + '''    static void expandAndMultiply(MLDSAEngine engine, PolyVec t, PolyVec v, byte[] rho)
    {
        PolyVec row = new PolyVec(engine, engine.getDilithiumL());
        for (int i = 0; i < engine.getDilithiumK(); ++i)
        {
            row.uniformBlocks(rho, i << 8);
            t.getVectorIndex(i).pointwiseAccountMontgomery(row, v);
        }
    }
''' + s[end:]; p.write_text(s)
        p = directory/'MLDSAEngine.java'; s = p.read_text()
        for signature in ['    public byte[][] generateKeyPairInternal(byte[] seed)',
                          '    public byte[] deriveT1(', '    private boolean doVerifyInternal(']:
            start, end = function_span(s, signature); body = s[start:end]
            body = replace_once(body, '        PolyVecMatrix aMatrix = new PolyVecMatrix(this);\n', '')
            body = replace_once(body, '        aMatrix.expandMatrix(rho);\n', '')
            old = 'aMatrix.pointwiseMontgomery(w1, z);' if 'doVerifyInternal' in signature else 'aMatrix.pointwiseMontgomery(t1, s1hat);'
            new = 'PolyVecMatrix.expandAndMultiply(this, w1, z, rho);' if 'doVerifyInternal' in signature else 'PolyVecMatrix.expandAndMultiply(this, t1, s1hat, rho);'
            body = replace_once(body, old, new)
            s = s[:start] + body + s[end:]
        p.write_text(s)
