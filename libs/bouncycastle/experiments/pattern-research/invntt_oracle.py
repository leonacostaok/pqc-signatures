#!/usr/bin/env python3
"""Arithmetic oracle, not a benchmark. Reads the pinned BC table; writes nothing.
Usage: python3 libs/bouncycastle/experiments/pattern-research/invntt_oracle.py [path/to/Ntt.java]
A bounded sample supplements the source-derived proof; it is not exhaustive.
"""
import pathlib, re, random, json, sys, hashlib
if not __debug__:
    raise SystemExit('Assertions are required; do not use -O or PYTHONOPTIMIZE')
DEFAULT = pathlib.Path(__file__).resolve().parents[4] / 'results/bouncycastle/pattern-research/invntt/Ntt.java'
p = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT)
binding = json.loads((p.parent / 'sources.json').read_text())
for name, digest in binding['files'].items():
    assert hashlib.sha256((p.parent / name).read_bytes()).hexdigest() == digest
assert hashlib.sha256(p.read_bytes()).hexdigest() == binding['files']['Ntt.java']
Z = list(map(int, re.search(r'nttZetas = \{(.*?)\};', p.read_text(), re.S).group(1).replace('\n', '').split(',')))
assert len(Z) == 256 and Z[1] == 25847
Q = 8380417; QI = 58728449; R = 1 << 32; F = 41978
engine = (p.parent / 'MLDSAEngine.java').read_text()
assert int(re.search(r'DilithiumQ\s*=\s*(\d+)', engine).group(1)) == Q
assert int(re.search(r'DilithiumQinv\s*=\s*(\d+)', engine).group(1)) == QI
assert int(re.search(r'final int f\s*=\s*(\d+)', p.read_text()).group(1)) == F
I32 = lambda n: ((n + (1 << 31)) % R) - (1 << 31)
def mr(a):
    assert -(1 << 63) <= a < (1 << 63)
    # Java's possible long overflow in a*QI has no effect on the low 32 bits.
    t = I32(a * QI)
    v = a - t * Q
    assert -(1 << 63) <= v < (1 << 63) and v % R == 0
    # (int)(v >>> 32) and (int)(v >> 32) are identical.
    return I32(v // R)
G = mr(F * (-Z[1])); assert G == 3975713

def ntt(v):
    v = v.copy(); k = 0; h = 128
    while h:
        for s in range(0, 256, 2*h):
            k += 1
            for j in range(s, s+h):
                t = mr(Z[k] * v[j+h]); a = v[j]
                assert -(1 << 31) < a-t < (1 << 31)
                assert -(1 << 31) < a+t < (1 << 31)
                v[j+h], v[j] = a-t, a+t
        h //= 2
    return v

def inverse(v, fold):
    assert all(abs(x) < Q for x in v)
    v = v.copy(); k = 256; h = 1
    while h < (128 if fold else 256):
        for s in range(0, 256, 2*h):
            k -= 1; z = -Z[k]
            for j in range(s, s+h):
                a, b = v[j], v[j+h]
                assert -(1 << 31) < a-b < (1 << 31)
                assert -(1 << 31) < a+b < (1 << 31)
                v[j], v[j+h] = a+b, mr(z*(a-b))
        h *= 2
    if fold:
        for j in range(128):
            a, b = v[j], v[j+128]
            assert -(1 << 31) < a-b < (1 << 31)
            assert -(1 << 31) < a+b < (1 << 31)
            v[j], v[j+128] = mr(F*(a+b)), mr(G*(a-b))
    else:
        v = [mr(F*x) for x in v]
    assert all(abs(x) < Q for x in v)
    return v

rng = random.Random(0x204)
cases = [[0]*256, [Q-1]*256, [1-Q]*256,
         [(Q-1)*(-1 if i&1 else 1) for i in range(256)]]
cases += [[rng.randrange(1-Q, Q) for _ in range(256)] for _ in range(256)]
rawdiff = 0; witness = None
for case_index, a in enumerate(cases):
    old, new = inverse(a, False), inverse(a, True)
    assert [x % Q for x in old] == [x % Q for x in new]
    for i, (x, y) in enumerate(zip(old, new)):
        if x != y:
            rawdiff += 1
            if witness is None:
                witness = {'case_index': case_index, 'coefficient': i,
                           'old': x, 'new': y, 'input_first8': a[:8]}
    for s in [-11, -5, -2, 0, 2, 4, 11]:
        assert all(abs(x+s) < Q and abs(y+s) < Q for x, y in zip(old, new))
        assert [(x+s) % Q for x in old] == [(x+s) % Q for x in new]

def product(c, s):
    out = [0]*256
    for i, x in enumerate(c):
        if x:
            for j, y in enumerate(s):
                n = i+j
                out[n % 256] += x*y*(1 if n < 256 else -1)
    return out

checked = 0
for tau in [39, 49, 60]:
    for lo, hi in [(-5, 2), (-11, 4), (-4095, 4096)]:
        for n in range(12):
            c = [0]*256
            for i in rng.sample(range(256), tau):
                c[i] = rng.choice([-1, 1])
            s = [(lo if (i+n)&1 else hi) if n < 2 else rng.randint(lo, hi)
                 for i in range(256)]
            a, b = ntt(c), ntt(s)
            v = [mr(x*y) for x, y in zip(a, b)]
            expected = product(c, s)
            assert inverse(v, False) == expected
            assert inverse(v, True) == expected
            checked += 1
scalar_witness = None
for x in range(256*Q-1, 256*Q-10000, -1):
    a, b = mr(F*mr(-Z[1]*x)), mr(G*x)
    assert (a-b) % Q == 0 and abs(a) < Q and abs(b) < Q
    if a != b:
        scalar_witness = {'difference_input': x, 'old': a, 'new': b}
        break
print(json.dumps({'inverse_vectors': len(cases), 'inverse_coefficients': len(cases)*256,
                  'raw_representative_differences': rawdiff, 'vector_witness': witness,
                  'sparse_products': checked, 'algebraic_scalar_witness': scalar_witness,
                  'scalar_witness_scope': 'Algebraic illustration only; not claimed reachable from an inverse input. vector_witness is from a valid full transform.', 'g': G,
                  'bounds': {'pointwise': (81*Q*Q)//R+(Q+1)//2,
                             'fused': (G*256*Q)//R+(Q+1)//2,
                             'left': (F*256*Q)//R+(Q+1)//2,
                             'reduce32': (1 << 22)+8*8191,
                             'max_sum_or_difference': 256*Q}}, indent=2))
