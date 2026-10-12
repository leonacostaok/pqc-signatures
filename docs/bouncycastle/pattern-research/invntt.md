# Folding the final inverse-NTT scale

This is a source-reviewed arithmetic candidate, not a measured speedup or a production patch. The pinned BC source is `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. It preserves the standardized transform modulo q and adds no secret-dependent branches or storage. Internal integer representatives can change, so the proof must cover callers as well as the transform.

## Transformation

Let q = 8,380,417, R = 2^32 and M(x) be BC's signed Montgomery reduction, congruent to x/R modulo q. The final inverse butterfly uses z = −25,847, then multiplies both outputs by f = 41,978:

```
original left  = M(f * (a + b))
original right = M(f * M(z * (a - b)))

g = M(f * z) = 3,975,713
folded left    = M(f * (a + b))
folded right   = M(g * (a - b))
```

The right expressions are congruent because both equal f*z*(a−b)/R² modulo q. Stop the generic butterfly loop before length 128 and combine its final stage with scaling. This removes 128 of 1,280 Montgomery reductions (**10% of this transform's reductions**) and its separate final array pass. It does not imply 10% faster signing or verification.

The arithmetic pattern is established: the [pq-crystals AVX2 inverse](https://github.com/pq-crystals/dilithium/blob/master/avx2/invntt.S) uses a scaled final twiddle from its [constant table](https://github.com/pq-crystals/dilithium/blob/master/avx2/consts.c). Its opposite subtraction order uses the negative constant. The proposed portable Java version would need its own correctness and performance validation.

## Bounds and caller behavior

All seven inverse-transform call sites in the pinned MLDSAEngine receive coefficients with magnitude below q. Forward inputs, including decoded t1 shifted by 13, are below q; eight forward stages give a conservative bound below 9q. Pointwise Montgomery products are bounded by 5,514,722. Matrix rows sum at most seven such products; verification subtracts one more. Their following reduce32 yields magnitude at most 4,259,832. All these inverse inputs therefore meet the required bound.

At each inverse stage, sums at most double the preceding bound, while Montgomery-reduced right branches remain below q. After seven stages, the final sum/difference has magnitude below 256q = 2,145,386,752, less than Integer.MAX_VALUE. Folded right outputs have magnitude at most 6,176,124, and left outputs at most 4,211,177. The original outputs also satisfy the common 6,176,124 bound used below. All multiplication/reduction intermediates fit signed long except the intentional low-word product with Qinv; Java wrapping preserves that low word. Java multiplication must widen first, such as `(long)g * difference`; both old butterfly operands must be read before either result overwrites them.

| Caller in pinned MLDSAEngine | Next operations | Required equivalence |
|---|---|---|
| Keygen, line 285; deriveT1, line 333 | Add s2, conditionalAddQ, power2Round | Both representatives remain inside (−q,q), even allowing decoded s2 magnitude 11; canonical outputs are identical. |
| Signing matrix product, line 433 | conditionalAddQ, decomposition | Canonical outputs are identical before decomposition. |
| Challenge products, lines 450, 459, 468 | Add/subtract, reduction, norm checks, hints | Exact integer products are identical, as bounded below. |
| Verification, line 562 | conditionalAddQ, useHint | Canonical outputs are identical before useHint. |

Challenge polynomials have at most 60 nonzero coefficients of magnitude one. Thus c*s1 and c*s2 have coefficient magnitude at most 660, including noncanonical-but-decodable eta fields; c*t0 is at most 245,760. A different representative of these small products would have magnitude at least q−245,760 = 8,134,657, exceeding the folded output bound. Congruence therefore forces exact integer equality for these products, preserving subsequent rejection and hint decisions.

Raw equality is not required for arbitrary inverse inputs. In the oracle's valid vector 15, coefficient 137, the original result is −4,178,559 and the folded result is 4,201,858: they differ by exactly q. An arbitrary-array raw-equality test would reject a valid modular transformation, while modular equality alone would be insufficient without the caller bounds above. The oracle also reports a scalar algebraic illustration; that larger scalar is not claimed to arise from a valid inverse input.

## Reproduce the arithmetic check

```
python3 libs/bouncycastle/experiments/pattern-research/invntt_oracle.py
```

The deterministic oracle verifies the [snapshot hashes](../../../results/bouncycastle/pattern-research/invntt/sources.json) and q/Qinv/f source constants, compares canonical transforms on boundary/random vectors, and compares both versions' challenge products with independent schoolbook negacyclic convolution. It checks Java integer/long bounds explicitly and rejects disabled Python assertions. [Saved output](../../../results/bouncycastle/pattern-research/invntt/oracle-result.json) retains the representative differences. Sampling supplements the source-derived bounds; it is not exhaustive, a full signature test, or a timing result. The proof covers the current seven callers and sequencing, not arbitrary int arrays, future callers, or composition with a changed reduction scheme.

Before production use: implement the actual Java transform, check exact key/signature bytes and negative verification cases across all ML-DSA sets, run native tests, then measure complete operations with balanced fresh processes. The same technique may transfer to generic implementations in other languages, but each reduction convention and caller range needs its own review. See [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) and the [reference reduction contract](https://github.com/pq-crystals/dilithium/blob/master/ref/reduce.c).
