# Verify, split into stages

Verification was split into the steps of the FIPS algorithms. Every library timed **its own implementation of each
step** (by calling internal functions, linking internal symbols from a static library, vendoring the source with
stage entry points, or reflection), plus up to five alternatives per step.

## ML-DSA (FIPS 204, Algorithm 8)

| stage | what happens | typical share |
|---|---|---|
| `decode` | unpack pk (rho, t1) and signature (c~, z, h), validate hint encoding | small |
| `mu` | tr = SHAKE256(pk, 64); mu = SHAKE256(tr ‖ 0 ‖ |ctx| ‖ ctx ‖ M, 64) | small, grows with message |
| `expandA` | k·l polynomials of SHAKE-128 rejection sampling | large |
| `w_approx` | c = SampleInBall(c~); w' = NTT⁻¹(A·NTT(z) − NTT(c)·NTT(t1·2^d)) | large |
| `hint_check` | ‖z‖∞ bound, w1' = UseHint(h, w'), c~' = H(mu ‖ w1Encode(w1')), compare | small |

## SLH-DSA (FIPS 205, Algorithm 20)

| stage | what happens |
|---|---|
| `hmsg` | parse signature, digest = H_msg(R, PK.seed, PK.root, M'), split into FORS indices and tree/leaf index |
| `fors` | rebuild k FORS tree roots from the revealed leaves and auth paths, compress to PK_FORS |
| `ht_wots` | for each of d hypertree layers, finish the WOTS+ hash chains to recover the WOTS+ public key (the bulk of the work) |
| `ht_auth` | for each layer, hash up the XMSS auth path to the layer root; compare the top root with PK.root |

## Rules

- Each stage is timed in isolation with inputs computed by the previous stages outside the timed region.
- Every alternative's output is compared with the library's own stage output on every run.
- Canonical stage outputs (c~, mu, A in [0,q), w' in [0,q), w1Encode; H_msg digest, PK_FORS, WOTS pks, layer roots) are
  compared **across all six libraries**: same intermediate values everywhere, or the run reports a problem.
- `total` = the library's v0 stages chained; `total_best` = the library's fastest correct combination. Both run the
  validation suite.
- "best-of-breed" in [../RESULTS.md](../RESULTS.md) sums the fastest implementation of each stage across all libraries:
  what a single implementation combining every library's best idea would approach.

Stage alternatives per library: `docs/<lib>/verify-stages.md`. Ideas behind them: [approaches.md](approaches.md).
