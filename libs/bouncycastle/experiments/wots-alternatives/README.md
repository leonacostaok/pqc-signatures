# WOTS alternatives

These experiments start from Bouncy Castle `c314b9cdffa3958a0eff5344f8fdcdb0181ed830`. They compare separate address and chain-buffer mechanisms. No persistent cache is used and no production repository is edited.

| Variant | Change |
| --- | --- |
| baseline | Pinned WOTS and engine sources |
| object_hoist | Move the public-key generation address allocation outside its chain loop; retain every clear/reset |
| field_rewrite | At four PRF/HASH setup sites, replace clearing the type suffix with changing the type; all three suffix words are then overwritten exactly as before, with identical allocation structure |
| two_addresses | Prior comparator: initialize separate PRF and HASH addresses once in public-key generation and signing |
| buffer | Prior in-place chain buffer patch, including its per-step first-iteration branch |
| buffer_peeled | Same buffer patch with the first allocating hash outside the repeated loop; preserve negative, zero, invalid-range and integer-overflow behavior |

The full-overwrite requirement is essential to `field_rewrite`: key-pair, chain and hash words are explicitly written before each hash. Public-key compression retains `setTypeAndClear`. The other address variants initialize their local domains independently and preserve all incoming upper tree bytes. None changes PRF/F/T_l byte strings or entropy consumption.

`run.py prepare --parent PATH` imports and verifies the earlier sealed source/class corpus, builds isolated variants, and runs correctness gates. Preparation uses at most two compiler processes concurrently. It does not collect latency or allocation. `AddressTrace` compares ordered hash inputs with dirty addresses and a deliberately nonproduction test engine. `ChainGate` checks real SHA2/SHAKE chains at n=16/24/32 against independent input assembly, exhaustive valid ranges and selected negative/overflow cases. `WotsAlternativeProbe` checks all twelve fixture keys for each fast parameter set and measured case 0 for each slow set, three operations per key. Every operation checks exact output, entropy use where applicable, valid/tampered verification, caller data and encoded key ownership.

Run `python3 prescribe.py` once after preparation to create the expanded six-comparison plan. It records the collection and audit scripts' hashes. This is the plan used here; the older five-comparison helper in the frozen preparation script is not invoked. The first screen is SHA2/SHAKE-128f, three operations, separate latency/allocation processes, two independent AB/BA pairs per comparison, twenty warmup calls on two keys, and ten distinct measured keys used once each per process. Key decoding is outside the counter interval. Operation objects and engines are created inside each call. Correctness checks and output encoding for key generation are outside the interval; signature generation includes its normal serialization. Warmup and validation still affect compilation and GC state. This fixed short warmup does not establish steady state.

Only begin collection during the coordinated window: `python3 run.py collect --window "authorization reference"`. Each process receives exactly one implementation class tree. Compilation, process order, source/class/driver/fixture/runtime identities, commands, status, all observations and losses are retained. The quantitative followup rule is recorded in `plan.json`; it selects individual mechanisms for all four SHA2/SHAKE-192f/256f configurations and never combines winners. It is a screening rule rather than a significance test.

Run `python3 audit.py [CHECKOUT_ROOT]` to recompute source/class seals, correctness coverage, process/corpus checks and all summary arithmetic without cryptographic execution. It also works before collection, reporting preparation-only coverage. Python `-O` and `PYTHONOPTIMIZE` are rejected. Process summaries are arithmetic means over the ten distinct measured keys; aggregate percentages divide the arithmetic mean of the two candidate process means by the corresponding reference mean. Both individual pair changes remain in the summary. No peak-memory or retained-heap claim follows from thread allocated bytes.

For another host, `rebuild.py --javac /path/to/javac --out /new/output` extracts the retained complete pinned source archive and overlays each saved WOTS/engine pair, then builds the drivers. It never requires the original parent checkout. Exact compiled-class matching additionally depends on the retained compiler/runtime version. The saved fixture TSV, all selected sources and all Java/Python drivers are portable; recorded absolute paths describe the original execution host. Rebuilding runs compilers but no benchmarks. A reproduced collection requires its own fresh manifest and checks.
