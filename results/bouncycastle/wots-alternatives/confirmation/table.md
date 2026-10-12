# Selected WOTS higher-size followup

All 48 reference/candidate/parameter/operation combinations are retained below. Each reference is stock Bouncy Castle. These are the four mechanisms selected by the initial 128f screen; the rejected peeled buffer was not retested. Negative values mean lower, and percentages divide the mean of two candidate process means by the corresponding reference mean. Both per-pair changes and absolute means remain in `summary.json`. Address-variant verification paths are unchanged controls. Separate JVMs measured latency and allocated bytes; neither aggregate percentages nor selected followup establish steady state or causal speed attribution.

| Parameter | Candidate | Operation | Wall time % | Thread CPU % | Allocated bytes % |
| --- | --- | --- | ---: | ---: | ---: |
| sha2-192f | object_hoist | keygen | +0.52 | -0.04 | -8.42 |
| sha2-192f | field_rewrite | keygen | -2.78 | -2.51 | +0.00 |
| sha2-192f | two_addresses | keygen | -2.47 | -2.54 | -8.25 |
| sha2-192f | buffer | keygen | +0.44 | +0.42 | -75.16 |
| sha2-192f | object_hoist | sign | -0.02 | -0.07 | -6.03 |
| sha2-192f | field_rewrite | sign | -0.30 | -0.29 | +0.00 |
| sha2-192f | two_addresses | sign | -8.14 | -1.64 | -5.89 |
| sha2-192f | buffer | sign | -1.32 | -0.03 | -60.81 |
| sha2-192f | object_hoist | verify | +12.19 | +11.83 | +0.00 |
| sha2-192f | field_rewrite | verify | +6.27 | +6.32 | +0.00 |
| sha2-192f | two_addresses | verify | +1.77 | +1.79 | +0.00 |
| sha2-192f | buffer | verify | -6.07 | -5.90 | -64.13 |
| sha2-256f | object_hoist | keygen | +4.32 | +3.48 | -7.21 |
| sha2-256f | field_rewrite | keygen | +6.35 | +5.94 | +0.00 |
| sha2-256f | two_addresses | keygen | +6.16 | +5.62 | -7.10 |
| sha2-256f | buffer | keygen | +9.58 | +6.90 | -76.80 |
| sha2-256f | object_hoist | sign | -1.09 | -1.07 | -5.51 |
| sha2-256f | field_rewrite | sign | +2.76 | +2.20 | +0.00 |
| sha2-256f | two_addresses | sign | -1.91 | -1.75 | -5.42 |
| sha2-256f | buffer | sign | -0.49 | -0.01 | -62.35 |
| sha2-256f | object_hoist | verify | +1.17 | +1.14 | +0.00 |
| sha2-256f | field_rewrite | verify | +6.70 | +6.66 | +0.00 |
| sha2-256f | two_addresses | verify | -1.85 | -2.01 | +0.00 |
| sha2-256f | buffer | verify | +15.85 | +15.73 | -62.96 |
| shake-192f | object_hoist | keygen | +0.71 | +0.30 | -8.46 |
| shake-192f | field_rewrite | keygen | +0.94 | +0.45 | +0.00 |
| shake-192f | two_addresses | keygen | -0.57 | -0.58 | -8.29 |
| shake-192f | buffer | keygen | +2.05 | +1.93 | -75.47 |
| shake-192f | object_hoist | sign | -0.09 | -0.04 | -6.03 |
| shake-192f | field_rewrite | sign | -0.75 | -0.73 | +0.00 |
| shake-192f | two_addresses | sign | -0.89 | -0.61 | -5.89 |
| shake-192f | buffer | sign | -1.40 | -0.55 | -60.84 |
| shake-192f | object_hoist | verify | +0.21 | +0.22 | +0.00 |
| shake-192f | field_rewrite | verify | -0.61 | -0.61 | +0.00 |
| shake-192f | two_addresses | verify | +0.27 | +0.25 | +0.00 |
| shake-192f | buffer | verify | +3.06 | +2.92 | -64.07 |
| shake-256f | object_hoist | keygen | -0.71 | -0.66 | -7.22 |
| shake-256f | field_rewrite | keygen | -3.63 | -2.38 | +0.00 |
| shake-256f | two_addresses | keygen | -0.86 | -0.90 | -7.11 |
| shake-256f | buffer | keygen | +1.99 | +2.03 | -76.91 |
| shake-256f | object_hoist | sign | -0.87 | -0.36 | -5.52 |
| shake-256f | field_rewrite | sign | -0.17 | -0.23 | +0.00 |
| shake-256f | two_addresses | sign | -0.00 | -0.08 | -5.45 |
| shake-256f | buffer | sign | +0.44 | +0.62 | -62.37 |
| shake-256f | object_hoist | verify | +0.12 | +0.11 | +0.00 |
| shake-256f | field_rewrite | verify | -0.89 | -0.88 | +0.00 |
| shake-256f | two_addresses | verify | -2.55 | -1.25 | +0.00 |
| shake-256f | buffer | verify | +1.79 | +1.84 | -63.04 |
