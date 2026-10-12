# Initial WOTS alternative screen

All 36 comparison/parameter/operation combinations are retained. Negative values mean lower. Each percentage divides the mean of two candidate process means by the corresponding reference mean. Wall/CPU and allocation use separate processes. Both pair changes and absolute means remain in `summary.json`. Unchanged address-variant verification controls and rejected candidates remain included.

| Parameter | Reference → candidate | Operation | Wall time % | Thread CPU % | Allocated bytes % |
| --- | --- | --- | ---: | ---: | ---: |
| sha2-128f | baseline → object_hoist | keygen | +1.33 | +1.49 | -10.16 |
| sha2-128f | baseline → field_rewrite | keygen | +6.11 | +5.84 | +0.00 |
| sha2-128f | baseline → two_addresses | keygen | -5.23 | -5.31 | -9.86 |
| sha2-128f | baseline → buffer | keygen | +2.84 | +2.89 | -73.21 |
| sha2-128f | buffer → buffer_peeled | keygen | -0.69 | -0.73 | +0.00 |
| sha2-128f | baseline → buffer_peeled | keygen | +4.76 | +4.88 | -73.23 |
| sha2-128f | baseline → object_hoist | sign | -0.67 | -0.37 | -8.23 |
| sha2-128f | baseline → field_rewrite | sign | -3.83 | -3.55 | -0.07 |
| sha2-128f | baseline → two_addresses | sign | -2.44 | -2.25 | -7.94 |
| sha2-128f | baseline → buffer | sign | +0.75 | +0.90 | -66.60 |
| sha2-128f | buffer → buffer_peeled | sign | -8.23 | -7.26 | -0.18 |
| sha2-128f | baseline → buffer_peeled | sign | +2.29 | -5.17 | -66.52 |
| sha2-128f | baseline → object_hoist | verify | -0.61 | -1.00 | +0.00 |
| sha2-128f | baseline → field_rewrite | verify | -0.59 | -0.64 | +0.00 |
| sha2-128f | baseline → two_addresses | verify | +0.98 | +1.01 | +0.00 |
| sha2-128f | baseline → buffer | verify | +3.07 | +2.98 | -61.08 |
| sha2-128f | buffer → buffer_peeled | verify | -14.24 | -14.04 | -0.03 |
| sha2-128f | baseline → buffer_peeled | verify | -1.74 | -1.70 | -61.07 |
| shake-128f | baseline → object_hoist | keygen | +0.09 | +0.06 | -10.19 |
| shake-128f | baseline → field_rewrite | keygen | -0.02 | +0.01 | +0.00 |
| shake-128f | baseline → two_addresses | keygen | -1.43 | -1.42 | -9.89 |
| shake-128f | baseline → buffer | keygen | +0.72 | +0.66 | -73.45 |
| shake-128f | buffer → buffer_peeled | keygen | -4.44 | -4.33 | +0.00 |
| shake-128f | baseline → buffer_peeled | keygen | -1.97 | -2.06 | -73.45 |
| shake-128f | baseline → object_hoist | sign | -0.30 | +0.03 | -8.18 |
| shake-128f | baseline → field_rewrite | sign | -0.28 | -0.33 | -0.00 |
| shake-128f | baseline → two_addresses | sign | +0.48 | +0.58 | -7.97 |
| shake-128f | baseline → buffer | sign | -1.18 | -0.99 | -66.66 |
| shake-128f | buffer → buffer_peeled | sign | -0.83 | -0.79 | +0.00 |
| shake-128f | baseline → buffer_peeled | sign | -0.52 | -0.37 | -66.66 |
| shake-128f | baseline → object_hoist | verify | +0.30 | +0.31 | +0.00 |
| shake-128f | baseline → field_rewrite | verify | +1.01 | +0.94 | +0.02 |
| shake-128f | baseline → two_addresses | verify | +0.18 | +0.15 | +0.00 |
| shake-128f | baseline → buffer | verify | +0.85 | +0.87 | -61.17 |
| shake-128f | buffer → buffer_peeled | verify | -1.57 | -1.66 | +0.00 |
| shake-128f | baseline → buffer_peeled | verify | -1.73 | -1.76 | -61.14 |
