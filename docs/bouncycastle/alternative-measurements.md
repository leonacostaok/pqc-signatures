# Bouncy Castle alternative measurements

All 156 candidate/action comparisons are retained. Green means the recorded value decreased; red means it increased. Color indicates direction, not statistical confidence or a recommendation. Negative time change means less elapsed time per operation, not the same percentage increase in throughput.

These campaigns use different corpora, runtime versions, warmup caps and heap settings. Compare each candidate only with its listed reference. CPU is calling-thread CPU. Allocated bytes come from separate JVM cohorts and exclude static initialization; the NTT companion table adds 1,024 bytes of static payload plus its header. Peak/live heap, RSS, stack and GC pauses are not measured here. Seven matrix allocation processes had unusually long durations; their counts are retained with that qualification.

See the [verdicts and limits](alternative-comparison.md) and each group report for pair/round variation, unchanged controls, correctness and promotion rules. All values below are arithmetic means; times are milliseconds and allocations are bytes per call.

## NTT Java 25 screen

| Parameter | Reference → candidate | Action | Original ms | Changed ms | Time Δ | CPU Δ | Original B/op | Changed B/op | Allocation Δ |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| ml_dsa_44 | baseline → fused | keygen | 0.0746 | 0.0746 | 🔴 +0.04% | 🔴 +0.07% | 70994.2 | 70890.6 | 🟢 -0.15% |
| ml_dsa_44 | baseline → companion | keygen | 0.0746 | 0.0752 | 🔴 +0.83% | 🔴 +0.84% | 70994.2 | 71290.0 | 🔴 +0.42% |
| ml_dsa_44 | baseline → both | keygen | 0.0746 | 0.0735 | 🟢 -1.43% | 🟢 -1.31% | 70994.2 | 71294.3 | 🔴 +0.42% |
| ml_dsa_44 | baseline → fused | sign | 0.3249 | 0.3161 | 🟢 -2.72% | 🟢 -2.73% | 90714.6 | 90714.6 | ⚪ 0.00% |
| ml_dsa_44 | baseline → companion | sign | 0.3249 | 0.3054 | 🟢 -6.03% | 🟢 -6.00% | 90714.6 | 90898.6 | 🔴 +0.20% |
| ml_dsa_44 | baseline → both | sign | 0.3249 | 0.3011 | 🟢 -7.32% | 🟢 -7.36% | 90714.6 | 90810.6 | 🔴 +0.11% |
| ml_dsa_44 | baseline → fused | verify | 0.1118 | 0.1052 | 🟢 -5.92% | 🟢 -2.79% | 59859.8 | 59735.8 | 🟢 -0.21% |
| ml_dsa_44 | baseline → companion | verify | 0.1118 | 0.1023 | 🟢 -8.50% | 🟢 -5.63% | 59859.8 | 59760.8 | 🟢 -0.17% |
| ml_dsa_44 | baseline → both | verify | 0.1118 | 0.1065 | 🟢 -4.70% | 🟢 -4.89% | 59859.8 | 59865.3 | 🔴 +0.01% |
| ml_dsa_65 | baseline → fused | keygen | 0.1439 | 0.1444 | 🔴 +0.35% | 🔴 +0.24% | 114080.6 | 113828.6 | 🟢 -0.22% |
| ml_dsa_65 | baseline → companion | keygen | 0.1439 | 0.1433 | 🟢 -0.40% | 🟢 -0.40% | 114080.6 | 113900.0 | 🟢 -0.16% |
| ml_dsa_65 | baseline → both | keygen | 0.1439 | 0.1366 | 🟢 -5.08% | 🟢 -2.18% | 114080.6 | 113900.6 | 🟢 -0.16% |
| ml_dsa_65 | baseline → fused | sign | 0.5451 | 0.5297 | 🟢 -2.81% | 🟢 -2.29% | 142278.7 | 142098.7 | 🟢 -0.13% |
| ml_dsa_65 | baseline → companion | sign | 0.5451 | 0.5159 | 🟢 -5.35% | 🟢 -5.11% | 142278.7 | 142098.7 | 🟢 -0.13% |
| ml_dsa_65 | baseline → both | sign | 0.5451 | 0.5099 | 🟢 -6.45% | 🟢 -6.47% | 142278.7 | 142638.7 | 🔴 +0.25% |
| ml_dsa_65 | baseline → fused | verify | 0.1420 | 0.1431 | 🔴 +0.76% | 🔴 +0.96% | 96707.7 | 96818.9 | 🔴 +0.12% |
| ml_dsa_65 | baseline → companion | verify | 0.1420 | 0.1419 | 🟢 -0.05% | 🟢 -1.27% | 96707.7 | 96706.7 | ⚪ 0.00% |
| ml_dsa_65 | baseline → both | verify | 0.1420 | 0.1410 | 🟢 -0.68% | 🟢 -1.87% | 96707.7 | 97248.3 | 🔴 +0.56% |
| ml_dsa_87 | baseline → fused | keygen | 0.2010 | 0.2044 | 🔴 +1.70% | 🔴 +1.70% | 178865.7 | 178973.1 | 🔴 +0.06% |
| ml_dsa_87 | baseline → companion | keygen | 0.2010 | 0.1999 | 🟢 -0.52% | 🟢 -0.68% | 178865.7 | 178973.1 | 🔴 +0.06% |
| ml_dsa_87 | baseline → both | keygen | 0.2010 | 0.1992 | 🟢 -0.90% | 🟢 -0.83% | 178865.7 | 178864.8 | ⚪ 0.00% |
| ml_dsa_87 | baseline → fused | sign | 0.6185 | 0.6016 | 🟢 -2.73% | 🟢 -2.51% | 210416.7 | 210834.0 | 🔴 +0.20% |
| ml_dsa_87 | baseline → companion | sign | 0.6185 | 0.5876 | 🟢 -4.99% | 🟢 -4.83% | 210416.7 | 210416.7 | ⚪ 0.00% |
| ml_dsa_87 | baseline → both | sign | 0.6185 | 0.5844 | 🟢 -5.51% | 🟢 -5.73% | 210416.7 | 210752.7 | 🔴 +0.16% |
| ml_dsa_87 | baseline → fused | verify | 0.2221 | 0.2202 | 🟢 -0.89% | 🟢 -0.54% | 159096.2 | 158819.4 | 🟢 -0.17% |
| ml_dsa_87 | baseline → companion | verify | 0.2221 | 0.2178 | 🟢 -1.96% | 🟢 -1.34% | 159096.2 | 158413.4 | 🟢 -0.43% |
| ml_dsa_87 | baseline → both | verify | 0.2221 | 0.2170 | 🟢 -2.30% | 🟢 -2.25% | 159096.2 | 158754.7 | 🟢 -0.21% |

## NTT Java 17 held-out confirmation

| Parameter | Reference → candidate | Action | Original ms | Changed ms | Time Δ | CPU Δ | Original B/op | Changed B/op | Allocation Δ |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| ml_dsa_44 | baseline → companion | keygen | 0.0857 | 0.0839 | 🟢 -2.02% | 🟢 -1.29% | 70727.8 | 70973.5 | 🔴 +0.35% |
| ml_dsa_44 | baseline → both | keygen | 0.0857 | 0.1033 | 🔴 +20.54% | 🔴 +2.74% | 70727.8 | 70872.0 | 🔴 +0.20% |
| ml_dsa_44 | baseline → companion | sign | 0.3577 | 0.3353 | 🟢 -6.26% | 🟢 -5.34% | 91125.4 | 91125.4 | ⚪ 0.00% |
| ml_dsa_44 | baseline → both | sign | 0.3577 | 0.3293 | 🟢 -7.93% | 🟢 -6.95% | 91125.4 | 91317.4 | 🔴 +0.21% |
| ml_dsa_44 | baseline → companion | verify | 0.1124 | 0.1117 | 🟢 -0.64% | 🟢 -0.05% | 60096.9 | 60001.5 | 🟢 -0.16% |
| ml_dsa_44 | baseline → both | verify | 0.1124 | 0.1108 | 🟢 -1.42% | 🔴 +0.16% | 60096.9 | 60003.9 | 🟢 -0.15% |
| ml_dsa_65 | baseline → companion | keygen | 0.1603 | 0.1577 | 🟢 -1.65% | 🟢 -2.34% | 114476.0 | 114116.0 | 🟢 -0.31% |
| ml_dsa_65 | baseline → both | keygen | 0.1603 | 0.1666 | 🔴 +3.92% | 🟢 -0.93% | 114476.0 | 114476.0 | ⚪ 0.00% |
| ml_dsa_65 | baseline → companion | sign | 0.5674 | 0.5314 | 🟢 -6.33% | 🟢 -5.73% | 141172.2 | 140927.3 | 🟢 -0.17% |
| ml_dsa_65 | baseline → both | sign | 0.5674 | 0.6380 | 🔴 +12.45% | 🟢 -5.77% | 141172.2 | 140992.2 | 🟢 -0.13% |
| ml_dsa_65 | baseline → companion | verify | 0.1553 | 0.1575 | 🔴 +1.43% | 🟢 -0.53% | 97366.7 | 96999.4 | 🟢 -0.38% |
| ml_dsa_65 | baseline → both | verify | 0.1553 | 0.1560 | 🔴 +0.44% | 🟢 -2.24% | 97366.7 | 96999.4 | 🟢 -0.38% |
| ml_dsa_87 | baseline → companion | keygen | 0.2306 | 0.2278 | 🟢 -1.22% | 🟢 -1.76% | 179752.0 | 179752.0 | ⚪ 0.00% |
| ml_dsa_87 | baseline → both | keygen | 0.2306 | 0.2318 | 🔴 +0.52% | 🟢 -1.11% | 179752.0 | 179080.0 | 🟢 -0.37% |
| ml_dsa_87 | baseline → companion | sign | 0.7064 | 0.6909 | 🟢 -2.18% | 🟢 -3.40% | 213729.2 | 213057.2 | 🟢 -0.31% |
| ml_dsa_87 | baseline → both | sign | 0.7064 | 0.6680 | 🟢 -5.42% | 🟢 -5.55% | 213729.2 | 214065.2 | 🔴 +0.16% |
| ml_dsa_87 | baseline → companion | verify | 0.2501 | 0.2405 | 🟢 -3.82% | 🟢 -1.75% | 159106.3 | 159101.9 | ⚪ 0.00% |
| ml_dsa_87 | baseline → both | verify | 0.2501 | 0.2424 | 🟢 -3.06% | 🟢 -1.88% | 159106.3 | 159104.9 | ⚪ 0.00% |

## Matrix Java 25 screen

| Parameter | Reference → candidate | Action | Original ms | Changed ms | Time Δ | CPU Δ | Original B/op | Changed B/op | Allocation Δ |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| ml_dsa_44 | baseline → lazy | keygen | 0.0801 | 0.0826 | 🔴 +3.20% | 🔴 +3.15% | 70470.4 | 70670.8 | 🔴 +0.28% |
| ml_dsa_44 | baseline → stream | keygen | 0.0801 | 0.0785 | 🟢 -1.88% | 🟢 -1.80% | 70470.4 | 57675.7 | 🟢 -18.16% |
| ml_dsa_44 | baseline → combined | keygen | 0.0801 | 0.0811 | 🔴 +1.36% | 🔴 +1.18% | 70470.4 | 57549.9 | 🟢 -18.33% |
| ml_dsa_44 | baseline → lazy | sign | 0.3304 | 0.3422 | 🔴 +3.59% | 🔴 +3.67% | 90714.6 | 90810.6 | 🔴 +0.11% |
| ml_dsa_44 | baseline → stream | sign | 0.3304 | 0.3296 | 🟢 -0.24% | 🟢 -0.01% | 90714.6 | 90810.6 | 🔴 +0.11% |
| ml_dsa_44 | baseline → combined | sign | 0.3304 | 0.3399 | 🔴 +2.89% | 🔴 +3.11% | 90714.6 | 90714.6 | ⚪ 0.00% |
| ml_dsa_44 | baseline → lazy | verify | 0.1067 | 0.1066 | 🟢 -0.11% | 🔴 +0.20% | 60157.4 | 59836.5 | 🟢 -0.53% |
| ml_dsa_44 | baseline → stream | verify | 0.1067 | 0.1033 | 🟢 -3.22% | 🟢 -2.82% | 60157.4 | 46902.5 | 🟢 -22.03% |
| ml_dsa_44 | baseline → combined | verify | 0.1067 | 0.1070 | 🔴 +0.21% | 🔴 +0.44% | 60157.4 | 46690.4 | 🟢 -22.39% |
| ml_dsa_65 | baseline → lazy | keygen | 0.1467 | 0.1530 | 🔴 +4.26% | 🔴 +3.69% | 113720.0 | 113720.0 | ⚪ 0.00% |
| ml_dsa_65 | baseline → stream | keygen | 0.1467 | 0.1431 | 🟢 -2.45% | 🟢 -2.44% | 113720.0 | 86944.6 | 🟢 -23.55% |
| ml_dsa_65 | baseline → combined | keygen | 0.1467 | 0.1490 | 🔴 +1.52% | 🔴 +1.42% | 113720.0 | 86764.4 | 🟢 -23.70% |
| ml_dsa_65 | baseline → lazy | sign | 0.5450 | 0.5691 | 🔴 +4.42% | 🔴 +4.38% | 142098.7 | 142278.7 | 🔴 +0.13% |
| ml_dsa_65 | baseline → stream | sign | 0.5450 | 0.5472 | 🔴 +0.39% | 🔴 +0.37% | 142098.7 | 142278.7 | 🔴 +0.13% |
| ml_dsa_65 | baseline → combined | sign | 0.5450 | 0.5744 | 🔴 +5.39% | 🔴 +5.22% | 142098.7 | 142098.7 | ⚪ 0.00% |
| ml_dsa_65 | baseline → lazy | verify | 0.1492 | 0.1502 | 🔴 +0.71% | 🔴 +0.70% | 97274.1 | 96685.4 | 🟢 -0.61% |
| ml_dsa_65 | baseline → stream | verify | 0.1492 | 0.1429 | 🟢 -4.22% | 🟢 -4.19% | 97274.1 | 69659.4 | 🟢 -28.39% |
| ml_dsa_65 | baseline → combined | verify | 0.1492 | 0.1462 | 🟢 -1.99% | 🟢 -2.01% | 97274.1 | 69488.7 | 🟢 -28.56% |
| ml_dsa_87 | baseline → lazy | keygen | 0.2062 | 0.2093 | 🔴 +1.53% | 🔴 +1.54% | 178636.0 | 179200.0 | 🔴 +0.32% |
| ml_dsa_87 | baseline → stream | keygen | 0.2062 | 0.2031 | 🟢 -1.49% | 🟢 -1.44% | 178636.0 | 125825.1 | 🟢 -29.56% |
| ml_dsa_87 | baseline → combined | keygen | 0.2062 | 0.2128 | 🔴 +3.24% | 🔴 +3.11% | 178636.0 | 125824.0 | 🟢 -29.56% |
| ml_dsa_87 | baseline → lazy | sign | 0.6355 | 0.6612 | 🔴 +4.05% | 🔴 +4.13% | 210752.7 | 210752.7 | ⚪ 0.00% |
| ml_dsa_87 | baseline → stream | sign | 0.6355 | 0.6202 | 🟢 -2.41% | 🟢 -2.27% | 210752.7 | 210416.7 | 🟢 -0.16% |
| ml_dsa_87 | baseline → combined | sign | 0.6355 | 0.6803 | 🔴 +7.04% | 🔴 +3.19% | 210752.7 | 210416.7 | 🟢 -0.16% |
| ml_dsa_87 | baseline → lazy | verify | 0.2316 | 0.2454 | 🔴 +5.97% | 🔴 +4.00% | 158410.6 | 158341.4 | 🟢 -0.04% |
| ml_dsa_87 | baseline → stream | verify | 0.2316 | 0.2236 | 🟢 -3.45% | 🟢 -0.49% | 158410.6 | 106057.4 | 🟢 -33.05% |
| ml_dsa_87 | baseline → combined | verify | 0.2316 | 0.2295 | 🟢 -0.89% | 🔴 +2.13% | 158410.6 | 105344.4 | 🟢 -33.50% |

## WOTS Java 25 screen

| Parameter | Reference → candidate | Action | Original ms | Changed ms | Time Δ | CPU Δ | Original B/op | Changed B/op | Allocation Δ |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| sha2_128f | baseline → object_hoist | keygen | 1.9173 | 1.9427 | 🔴 +1.33% | 🔴 +1.49% | 171288.0 | 153880.0 | 🟢 -10.16% |
| sha2_128f | baseline → field_rewrite | keygen | 1.9061 | 2.0226 | 🔴 +6.11% | 🔴 +5.84% | 171288.0 | 171288.0 | ⚪ 0.00% |
| sha2_128f | baseline → two_addresses | keygen | 1.9039 | 1.8043 | 🟢 -5.23% | 🟢 -5.31% | 171288.0 | 154392.0 | 🟢 -9.86% |
| sha2_128f | baseline → buffer | keygen | 1.9427 | 1.9979 | 🔴 +2.84% | 🔴 +2.89% | 171288.0 | 45882.0 | 🟢 -73.21% |
| sha2_128f | buffer → buffer_peeled | keygen | 1.9844 | 1.9708 | 🟢 -0.69% | 🟢 -0.73% | 45848.0 | 45848.0 | ⚪ 0.00% |
| sha2_128f | baseline → buffer_peeled | keygen | 1.9223 | 2.0138 | 🔴 +4.76% | 🔴 +4.88% | 171288.0 | 45848.0 | 🟢 -73.23% |
| sha2_128f | baseline → object_hoist | sign | 43.4528 | 43.1636 | 🟢 -0.67% | 🟢 -0.37% | 4103200.0 | 3765561.6 | 🟢 -8.23% |
| sha2_128f | baseline → field_rewrite | sign | 43.5807 | 41.9124 | 🟢 -3.83% | 🟢 -3.55% | 4103516.8 | 4100665.6 | 🟢 -0.07% |
| sha2_128f | baseline → two_addresses | sign | 43.4512 | 42.3915 | 🟢 -2.44% | 🟢 -2.25% | 4102566.4 | 3776825.6 | 🟢 -7.94% |
| sha2_128f | baseline → buffer | sign | 42.9986 | 43.3224 | 🔴 +0.75% | 🔴 +0.90% | 4102566.4 | 1370400.0 | 🟢 -66.60% |
| sha2_128f | buffer → buffer_peeled | sign | 44.1175 | 40.4849 | 🟢 -8.23% | 🟢 -7.26% | 1372300.8 | 1369766.4 | 🟢 -0.18% |
| sha2_128f | baseline → buffer_peeled | sign | 43.1255 | 44.1151 | 🔴 +2.29% | 🟢 -5.17% | 4103200.0 | 1373568.0 | 🟢 -66.52% |
| sha2_128f | baseline → object_hoist | verify | 2.8254 | 2.8083 | 🟢 -0.61% | 🟢 -1.00% | 272819.2 | 272819.2 | ⚪ 0.00% |
| sha2_128f | baseline → field_rewrite | verify | 2.7881 | 2.7717 | 🟢 -0.59% | 🟢 -0.64% | 272819.2 | 272819.2 | ⚪ 0.00% |
| sha2_128f | baseline → two_addresses | verify | 2.7858 | 2.8132 | 🔴 +0.98% | 🔴 +1.01% | 272819.2 | 272819.2 | ⚪ 0.00% |
| sha2_128f | baseline → buffer | verify | 2.7789 | 2.8642 | 🔴 +3.07% | 🔴 +2.98% | 272819.2 | 106169.6 | 🟢 -61.08% |
| sha2_128f | buffer → buffer_peeled | verify | 2.9889 | 2.5633 | 🟢 -14.24% | 🟢 -14.04% | 106203.6 | 106169.6 | 🟢 -0.03% |
| sha2_128f | baseline → buffer_peeled | verify | 2.8147 | 2.7658 | 🟢 -1.74% | 🟢 -1.70% | 272819.2 | 106203.6 | 🟢 -61.07% |
| shake_128f | baseline → object_hoist | keygen | 1.6203 | 1.6218 | 🔴 +0.09% | 🔴 +0.06% | 170792.0 | 153384.0 | 🟢 -10.19% |
| shake_128f | baseline → field_rewrite | keygen | 1.6286 | 1.6283 | 🟢 -0.02% | 🔴 +0.01% | 170792.0 | 170792.0 | ⚪ 0.00% |
| shake_128f | baseline → two_addresses | keygen | 1.6191 | 1.5959 | 🟢 -1.43% | 🟢 -1.42% | 170792.0 | 153896.0 | 🟢 -9.89% |
| shake_128f | baseline → buffer | keygen | 1.6229 | 1.6346 | 🔴 +0.72% | 🔴 +0.66% | 170792.0 | 45352.0 | 🟢 -73.45% |
| shake_128f | buffer → buffer_peeled | keygen | 1.6528 | 1.5794 | 🟢 -4.44% | 🟢 -4.33% | 45352.0 | 45352.0 | ⚪ 0.00% |
| shake_128f | baseline → buffer_peeled | keygen | 1.6114 | 1.5796 | 🟢 -1.97% | 🟢 -2.06% | 170792.0 | 45352.0 | 🟢 -73.45% |
| shake_128f | baseline → object_hoist | sign | 36.2317 | 36.1245 | 🟢 -0.30% | 🔴 +0.03% | 4096804.0 | 3761600.0 | 🟢 -8.18% |
| shake_128f | baseline → field_rewrite | sign | 36.1154 | 36.0130 | 🟢 -0.28% | 🟢 -0.33% | 4096804.0 | 4096704.0 | ⚪ 0.00% |
| shake_128f | baseline → two_addresses | sign | 36.0179 | 36.1925 | 🔴 +0.48% | 🔴 +0.58% | 4096804.0 | 3770400.0 | 🟢 -7.97% |
| shake_128f | baseline → buffer | sign | 36.3560 | 35.9279 | 🟢 -1.18% | 🟢 -0.99% | 4096803.2 | 1365988.0 | 🟢 -66.66% |
| shake_128f | buffer → buffer_peeled | sign | 36.0840 | 35.7835 | 🟢 -0.83% | 🟢 -0.79% | 1365920.8 | 1365922.4 | ⚪ 0.00% |
| shake_128f | baseline → buffer_peeled | sign | 36.0586 | 35.8714 | 🟢 -0.52% | 🟢 -0.37% | 4096736.0 | 1365988.8 | 🟢 -66.66% |
| shake_128f | baseline → object_hoist | verify | 2.3360 | 2.3431 | 🔴 +0.30% | 🔴 +0.31% | 271353.6 | 271353.6 | ⚪ 0.00% |
| shake_128f | baseline → field_rewrite | verify | 2.3277 | 2.3513 | 🔴 +1.01% | 🔴 +0.94% | 271300.8 | 271353.6 | 🔴 +0.02% |
| shake_128f | baseline → two_addresses | verify | 2.3294 | 2.3336 | 🔴 +0.18% | 🔴 +0.15% | 271353.6 | 271353.6 | ⚪ 0.00% |
| shake_128f | baseline → buffer | verify | 2.3235 | 2.3432 | 🔴 +0.85% | 🔴 +0.87% | 271300.8 | 105356.8 | 🟢 -61.17% |
| shake_128f | buffer → buffer_peeled | verify | 2.3368 | 2.3001 | 🟢 -1.57% | 🟢 -1.66% | 105356.8 | 105356.8 | ⚪ 0.00% |
| shake_128f | baseline → buffer_peeled | verify | 2.3301 | 2.2897 | 🟢 -1.73% | 🟢 -1.76% | 271300.8 | 105424.8 | 🟢 -61.14% |

## WOTS Java 25 selected higher-size followup

| Parameter | Reference → candidate | Action | Original ms | Changed ms | Time Δ | CPU Δ | Original B/op | Changed B/op | Allocation Δ |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| sha2_192f | baseline → object_hoist | keygen | 2.7339 | 2.7482 | 🔴 +0.52% | 🟢 -0.04% | 303976.0 | 278376.0 | 🟢 -8.42% |
| sha2_192f | baseline → field_rewrite | keygen | 2.7617 | 2.6849 | 🟢 -2.78% | 🟢 -2.51% | 303976.0 | 303976.0 | ⚪ 0.00% |
| sha2_192f | baseline → two_addresses | keygen | 2.7883 | 2.7194 | 🟢 -2.47% | 🟢 -2.54% | 303976.0 | 278888.0 | 🟢 -8.25% |
| sha2_192f | baseline → buffer | keygen | 2.7185 | 2.7304 | 🔴 +0.44% | 🔴 +0.42% | 303976.0 | 75496.0 | 🟢 -75.16% |
| sha2_192f | baseline → object_hoist | sign | 69.4167 | 69.4024 | 🟢 -0.02% | 🟢 -0.07% | 8178611.2 | 7685811.2 | 🟢 -6.03% |
| sha2_192f | baseline → field_rewrite | sign | 69.6087 | 69.3973 | 🟢 -0.30% | 🟢 -0.29% | 8178611.2 | 8178611.2 | ⚪ 0.00% |
| sha2_192f | baseline → two_addresses | sign | 75.3850 | 69.2520 | 🟢 -8.14% | 🟢 -1.64% | 8178611.2 | 7697075.2 | 🟢 -5.89% |
| sha2_192f | baseline → buffer | sign | 70.5545 | 69.6261 | 🟢 -1.32% | 🟢 -0.03% | 8178611.2 | 3205555.2 | 🟢 -60.81% |
| sha2_192f | baseline → object_hoist | verify | 3.9696 | 4.4533 | 🔴 +12.19% | 🔴 +11.83% | 475952.0 | 475952.0 | ⚪ 0.00% |
| sha2_192f | baseline → field_rewrite | verify | 4.0325 | 4.2855 | 🔴 +6.27% | 🔴 +6.32% | 475952.0 | 475952.0 | ⚪ 0.00% |
| sha2_192f | baseline → two_addresses | verify | 4.0442 | 4.1158 | 🔴 +1.77% | 🔴 +1.79% | 475952.0 | 475952.0 | ⚪ 0.00% |
| sha2_192f | baseline → buffer | verify | 4.2994 | 4.0384 | 🟢 -6.07% | 🟢 -5.90% | 475952.0 | 170716.0 | 🟢 -64.13% |
| sha2_256f | baseline → object_hoist | keygen | 6.6894 | 6.9782 | 🔴 +4.32% | 🔴 +3.48% | 937944.0 | 870360.0 | 🟢 -7.21% |
| sha2_256f | baseline → field_rewrite | keygen | 6.7416 | 7.1698 | 🔴 +6.35% | 🔴 +5.94% | 937944.0 | 937944.0 | ⚪ 0.00% |
| sha2_256f | baseline → two_addresses | keygen | 6.7393 | 7.1542 | 🔴 +6.16% | 🔴 +5.62% | 937944.0 | 871384.0 | 🟢 -7.10% |
| sha2_256f | baseline → buffer | keygen | 6.6749 | 7.3143 | 🔴 +9.58% | 🔴 +6.90% | 937944.0 | 217560.0 | 🟢 -76.80% |
| sha2_256f | baseline → object_hoist | sign | 141.5028 | 139.9584 | 🟢 -1.09% | 🟢 -1.07% | 19531123.2 | 18454003.2 | 🟢 -5.51% |
| sha2_256f | baseline → field_rewrite | sign | 138.9224 | 142.7513 | 🔴 +2.76% | 🔴 +2.20% | 19531123.2 | 19531123.2 | ⚪ 0.00% |
| sha2_256f | baseline → two_addresses | sign | 142.4184 | 139.6924 | 🟢 -1.91% | 🟢 -1.75% | 19528955.2 | 18471411.2 | 🟢 -5.42% |
| sha2_256f | baseline → buffer | sign | 141.5100 | 140.8168 | 🟢 -0.49% | 🟢 -0.01% | 19531123.2 | 7353451.2 | 🟢 -62.35% |
| sha2_256f | baseline → object_hoist | verify | 4.1390 | 4.1875 | 🔴 +1.17% | 🔴 +1.14% | 580288.0 | 580288.0 | ⚪ 0.00% |
| sha2_256f | baseline → field_rewrite | verify | 4.1067 | 4.3819 | 🔴 +6.70% | 🔴 +6.66% | 580288.0 | 580288.0 | ⚪ 0.00% |
| sha2_256f | baseline → two_addresses | verify | 4.2311 | 4.1526 | 🟢 -1.85% | 🟢 -2.01% | 580288.0 | 580288.0 | ⚪ 0.00% |
| sha2_256f | baseline → buffer | verify | 4.1566 | 4.8154 | 🔴 +15.85% | 🔴 +15.73% | 580288.0 | 214936.0 | 🟢 -62.96% |
| shake_192f | baseline → object_hoist | keygen | 2.3789 | 2.3959 | 🔴 +0.71% | 🔴 +0.30% | 302744.0 | 277144.0 | 🟢 -8.46% |
| shake_192f | baseline → field_rewrite | keygen | 2.3828 | 2.4053 | 🔴 +0.94% | 🔴 +0.45% | 302744.0 | 302744.0 | ⚪ 0.00% |
| shake_192f | baseline → two_addresses | keygen | 2.3483 | 2.3349 | 🟢 -0.57% | 🟢 -0.58% | 302744.0 | 277656.0 | 🟢 -8.29% |
| shake_192f | baseline → buffer | keygen | 2.4010 | 2.4502 | 🔴 +2.05% | 🔴 +1.93% | 302744.0 | 74264.0 | 🟢 -75.47% |
| shake_192f | baseline → object_hoist | sign | 59.3166 | 59.2614 | 🟢 -0.09% | 🟢 -0.04% | 8173376.0 | 7680576.0 | 🟢 -6.03% |
| shake_192f | baseline → field_rewrite | sign | 59.2086 | 58.7652 | 🟢 -0.75% | 🟢 -0.73% | 8173376.0 | 8173376.0 | ⚪ 0.00% |
| shake_192f | baseline → two_addresses | sign | 59.1313 | 58.6074 | 🟢 -0.89% | 🟢 -0.61% | 8173376.0 | 7691840.0 | 🟢 -5.89% |
| shake_192f | baseline → buffer | sign | 59.6606 | 58.8246 | 🟢 -1.40% | 🟢 -0.55% | 8173376.0 | 3200288.0 | 🟢 -60.84% |
| shake_192f | baseline → object_hoist | verify | 3.3642 | 3.3713 | 🔴 +0.21% | 🔴 +0.22% | 469252.0 | 469255.2 | ⚪ 0.00% |
| shake_192f | baseline → field_rewrite | verify | 3.3875 | 3.3670 | 🟢 -0.61% | 🟢 -0.61% | 469264.0 | 469285.6 | ⚪ 0.00% |
| shake_192f | baseline → two_addresses | verify | 3.3950 | 3.4041 | 🔴 +0.27% | 🔴 +0.25% | 469241.6 | 469246.4 | ⚪ 0.00% |
| shake_192f | baseline → buffer | verify | 3.3556 | 3.4582 | 🔴 +3.06% | 🔴 +2.92% | 469240.0 | 168578.4 | 🟢 -64.07% |
| shake_256f | baseline → object_hoist | keygen | 6.2378 | 6.1936 | 🟢 -0.71% | 🟢 -0.66% | 936712.0 | 869128.0 | 🟢 -7.22% |
| shake_256f | baseline → field_rewrite | keygen | 6.4017 | 6.1692 | 🟢 -3.63% | 🟢 -2.38% | 936712.0 | 936712.0 | ⚪ 0.00% |
| shake_256f | baseline → two_addresses | keygen | 6.2212 | 6.1679 | 🟢 -0.86% | 🟢 -0.90% | 936712.0 | 870152.0 | 🟢 -7.11% |
| shake_256f | baseline → buffer | keygen | 6.1971 | 6.3205 | 🔴 +1.99% | 🔴 +2.03% | 936712.0 | 216328.0 | 🟢 -76.91% |
| shake_256f | baseline → object_hoist | sign | 122.8744 | 121.8077 | 🟢 -0.87% | 🟢 -0.36% | 19523671.2 | 18446551.2 | 🟢 -5.52% |
| shake_256f | baseline → field_rewrite | sign | 121.6279 | 121.4271 | 🟢 -0.17% | 🟢 -0.23% | 19523671.2 | 19523671.2 | ⚪ 0.00% |
| shake_256f | baseline → two_addresses | sign | 121.6038 | 121.6026 | ⚪ 0.00% | 🟢 -0.08% | 19523671.2 | 18459859.2 | 🟢 -5.45% |
| shake_256f | baseline → buffer | sign | 121.6409 | 122.1810 | 🔴 +0.44% | 🔴 +0.62% | 19523671.2 | 7346916.0 | 🟢 -62.37% |
| shake_256f | baseline → object_hoist | verify | 3.4836 | 3.4879 | 🔴 +0.12% | 🔴 +0.11% | 576250.4 | 576250.4 | ⚪ 0.00% |
| shake_256f | baseline → field_rewrite | verify | 3.5016 | 3.4705 | 🟢 -0.89% | 🟢 -0.88% | 576250.4 | 576250.4 | ⚪ 0.00% |
| shake_256f | baseline → two_addresses | verify | 3.5790 | 3.4877 | 🟢 -2.55% | 🟢 -1.25% | 576250.4 | 576250.4 | ⚪ 0.00% |
| shake_256f | baseline → buffer | verify | 3.5149 | 3.5778 | 🔴 +1.79% | 🔴 +1.84% | 576250.4 | 213000.8 | 🟢 -63.04% |

