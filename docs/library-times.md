# Actual operation times by library

Compare the exact parameter set and action below: ML-DSA-44 is separate from ML-DSA-65/87; SLH-DSA SHA2 is separate from SHAKE, and fast (`f`) from small-signature (`s`) sets. All times are milliseconds per operation; lower is better. 0.1000 ms = 100 microseconds.

**These are observed times from different protocols, not a controlled cross-library ranking.** The tables make the existing absolute values easy to compare, but cannot establish which implementation is intrinsically faster. Fixtures, key representations, setup boundaries, warmup, sample counts and statistics differ. In particular, Rust ML-DSA keygen is construction from a seed; verification can use its existing expanded/cached key, unlike decoding a fresh serialized key. Short JVM warmup in the ten-key study is not steady-state Java throughput. Close values do not establish a winner.

Original uses the unpatched side of each selected study. Selected patch uses that study's candidate, even when slower, and retains baseline-only observations where no candidate was measured (marked B). It is not a best-of-all-experiments selection and does not imply the patch is merged or available in a release. The later Bouncy Castle NTT/WOTS experiments are [reported separately](bouncycastle/alternative-comparison.md); their different runtime/corpus results are not substituted here.

[Full source data and statistics](../results/library-times/comparison.csv) · [Source hashes and numerical minima](../results/library-times/comparison.json) · [Provider revisions and patches](provider-improvements.md) · [Measurement boundaries](ten-key-order.md) · [Memory tradeoffs](audit/complete-performance-comparison.md). This report reformats saved evidence; no new timing experiment was run.

## Lowest recorded times

Each cell gives the library and its lowest numerical observation for that exact action/parameter. † means another recorded value is within 5%; this is a proximity flag, not a confidence interval or tie test. No sample was removed. Falcon is shown only for supported selected implementations and is not interchangeable with ML-DSA/SLH-DSA.

### Original implementations

| Exact signature | Keygen / construction (ms) | Sign (ms) | Verify (ms) |
|---|---:|---:|---:|
| ML-DSA-44 | liboqs 0.0382 | liboqs 0.0688 | RustCrypto 0.0368 |
| ML-DSA-65 | liboqs 0.0666 | liboqs 0.1126 | RustCrypto 0.0527 |
| ML-DSA-87 | liboqs 0.1140 | liboqs 0.2707 | CIRCL 0.0847 † |
| SLH-DSA-SHA2-128f | OpenSSL 0.2454 † | RustCrypto 5.6878 † | RustCrypto 0.3538 † |
| SLH-DSA-SHA2-128s | OpenSSL 15.4981 † | RustCrypto 118.1642 † | RustCrypto 0.1211 |
| SLH-DSA-SHA2-192f | OpenSSL 0.3378 | RustCrypto 10.1841 † | OpenSSL 0.5665 † |
| SLH-DSA-SHA2-192s | RustCrypto 22.9919 | RustCrypto 237.0305 | RustCrypto 0.2099 |
| SLH-DSA-SHA2-256f | OpenSSL 0.9334 † | RustCrypto 21.1103 | RustCrypto 0.5956 † |
| SLH-DSA-SHA2-256s | OpenSSL 14.4468 | RustCrypto 222.7785 | RustCrypto 0.3038 |
| SLH-DSA-SHAKE-128f | RustCrypto 1.0472 | RustCrypto 23.7768 | RustCrypto 1.4324 |
| SLH-DSA-SHAKE-128s | RustCrypto 64.7189 | RustCrypto 493.9892 | RustCrypto 0.4882 |
| SLH-DSA-SHAKE-192f | RustCrypto 1.5062 | RustCrypto 39.1354 | RustCrypto 2.1187 |
| SLH-DSA-SHAKE-192s | RustCrypto 96.6676 | RustCrypto 876.8538 | RustCrypto 0.7436 |
| SLH-DSA-SHAKE-256f | RustCrypto 4.0220 | RustCrypto 81.0758 | RustCrypto 2.1617 |
| SLH-DSA-SHAKE-256s | RustCrypto 64.3379 | RustCrypto 771.5614 | RustCrypto 1.0765 |
| Falcon-512 | liboqs 6.0430 | liboqs 0.2020 | liboqs 0.0375 |
| Falcon-1024 | liboqs 20.1960 | liboqs 0.3960 | liboqs 0.0708 |

### Selected patches, baseline where no patch was measured

| Exact signature | Keygen / construction (ms) | Sign (ms) | Verify (ms) |
|---|---:|---:|---:|
| ML-DSA-44 | liboqs 0.0382 | liboqs 0.0688 | RustCrypto 0.0368 |
| ML-DSA-65 | liboqs 0.0666 | liboqs 0.1126 | RustCrypto 0.0528 |
| ML-DSA-87 | liboqs 0.1140 | liboqs 0.2707 | RustCrypto 0.0784 |
| SLH-DSA-SHA2-128f | liboqs 0.2111 | liboqs 5.0798 | liboqs 0.3094 |
| SLH-DSA-SHA2-128s | liboqs 13.5766 | liboqs 107.1130 | liboqs 0.1097 |
| SLH-DSA-SHA2-192f | liboqs 0.3164 | liboqs 9.3152 † | liboqs 0.4994 |
| SLH-DSA-SHA2-192s | liboqs 20.2737 † | liboqs 218.1679 † | liboqs 0.1940 † |
| SLH-DSA-SHA2-256f | liboqs 0.8419 | liboqs 19.1816 † | liboqs 0.5126 |
| SLH-DSA-SHA2-256s | liboqs 13.4244 | OpenSSL 202.8542 † | liboqs 0.2777 † |
| SLH-DSA-SHAKE-128f | RustCrypto 1.0472 | RustCrypto 23.7768 | RustCrypto 1.4324 |
| SLH-DSA-SHAKE-128s | RustCrypto 64.7189 | RustCrypto 493.9892 | RustCrypto 0.4882 |
| SLH-DSA-SHAKE-192f | RustCrypto 1.5062 | RustCrypto 39.1354 | RustCrypto 2.1187 |
| SLH-DSA-SHAKE-192s | RustCrypto 96.6676 | RustCrypto 876.8538 | RustCrypto 0.7436 |
| SLH-DSA-SHAKE-256f | RustCrypto 4.0220 | RustCrypto 81.0758 | RustCrypto 2.1617 |
| SLH-DSA-SHAKE-256s | RustCrypto 64.3379 | RustCrypto 771.5614 | RustCrypto 1.0765 |
| Falcon-512 | liboqs 6.0430 | liboqs 0.2020 | liboqs 0.0375 |
| Falcon-1024 | liboqs 20.1960 | liboqs 0.3960 | liboqs 0.0708 |

## All libraries and actions

🟢 marks the lowest recorded number in that view/parameter/action, not a proven performance advantage. B = baseline-only value reused in both views; — = unsupported by the selected build. Each library name links to its saved source for that parameter. All languages, including interpreted/JIT/native runtime costs, are represented as measured.

### ML-DSA-44

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/ten-key-order/independent-check.json) | TypeScript/JavaScript | 1.6346 | 9.0638 | 2.0249 | 1.3137 | 7.7540 | 1.7641 |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 🟢 0.0382 B | 🟢 0.0688 B | 0.0388 B | 🟢 0.0382 B | 🟢 0.0688 B | 0.0388 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 0.0658 B | 0.2385 B | 0.0670 B | 0.0658 B | 0.2385 B | 0.0670 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 0.1154 B | 0.2468 B | 0.0456 B | 0.1154 B | 0.2468 B | 0.0456 B |
| [RustCrypto](../results/ten-key-order/independent-check.json) | Rust | 0.1209 | 0.1992 | 🟢 0.0368 | 0.1057 | 0.1901 | 🟢 0.0368 |
| [Bouncy Castle](../results/bouncycastle/completion/result.json) | Java | 0.1242 B | 0.3635 B | 0.1036 B | 0.1242 B | 0.3635 B | 0.1036 B |

### ML-DSA-65

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/ten-key-order/independent-check.json) | TypeScript/JavaScript | 2.4287 | 23.2649 | 3.0044 | 2.0462 | 20.3131 | 2.6266 |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 🟢 0.0666 B | 🟢 0.1126 B | 0.0641 B | 🟢 0.0666 B | 🟢 0.1126 B | 0.0641 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 0.1263 B | 0.4198 B | 0.1019 B | 0.1263 B | 0.4198 B | 0.1019 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 0.2042 B | 0.2575 B | 0.0605 B | 0.2042 B | 0.2575 B | 0.0605 B |
| [RustCrypto](../results/ten-key-order/independent-check.json) | Rust | 0.2307 | 0.7612 | 🟢 0.0527 | 0.1937 | 0.7540 | 🟢 0.0528 |
| [Bouncy Castle](../results/bouncycastle/completion/result.json) | Java | 0.1851 B | 0.5540 B | 0.1457 B | 0.1851 B | 0.5540 B | 0.1457 B |

### ML-DSA-87

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/ten-key-order/independent-check.json) | TypeScript/JavaScript | 3.8107 | 22.5102 | 4.6070 | 3.1080 | 18.7206 | 3.8824 |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 🟢 0.1140 B | 🟢 0.2707 B | 0.1097 B | 🟢 0.1140 B | 🟢 0.2707 B | 0.1097 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 0.1676 B | 0.5471 B | 0.1633 B | 0.1676 B | 0.5471 B | 0.1633 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 0.3003 B | 0.5423 B | 🟢 0.0847 B | 0.3003 B | 0.5423 B | 0.0847 B |
| [RustCrypto](../results/ten-key-order/independent-check.json) | Rust | 0.3129 | 0.7087 | 0.0862 | 0.2635 | 0.7002 | 🟢 0.0784 |
| [Bouncy Castle](../results/bouncycastle/completion/result.json) | Java | 0.2507 B | 0.7944 B | 0.2158 B | 0.2507 B | 0.7944 B | 0.2158 B |

### SLH-DSA-SHA2-128f

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 3.7616 B | 83.1033 B | 5.5331 B | 3.7616 B | 83.1033 B | 5.5331 B |
| [liboqs](../results/ten-key-order/independent-check.json) | C | 1.1481 | 26.8591 | 1.6403 | 🟢 0.2111 | 🟢 5.0798 | 🟢 0.3094 |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 🟢 0.2454 | 5.7061 | 0.3615 | 0.2453 | 5.6914 | 0.3571 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 0.4428 | 10.1285 | 0.6190 | 0.3295 | 7.6859 | 0.4600 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 0.2478 B | 🟢 5.6878 B | 🟢 0.3538 B | 0.2478 B | 5.6878 B | 0.3538 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 1.9289 | 44.2063 | 2.8211 | 1.8976 | 43.9344 | 2.8244 |

### SLH-DSA-SHA2-128s

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 226.4017 B | 1728.2061 B | 2.1392 B | 226.4017 B | 1728.2061 B | 2.1392 B |
| [liboqs](../results/ten-key-order/independent-check.json) | C | 73.4345 | 561.9969 | 0.5690 | 🟢 13.5766 | 🟢 107.1130 | 🟢 0.1097 |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 🟢 15.4981 | 119.0584 | 0.1349 | 15.3950 | 119.1688 | 0.1323 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 28.0791 | 213.2795 | 0.2249 | 20.9377 | 162.4563 | 0.1733 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 15.5011 B | 🟢 118.1642 B | 🟢 0.1211 B | 15.5011 B | 118.1642 B | 0.1211 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 105.1394 | 805.4440 | 1.0384 | 104.8276 | 802.9421 | 0.9723 |

### SLH-DSA-SHA2-192f

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 5.4548 B | 150.1405 B | 8.9098 B | 5.4548 B | 150.1405 B | 8.9098 B |
| [liboqs](../results/ten-key-order/independent-check.json) | C | 1.6638 | 43.9069 | 2.3822 | 🟢 0.3164 | 🟢 9.3152 | 🟢 0.4994 |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 🟢 0.3378 | 10.3744 | 🟢 0.5665 | 0.3425 | 9.3652 | 0.5323 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 0.6500 | 18.6152 | 1.0073 | 0.4963 | 13.7012 | 0.7228 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 0.3636 B | 🟢 10.1841 B | 0.5695 B | 0.3636 B | 10.1841 B | 0.5695 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 2.6870 | 70.2566 | 3.9935 | 2.7003 | 70.6396 | 4.0114 |

### SLH-DSA-SHA2-192s

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 332.6020 B | 3472.2644 B | 3.5107 B | 332.6020 B | 3472.2644 B | 3.5107 B |
| [liboqs](../results/ten-key-order/independent-check.json) | C | 106.8767 | 988.6339 | 0.8249 | 🟢 20.2737 | 🟢 218.1679 | 🟢 0.1940 |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 30.5274 | 252.9485 | 0.2433 | 21.0928 | 219.6811 | 0.2027 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 41.8090 | 437.6655 | 0.3937 | 31.1002 | 318.2741 | 0.2789 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 22.9919 B | 🟢 237.0305 B | 🟢 0.2099 B | 22.9919 B | 237.0305 B | 0.2099 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 153.1777 | 1446.8049 | 1.4177 | 154.5493 | 1454.5750 | 1.3849 |

### SLH-DSA-SHA2-256f

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 14.5123 B | 318.1729 B | 9.2736 B | 14.5123 B | 318.1729 B | 9.2736 B |
| [liboqs](../results/ten-key-order/independent-check.json) | C | 4.4884 | 90.4062 | 2.4107 | 🟢 0.8419 | 🟢 19.1816 | 🟢 0.5126 |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 🟢 0.9334 | 22.2193 | 0.5960 | 0.8911 | 19.5554 | 0.5403 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 1.7387 | 38.6703 | 1.0396 | 1.2826 | 28.0619 | 0.7484 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 0.9664 B | 🟢 21.1103 B | 🟢 0.5956 B | 0.9664 B | 21.1103 B | 0.5956 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 7.1199 | 145.2968 | 4.3074 | 7.1582 | 146.1467 | 4.0951 |

### SLH-DSA-SHA2-256s

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 232.5009 B | 3299.3359 B | 4.8574 B | 232.5009 B | 3299.3359 B | 4.8574 B |
| [liboqs](../results/ten-key-order/independent-check.json) | C | 72.0602 | 876.1769 | 1.2058 | 🟢 13.4244 | 209.2582 | 🟢 0.2777 |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 🟢 14.4468 | 242.2261 | 0.3411 | 14.2042 | 🟢 202.8542 | 0.2897 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 28.3076 | 410.0928 | 0.5586 | 20.4276 | 295.1031 | 0.3910 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 15.4798 B | 🟢 222.7785 B | 🟢 0.3038 B | 15.4798 B | 222.7785 B | 0.3038 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 102.4512 | 1316.2605 | 2.0218 | 102.0342 | 1308.7956 | 1.9729 |

### SLH-DSA-SHAKE-128f

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 18.4705 B | 431.5676 B | 25.9229 B | 18.4705 B | 431.5676 B | 25.9229 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 1.3854 B | 32.6581 B | 1.9310 B | 1.3854 B | 32.6581 B | 1.9310 B |
| [OpenSSL](../results/ten-key-order/independent-check.json) | C | 1.3823 | 31.9683 | 1.9352 | 1.3688 | 31.8623 | 1.9348 |
| [CIRCL](../results/ten-key-order/independent-check.json) | Go | 2.3466 | 54.9281 | 3.3015 | 2.3333 | 54.6835 | 3.3034 |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 1.0472 B | 🟢 23.7768 B | 🟢 1.4324 B | 🟢 1.0472 B | 🟢 23.7768 B | 🟢 1.4324 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 1.5961 | 37.6826 | 2.4226 | 1.6039 | 37.3146 | 2.3518 |

### SLH-DSA-SHAKE-128s

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 1174.9686 B | 8965.6273 B | 9.2198 B | 1174.9686 B | 8965.6273 B | 9.2198 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 88.9836 B | 682.4874 B | 0.6898 B | 88.9836 B | 682.4874 B | 0.6898 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 86.6360 B | 660.4971 B | 0.6545 B | 86.6360 B | 660.4971 B | 0.6545 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 149.2955 B | 1132.5563 B | 1.1289 B | 149.2955 B | 1132.5563 B | 1.1289 B |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 64.7189 B | 🟢 493.9892 B | 🟢 0.4882 B | 🟢 64.7189 B | 🟢 493.9892 B | 🟢 0.4882 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 98.0790 | 753.8182 | 0.9343 | 97.8002 | 752.9866 | 0.8886 |

### SLH-DSA-SHAKE-192f

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 27.1738 B | 697.4401 B | 38.2225 B | 27.1738 B | 697.4401 B | 38.2225 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 2.0352 B | 54.0274 B | 2.8525 B | 2.0352 B | 54.0274 B | 2.8525 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 2.0117 B | 52.1160 B | 2.8136 B | 2.0117 B | 52.1160 B | 2.8136 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 3.3849 B | 86.9524 B | 4.6714 B | 3.3849 B | 86.9524 B | 4.6714 B |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 1.5062 B | 🟢 39.1354 B | 🟢 2.1187 B | 🟢 1.5062 B | 🟢 39.1354 B | 🟢 2.1187 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 2.3084 | 60.2786 | 3.3889 | 2.5142 | 64.7034 | 3.8610 |

### SLH-DSA-SHAKE-192s

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 1725.7343 B | 15530.4894 B | 13.0144 B | 1725.7343 B | 15530.4894 B | 13.0144 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 130.7803 B | 1227.2229 B | 0.9866 B | 130.7803 B | 1227.2229 B | 0.9866 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 128.7675 B | 1165.5120 B | 0.9596 B | 128.7675 B | 1165.5120 B | 0.9596 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 216.1610 B | 1938.6120 B | 1.5828 B | 216.1610 B | 1938.6120 B | 1.5828 B |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 96.6676 B | 🟢 876.8538 B | 🟢 0.7436 B | 🟢 96.6676 B | 🟢 876.8538 B | 🟢 0.7436 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 147.4909 | 1313.5396 | 1.3036 | 144.9719 | 1339.8492 | 1.2867 |

### SLH-DSA-SHAKE-256f

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 71.1408 B | 1433.1970 B | 38.7299 B | 71.1408 B | 1433.1970 B | 38.7299 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 5.4114 B | 112.6248 B | 2.9485 B | 5.4114 B | 112.6248 B | 2.9485 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 5.3088 B | 106.7432 B | 2.8544 B | 5.3088 B | 106.7432 B | 2.8544 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 8.7831 B | 175.6766 B | 4.6517 B | 8.7831 B | 175.6766 B | 4.6517 B |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 4.0220 B | 🟢 81.0758 B | 🟢 2.1617 B | 🟢 4.0220 B | 🟢 81.0758 B | 🟢 2.1617 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 6.1214 | 124.2847 | 3.5473 | 6.2048 | 125.1380 | 3.5157 |

### SLH-DSA-SHAKE-256s

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 1137.3259 B | 13606.4536 B | 19.6686 B | 1137.3259 B | 13606.4536 B | 19.6686 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 86.3954 B | 1105.5450 B | 1.4622 B | 86.3954 B | 1105.5450 B | 1.4622 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | 85.1052 B | 1017.8754 B | 1.4150 B | 85.1052 B | 1017.8754 B | 1.4150 B |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | 140.5422 B | 1666.9568 B | 2.3647 B | 140.5422 B | 1666.9568 B | 2.3647 B |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | 🟢 64.3379 B | 🟢 771.5614 B | 🟢 1.0765 B | 🟢 64.3379 B | 🟢 771.5614 B | 🟢 1.0765 B |
| [Bouncy Castle](../results/ten-key-order/independent-check.json) | Java | 96.7881 | 1169.2974 | 1.8686 | 98.7361 | 1170.6120 | 1.8510 |

### Falcon-512

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 108.0112 B | 3.8616 B | 0.7459 B | 108.0112 B | 3.8616 B | 0.7459 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 🟢 6.0430 B | 🟢 0.2020 B | 🟢 0.0375 B | 🟢 6.0430 B | 🟢 0.2020 B | 🟢 0.0375 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | — | — | — | — | — | — |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | — | — | — | — | — | — |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | — | — | — | — | — | — |
| [Bouncy Castle](../results/bouncycastle/completion/result.json) | Java | 10.4266 B | 1.3699 B | 0.2476 B | 10.4266 B | 1.3699 B | 0.2476 B |

### Falcon-1024

| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |
|---|---|---:|---:|---:|---:|---:|---:|
| [Noble](../results/noble/resource-followup/summary.json) | TypeScript/JavaScript | 438.0752 B | 6.7843 B | 1.4229 B | 438.0752 B | 6.7843 B | 1.4229 B |
| [liboqs](../results/liboqs/complete-indicators/summary.json) | C | 🟢 20.1960 B | 🟢 0.3960 B | 🟢 0.0708 B | 🟢 20.1960 B | 🟢 0.3960 B | 🟢 0.0708 B |
| [OpenSSL](../results/openssl/complete-indicators/summary.json) | C | — | — | — | — | — | — |
| [CIRCL](../results/circl/resource-followup/summary.json) | Go | — | — | — | — | — | — |
| [RustCrypto](../results/rustcrypto/completion/result.json) | Rust | — | — | — | — | — | — |
| [Bouncy Castle](../results/bouncycastle/completion/result.json) | Java | 29.7383 B | 2.4371 B | 0.4743 B | 29.7383 B | 2.4371 B | 0.4743 B |

## What would establish a fair ranking?

Run one shared corpus and message/context/entropy policy on the same host, with pinned builds and equivalent operation boundaries. Report expanded-key operations separately from import-plus-operation and fresh-key construction. Balance provider order across fresh processes, use adequate runtime-specific warmup, and retain distributions and resource costs. Existing evidence supports optimization comparisons within its studies; this report does not replace that matched cross-provider experiment.

