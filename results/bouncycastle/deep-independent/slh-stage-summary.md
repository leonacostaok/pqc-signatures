# SLH stage diagnostic summary

These are medians of within-process round means. Paired ratios are original / changed wall time. Kernels overlap and must not be added; warmup and repeated four-key scope differ from a full-operation API call. Both forks are retained, including controls and losses. The recovered collection retains quantized zero thread-CPU samples.

sha2_128f

| Stage | Original µs | Changed µs | Fork 0 ratio | Fork 1 ratio |
|---|---:|---:|---:|---:|
| verify.decode | 40.708 | 40.848 | 1.01117× | 0.98237× |
| sign.prf_msg | 5.602 | 5.606 | 0.96282× | 1.03555× |
| hmsg | 8.201 | 6.263 | 1.58238× | 1.01830× |
| fors.indices | 14.770 | 17.224 | 0.84869× | 0.86329× |
| verify.fors_leaves | 14.373 | 16.959 | 0.86871× | 0.82709× |
| verify.fors_auth | 110.511 | 114.629 | 0.98298× | 0.94532× |
| verify.fors_compress | 4.136 | 4.329 | 0.96363× | 0.94707× |
| verify.fors | 166.515 | 167.898 | 1.00557× | 0.97826× |
| verify.wots_chains | 2789.474 | 2771.474 | 0.89757× | 1.11468× |
| verify.wots_compress | 93.042 | 92.738 | 1.00047× | 1.00597× |
| verify.wots | 2611.526 | 2937.084 | 0.85742× | 0.92118× |
| verify.xmss_auth | 31.685 | 34.513 | 0.92193× | 0.91437× |
| verify.hypertree | 2751.609 | 2867.758 | 1.02780× | 0.89218× |
| sign.fors | 2661.453 | 2738.474 | 0.99653× | 0.94721× |
| sign.wots | 2777.917 | 3082.813 | 0.92615× | 0.87585× |
| sign.xmss_auth | 36409.008 | 35757.117 | 1.03206× | 1.00449× |
| sign.hypertree | 40935.479 | 41300.190 | 0.99786× | 0.98470× |
| sign.serialize | 10.050 | 7.083 | 1.54367× | 1.29231× |

shake_128f

| Stage | Original µs | Changed µs | Fork 0 ratio | Fork 1 ratio |
|---|---:|---:|---:|---:|
| verify.decode | 40.714 | 39.921 | 1.04399× | 0.99595× |
| sign.prf_msg | 1.764 | 1.760 | 0.99194× | 1.01309× |
| hmsg | 2.050 | 2.062 | 0.98313× | 1.00590× |
| fors.indices | 26.105 | 19.582 | 0.55184× | 2.49250× |
| verify.fors_leaves | 18.626 | 50.077 | 0.27598× | 0.98508× |
| verify.fors_auth | 102.817 | 107.639 | 0.89687× | 1.01992× |
| verify.fors_compress | 2.466 | 2.554 | 0.89878× | 1.03293× |
| verify.fors | 149.451 | 154.401 | 0.95711× | 0.97909× |
| verify.wots_chains | 2095.854 | 2090.935 | 0.99228× | 1.01238× |
| verify.wots_compress | 50.653 | 51.399 | 1.01316× | 0.96097× |
| verify.wots | 2126.305 | 2152.023 | 0.98297× | 0.99313× |
| verify.xmss_auth | 28.311 | 29.462 | 0.97279× | 0.94936× |
| verify.hypertree | 2161.599 | 2197.266 | 0.97968× | 0.98784× |
| sign.fors | 2358.222 | 2441.096 | 0.96670× | 0.96542× |
| sign.wots | 2269.526 | 2349.112 | 0.97630× | 0.95614× |
| sign.xmss_auth | 30589.648 | 30985.029 | 0.98367× | 0.99079× |
| sign.hypertree | 34902.726 | 35369.617 | 0.98853× | 0.98506× |
| sign.serialize | 8.152 | 12.536 | 0.70155× | 0.58957× |
