# Performance comparison handoff

Branch: `docs/performance-comparison`, based on `929d442`.

Generated `docs/audit/complete-performance-comparison.md` and corresponding CSV with `common/report-performance-tradeoffs.py`. There are 102 library/parameter rows and 309 action cells, including the three Rust combined-operation cells. 117 cells have measured coordinated ten-key results; 192 are explicitly unmeasured. Color indicates observed metric direction, not significance. Memory notes refer to the audited patches; newer BC alternatives have a separate table and local evidence commit references.

Verified original raw input hashes, cell count, percentages, and blank unknown values. No new benchmark or production change. Missing uniform all-library measurements, whole-operation peak stack/heap and GC-pressure tests remain future measurement work, not fabricated zeroes.
