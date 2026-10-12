# Individual compiler stack frames

Apple clang 21, arm64, `-O3 -fstack-usage`; same flags on both versions. These are individual function frames, not complete call-chain maxima. The source rows and compile commands are retained alongside this table.

| Function | Original local frame | Candidate local frame | Delta |
|---|---:|---:|---:|
| `sha2_224` | 176 B | 304 B | +128 B |
| `sha2_224_init` | 0 B | 0 B | +0 B |
| `sha2_256` | 176 B | 304 B | +128 B |
| `sha2_256_compress` | 160 B | 144 B | -16 B |
| `sha2_256_copy` | 0 B | 0 B | +0 B |
| `sha2_256_final_len` | 48 B | 160 B | +112 B |
| `sha2_256_final_pad` | 32 B | 144 B | +112 B |
| `sha2_256_init` | 0 B | 0 B | +0 B |
| `sha2_256_update` | 64 B | 176 B | +112 B |
| `sha2_384` | 320 B | 544 B | +224 B |
| `sha2_384_init` | 0 B | 0 B | +0 B |
| `sha2_512` | 320 B | 544 B | +224 B |
| `sha2_512_224` | 320 B | 544 B | +224 B |
| `sha2_512_224_init` | 0 B | 0 B | +0 B |
| `sha2_512_256` | 320 B | 544 B | +224 B |
| `sha2_512_256_init` | 0 B | 0 B | +0 B |
| `sha2_512_compress` | 192 B | 256 B | +64 B |
| `sha2_512_copy` | 0 B | 0 B | +0 B |
| `sha2_512_final_len` | 48 B | 272 B | +224 B |
| `sha2_512_final_pad` | 32 B | 272 B | +240 B |
| `sha2_512_init` | 0 B | 0 B | +0 B |
| `sha2_512_update` | 64 B | 304 B | +240 B |
