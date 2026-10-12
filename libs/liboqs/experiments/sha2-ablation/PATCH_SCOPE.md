# What can be made smaller

The full candidate `b14f1b616f938698ebc0bf8b75b3736c30e1502c` adds 257 lines across eight files, but its runtime behavior is concentrated in 64 added lines across two hash sources. The two backend choices are separable, so the ablation measures each independently instead of treating the entire diff as one indivisible optimization.

| Part of the original full diff | Added lines | Purpose |
|---|---:|---|
| `sha2_256.c` and `sha2_512.c` | 64 | Translate cached chaining states, call the OpenSSL compression implementation, and cleanse the temporary state; preserve portable fallbacks and instrumentation |
| Generated SLH CMake and its template | 6 | Make the selected OpenSSL headers available, including nonstandard installations, and preserve that setting on regeneration |
| Vendored-source patch | 114 | Reapply the same runtime edits after refreshing the upstream source |
| Test source and test integration | 73 | Exercise incremental hashing, copied states, padding boundaries, and the selected build configurations |

[The runtime-only patch](minimal-runtime.patch) contains three files and 67 additions: both hash sources and the generated SLH CMake include setting. Its exact source/CMake diff sections match the full patch; [the recorded comparison](evidence/minimal-runtime-proof.json) verifies this. The artifact demonstrates the small runtime scope. It is not a separately timed implementation or a recommendation to delete maintained tests and regeneration support from the PR.

The importer renders the CMake template into `CMakeLists.txt` at `scripts/copy_from_upstream/copy_from_slh_dsa_c.py:210–227`, walks and applies the vendored patch directory at `237–241`, and reapplies those patches after regeneration at `337–338`. Omitting the template or vendored patch would let a source refresh lose the optimization or its include configuration. These locations were inspected in the pinned original source, which is unchanged in the full candidate.

The existing generic SHA-256 incremental API in `src/common/sha2/sha2_ossl.c:51–85` allocates and initializes an `EVP_MD_CTX`, updates it with message bytes, and frees it after finalization or release. It does not expose the private chaining-state injection used by these SLH-DSA cached-prefix compression functions. Substituting that API would require a broader state/API change, with separate correctness and performance work; there is no demonstrated one-line replacement providing the measured behavior.

Both reduced variants retain the full candidate's initialization, endian conversion, compile-time OpenSSL/dlopen/deprecated-API guards, instrumentation handling, and non-optimizable cleansing. Removing those to reduce line count would change safety or supported-configuration behavior. The measured question is whether omitting one complete backend preserves the full patch's signing and verification gains; [the protocol](README.md) predeclares the comparison and its limits.
