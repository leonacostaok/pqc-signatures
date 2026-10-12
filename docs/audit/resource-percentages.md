# Audited resource percentages

Resource change = 100 × (changed/original − 1). Negative means lower cost. Percentages with a zero baseline are undefined: inspect the absolute values. Large relative changes to small buffers are not large process-memory changes.

| Library | Parameter | Operation | Metric | Original → changed | Change | Measurement scope |
|---|---|---|---|---|---|---|
| noble | ML-DSA-44 | keygen | polynomial_payload_allocated | 54,272.00 → 37,888.00 bytes | 🟢 -30.19% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-44 | getPublicKey | polynomial_payload_allocated | 58,368.00 → 41,984.00 bytes | 🟢 -28.07% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-44 | sign | polynomial_payload_allocated | 180,821.33 → 124,842.67 bytes | 🟢 -30.96% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-44 | verify | polynomial_payload_allocated | 58,368.00 → 41,984.00 bytes | 🟢 -28.07% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-44 | invalidLength | polynomial_payload_allocated | 4,096.00 → 4,096.00 bytes | ⚪ +0.00% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-65 | keygen | polynomial_payload_allocated | 91,136.00 → 60,416.00 bytes | 🟢 -33.71% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-65 | getPublicKey | polynomial_payload_allocated | 97,280.00 → 66,560.00 bytes | 🟢 -31.58% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-65 | sign | polynomial_payload_allocated | 490,837.33 → 291,157.33 bytes | 🟢 -40.68% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-65 | verify | polynomial_payload_allocated | 97,280.00 → 66,560.00 bytes | 🟢 -31.58% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-65 | invalidLength | polynomial_payload_allocated | 6,144.00 → 6,144.00 bytes | ⚪ +0.00% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-87 | keygen | polynomial_payload_allocated | 154,624.00 → 97,280.00 bytes | 🟢 -37.09% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-87 | getPublicKey | polynomial_payload_allocated | 162,816.00 → 105,472.00 bytes | 🟢 -35.22% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-87 | sign | polynomial_payload_allocated | 670,549.33 → 359,936.00 bytes | 🟢 -46.32% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-87 | verify | polynomial_payload_allocated | 162,816.00 → 105,472.00 bytes | 🟢 -35.22% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-87 | invalidLength | polynomial_payload_allocated | 8,192.00 → 8,192.00 bytes | ⚪ +0.00% | Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak |
| noble | ML-DSA-44 | keygen | post_gc_heapUsed | 7,167,000.00 → 7,169,148.00 bytes | 🔴 +0.03% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | keygen | post_gc_arrayBuffers | 68,727.00 → 68,727.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | getPublicKey | post_gc_heapUsed | 7,130,648.00 → 7,132,716.00 bytes | 🔴 +0.03% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | getPublicKey | post_gc_arrayBuffers | 68,727.00 → 68,727.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | sign | post_gc_heapUsed | 7,253,384.00 → 7,257,532.00 bytes | 🔴 +0.06% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | sign | post_gc_arrayBuffers | 68,727.00 → 68,727.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | verify | post_gc_heapUsed | 7,211,916.00 → 7,215,480.00 bytes | 🔴 +0.05% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-44 | verify | post_gc_arrayBuffers | 68,727.00 → 68,727.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | keygen | post_gc_heapUsed | 7,164,224.00 → 7,174,056.00 bytes | 🔴 +0.14% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | keygen | post_gc_arrayBuffers | 80,731.00 → 80,731.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | getPublicKey | post_gc_heapUsed | 7,133,368.00 → 7,135,096.00 bytes | 🔴 +0.02% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | getPublicKey | post_gc_arrayBuffers | 80,731.00 → 80,731.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | sign | post_gc_heapUsed | 7,252,596.00 → 7,259,236.00 bytes | 🔴 +0.09% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | sign | post_gc_arrayBuffers | 80,731.00 → 80,731.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | verify | post_gc_heapUsed | 7,218,928.00 → 7,222,448.00 bytes | 🔴 +0.05% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-65 | verify | post_gc_arrayBuffers | 80,731.00 → 80,731.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | keygen | post_gc_heapUsed | 7,165,632.00 → 7,169,352.00 bytes | 🔴 +0.05% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | keygen | post_gc_arrayBuffers | 92,019.00 → 92,019.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | getPublicKey | post_gc_heapUsed | 7,123,824.00 → 7,128,168.00 bytes | 🔴 +0.06% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | getPublicKey | post_gc_arrayBuffers | 92,019.00 → 92,019.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | sign | post_gc_heapUsed | 7,256,272.00 → 7,265,232.00 bytes | 🔴 +0.12% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | sign | post_gc_arrayBuffers | 92,019.00 → 92,019.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | verify | post_gc_heapUsed | 7,210,976.00 → 7,216,936.00 bytes | 🔴 +0.08% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| noble | ML-DSA-87 | verify | post_gc_arrayBuffers | 92,019.00 → 92,019.00 bytes | ⚪ +0.00% | Median final process snapshot; includes harness/runtime/JIT, not operation peak |
| circl | SLH-DSA-SHA2-128f | keygen | allocated_bytes | 864.00 → 1,952.00 bytes | 🔴 +125.93% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128f | keygen | allocated_objects | 9.00 → 21.00 objects | 🔴 +133.33% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128f | sign | allocated_bytes | 28,506.67 → 29,605.33 bytes | 🔴 +3.85% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128f | sign | allocated_objects | 54.33 → 66.56 objects | 🔴 +22.49% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128f | verify | allocated_bytes | 9,130.67 → 10,218.67 bytes | 🔴 +11.92% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128f | verify | allocated_objects | 44.33 → 56.33 objects | 🔴 +27.07% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128s | keygen | allocated_bytes | 1,152.00 → 2,240.00 bytes | 🔴 +94.44% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128s | keygen | allocated_objects | 9.00 → 21.00 objects | 🔴 +133.33% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128s | sign | allocated_bytes | 16,192.00 → 17,280.00 bytes | 🔴 +6.72% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128s | sign | allocated_objects | 34.67 → 46.67 objects | 🔴 +34.62% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128s | verify | allocated_bytes | 6,474.67 → 7,562.67 bytes | 🔴 +16.80% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-128s | verify | allocated_objects | 24.33 → 36.33 objects | 🔴 +49.32% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192f | keygen | allocated_bytes | 1,216.00 → 2,592.00 bytes | 🔴 +113.16% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192f | keygen | allocated_objects | 9.00 → 21.00 objects | 🔴 +133.33% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192f | sign | allocated_bytes | 53,558.22 → 54,936.00 bytes | 🔴 +2.57% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192f | sign | allocated_objects | 54.56 → 66.44 objects | 🔴 +21.79% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192f | verify | allocated_bytes | 11,154.67 → 12,530.67 bytes | 🔴 +12.34% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192f | verify | allocated_objects | 44.33 → 56.33 objects | 🔴 +27.07% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192s | keygen | allocated_bytes | 1,552.00 → 2,928.00 bytes | 🔴 +88.66% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192s | keygen | allocated_objects | 9.00 → 21.00 objects | 🔴 +133.33% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192s | sign | allocated_bytes | 27,608.00 → 28,989.33 bytes | 🔴 +5.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192s | sign | allocated_objects | 38.67 → 50.78 objects | 🔴 +31.32% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192s | verify | allocated_bytes | 9,106.67 → 10,482.67 bytes | 🔴 +15.11% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-192s | verify | allocated_objects | 28.33 → 40.33 objects | 🔴 +42.35% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256f | keygen | allocated_bytes | 1,392.00 → 2,773.33 bytes | 🔴 +99.23% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256f | keygen | allocated_objects | 9.00 → 21.11 objects | 🔴 +134.57% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256f | sign | allocated_bytes | 71,488.00 → 72,869.33 bytes | 🔴 +1.93% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256f | sign | allocated_objects | 56.67 → 68.78 objects | 🔴 +21.37% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256f | verify | allocated_bytes | 12,506.67 → 13,882.67 bytes | 🔴 +11.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256f | verify | allocated_objects | 46.33 → 58.33 objects | 🔴 +25.90% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256s | keygen | allocated_bytes | 1,648.00 → 3,029.33 bytes | 🔴 +83.82% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256s | keygen | allocated_objects | 9.00 → 21.11 objects | 🔴 +134.57% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256s | sign | allocated_bytes | 46,224.00 → 47,600.00 bytes | 🔴 +2.98% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256s | sign | allocated_objects | 43.67 → 55.67 objects | 🔴 +27.48% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256s | verify | allocated_bytes | 11,242.67 → 12,618.67 bytes | 🔴 +12.24% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHA2-256s | verify | allocated_objects | 33.33 → 45.33 objects | 🔴 +36.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHAKE-128f | keygen | allocated_bytes | 976.00 → 976.00 bytes | ⚪ +0.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHAKE-128f | keygen | allocated_objects | 8.00 → 8.00 objects | ⚪ +0.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHAKE-128f | sign | allocated_bytes | 27,936.00 → 27,936.00 bytes | ⚪ +0.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHAKE-128f | sign | allocated_objects | 46.67 → 46.67 objects | ⚪ +0.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHAKE-128f | verify | allocated_bytes | 9,082.67 → 9,082.67 bytes | ⚪ +0.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| circl | SLH-DSA-SHAKE-128f | verify | allocated_objects | 41.33 → 41.33 objects | ⚪ +0.00% | Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled |
| openssl | SLH-DSA-SHA2-128f | hash_context_new | requested_bytes | 392.00 → 400.00 bytes | 🔴 +2.04% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHA2-128f | hash_context_new | allocations | 3.00 → 3.00 objects | ⚪ +0.00% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHA2-192f | hash_context_new | requested_bytes | 392.00 → 616.00 bytes | 🔴 +57.14% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHA2-192f | hash_context_new | allocations | 3.00 → 4.00 objects | 🔴 +33.33% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHA2-256f | hash_context_new | requested_bytes | 392.00 → 616.00 bytes | 🔴 +57.14% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHA2-256f | hash_context_new | allocations | 3.00 → 4.00 objects | 🔴 +33.33% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHAKE-128f | hash_context_new | requested_bytes | 1,360.00 → 1,368.00 bytes | 🔴 +0.59% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHAKE-128f | hash_context_new | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHAKE-192f | hash_context_new | requested_bytes | 1,360.00 → 1,368.00 bytes | 🔴 +0.59% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHAKE-192f | hash_context_new | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHAKE-256f | hash_context_new | requested_bytes | 1,360.00 → 1,368.00 bytes | 🔴 +0.59% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| openssl | SLH-DSA-SHAKE-256f | hash_context_new | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Focused hash context, synthetic key without HMAC; not full EVP operation |
| liboqs | private SHA2 | sha2_224 | local_frame_reserved | 176.00 → 304.00 bytes | 🔴 +72.73% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_224_init | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256 | local_frame_reserved | 176.00 → 304.00 bytes | 🔴 +72.73% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256_compress | local_frame_reserved | 160.00 → 144.00 bytes | 🟢 -10.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256_copy | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256_final_len | local_frame_reserved | 48.00 → 160.00 bytes | 🔴 +233.33% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256_final_pad | local_frame_reserved | 32.00 → 144.00 bytes | 🔴 +350.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256_init | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_256_update | local_frame_reserved | 64.00 → 176.00 bytes | 🔴 +175.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_384 | local_frame_reserved | 320.00 → 544.00 bytes | 🔴 +70.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_384_init | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512 | local_frame_reserved | 320.00 → 544.00 bytes | 🔴 +70.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_224 | local_frame_reserved | 320.00 → 544.00 bytes | 🔴 +70.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_224_init | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_256 | local_frame_reserved | 320.00 → 544.00 bytes | 🔴 +70.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_256_init | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_compress | local_frame_reserved | 192.00 → 256.00 bytes | 🔴 +33.33% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_copy | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_final_len | local_frame_reserved | 48.00 → 272.00 bytes | 🔴 +466.67% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_final_pad | local_frame_reserved | 32.00 → 272.00 bytes | 🔴 +750.00% | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_init | local_frame_reserved | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Compiler-specific function frame including inlining; not full-call peak |
| liboqs | private SHA2 | sha2_512_update | local_frame_reserved | 64.00 → 304.00 bytes | 🔴 +375.00% | Compiler-specific function frame including inlining; not full-call peak |
| rustcrypto | ML-DSA-87 | constructor | local_frame_reserved | 398,704.00 → 343,328.00 bytes | 🟢 -13.89% | Original uninstrumented binary, compiler-specific constructor frame; not full-call peak |
| rustcrypto | ML-DSA-65 | constructor | local_frame_reserved | 214,736.00 → 176,800.00 bytes | 🟢 -17.67% | Original uninstrumented binary, compiler-specific constructor frame; not full-call peak |
| rustcrypto | ML-DSA-44 | constructor | local_frame_reserved | 182,384.00 → 142,352.00 bytes | 🟢 -21.95% | Original uninstrumented binary, compiler-specific constructor frame; not full-call peak |
| rustcrypto | ML-DSA-44 | keygen | allocated_bytes | 65,760.00 → 65,760.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | peak_live_above_entry_bytes | 65,760.00 → 65,760.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocated_bytes | 5,120.00 → 5,120.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | peak_live_above_entry_bytes | 5,120.00 → 5,120.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocated_bytes | 70,880.00 → 70,880.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | peak_live_above_entry_bytes | 70,880.00 → 70,880.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocated_bytes | 108,768.00 → 108,768.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | peak_live_above_entry_bytes | 108,768.00 → 108,768.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocated_bytes | 6,656.00 → 6,656.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | peak_live_above_entry_bytes | 6,656.00 → 6,656.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocated_bytes | 115,424.00 → 115,424.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | peak_live_above_entry_bytes | 115,424.00 → 115,424.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocated_bytes | 178,400.00 → 178,400.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | peak_live_above_entry_bytes | 178,400.00 → 178,400.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocated_bytes | 9,216.00 → 9,216.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | peak_live_above_entry_bytes | 9,216.00 → 9,216.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocated_bytes | 187,616.00 → 187,616.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | peak_live_above_entry_bytes | 187,616.00 → 187,616.00 bytes | ⚪ +0.00% | Allocator probe default; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocated_bytes | 65,760.00 → 65,760.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | peak_live_above_entry_bytes | 65,760.00 → 65,760.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocated_bytes | 5,120.00 → 5,120.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | peak_live_above_entry_bytes | 5,120.00 → 5,120.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocated_bytes | 70,880.00 → 70,880.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | peak_live_above_entry_bytes | 70,880.00 → 70,880.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocated_bytes | 108,768.00 → 108,768.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | peak_live_above_entry_bytes | 108,768.00 → 108,768.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocated_bytes | 6,656.00 → 6,656.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | peak_live_above_entry_bytes | 6,656.00 → 6,656.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocated_bytes | 115,424.00 → 115,424.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | peak_live_above_entry_bytes | 115,424.00 → 115,424.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocated_bytes | 178,400.00 → 178,400.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | peak_live_above_entry_bytes | 178,400.00 → 178,400.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocated_bytes | 9,216.00 → 9,216.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | peak_live_above_entry_bytes | 9,216.00 → 9,216.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocated_bytes | 187,616.00 → 187,616.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | peak_live_above_entry_bytes | 187,616.00 → 187,616.00 bytes | ⚪ +0.00% | Allocator probe default-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocated_bytes | 65,760.00 → 65,760.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | peak_live_above_entry_bytes | 65,760.00 → 65,760.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocated_bytes | 5,120.00 → 5,120.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | peak_live_above_entry_bytes | 5,120.00 → 5,120.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocated_bytes | 70,880.00 → 70,880.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | peak_live_above_entry_bytes | 70,880.00 → 70,880.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocated_bytes | 108,768.00 → 108,768.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | peak_live_above_entry_bytes | 108,768.00 → 108,768.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocated_bytes | 6,656.00 → 6,656.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | peak_live_above_entry_bytes | 6,656.00 → 6,656.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocated_bytes | 115,424.00 → 115,424.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | peak_live_above_entry_bytes | 115,424.00 → 115,424.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocated_bytes | 178,400.00 → 178,400.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocations | 4.00 → 4.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | peak_live_above_entry_bytes | 178,400.00 → 178,400.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocated_bytes | 9,216.00 → 9,216.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocations | 2.00 → 2.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | peak_live_above_entry_bytes | 9,216.00 → 9,216.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocated_bytes | 187,616.00 → 187,616.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocations | 6.00 → 6.00 objects | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | peak_live_above_entry_bytes | 187,616.00 → 187,616.00 bytes | ⚪ +0.00% | Allocator probe alloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | keygen | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | sign | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-44 | fresh_key_sign | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | keygen | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | sign | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-65 | fresh_key_sign | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | keygen | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | sign | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | verify | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocated_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | allocations | 0.00 → 0.00 objects | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
| rustcrypto | ML-DSA-87 | fresh_key_sign | peak_live_above_entry_bytes | 0.00 → 0.00 bytes | ⚪ undefined (zero baseline) | Allocator probe noalloc-zeroize; caller key clone excluded; peak only tracked requested heap above operation entry |
