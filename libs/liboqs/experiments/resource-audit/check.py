#!/usr/bin/env python3
"""Check the saved untimed SHA-2 outputs and OpenSSL allocator counters."""
import hashlib, json
from pathlib import Path

SIZES = [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1024]
def need(value, message):
    if not value:
        raise ValueError(message)
def validate(rows):
    need([(r['sample'], r['bytes']) for r in rows] == [(s, n) for s in range(4) for n in SIZES], 'missing/duplicate/reordered cases')
    for row in rows:
        for key in ['sample', 'bytes', 'openssl_mallocs', 'openssl_reallocs', 'openssl_frees', 'openssl_requested_bytes', 'sha256_ctx_size', 'sha512_ctx_size']:
            need(type(row[key]) is int and row[key] >= 0, 'invalid counter ' + key)
        need(all(row[k] == 0 for k in ['openssl_mallocs', 'openssl_reallocs', 'openssl_frees', 'openssl_requested_bytes']), 'unexpected OpenSSL allocation traffic')
        data = bytes((i * 17 + row['sample'] * 31) % 256 for i in range(row['bytes']))
        need(row['sha256'] == hashlib.sha256(data).hexdigest(), 'SHA256 mismatch')
        need(row['sha512'] == hashlib.sha512(data).hexdigest(), 'SHA512 mismatch')
    return rows
def main():
    root = Path(__file__).resolve().parents[4]
    output = root / 'results/liboqs/resource-audit'
    variants = {}
    for side in ['baseline', 'candidate']:
        commands = json.loads((output / (side + '-commands.json')).read_text())
        need(len(commands) == 4 and all(c['returncode'] == 0 for c in commands), 'missing/failed compile or execution')
        path = output / (side + '.jsonl')
        rows = validate([json.loads(line) for line in path.read_text().splitlines()])
        variants[side] = dict(rows=len(rows), digests=len(rows)*2, raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), openssl_allocator_calls=0)
    print(json.dumps(dict(complete=True, variants=variants, scope='OpenSSL allocation hooks around the private SHA2 functions; not whole-process or full SLH API accounting'), indent=2))
if __name__ == '__main__':
    main()
