#!/usr/bin/env python3
"""Compile and compare private hashes with upstream and hashlib; fail closed."""
import argparse, ctypes, hashlib, json, random, subprocess
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--baseline', type=Path, required=True)
p.add_argument('--candidate', type=Path, required=True)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--evidence', type=Path, required=True)
a = p.parse_args()
a.build.mkdir(parents=True, exist_ok=True)
a.evidence.mkdir(parents=True, exist_ok=True)
openssl = Path(subprocess.check_output(['pkg-config', '--variable=prefix', 'openssl'], text=True).strip())
crypto = ctypes.CDLL(str(openssl/'lib/libcrypto.dylib'))
crypto.EVP_get_digestbyname.argtypes = [ctypes.c_char_p]
crypto.EVP_get_digestbyname.restype = ctypes.c_void_p
crypto.EVP_Digest.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint), ctypes.c_void_p, ctypes.c_void_p]
def expected_digest(name, message):
    if '_' not in name:
        return hashlib.new(name, message).digest()
    md = crypto.EVP_get_digestbyname(name.replace('_', '-').encode())
    assert md
    out = ctypes.create_string_buffer(64)
    size = ctypes.c_uint()
    assert crypto.EVP_Digest(message, len(message), out, ctypes.byref(size), md, None) == 1
    return out.raw[:size.value]
commands = []
def run(cmd):
    commands.append([str(v) for v in cmd])
    return subprocess.run(cmd, check=True, capture_output=True, text=True)

def library(name, source, definitions):
    dest = a.build / name
    (dest / 'oqs').mkdir(parents=True, exist_ok=True)
    (dest / 'oqs/oqsconfig.h').write_text(definitions)
    out = dest / 'hashes.dylib'
    private = source / 'src/sig/slh_dsa/slh_dsa_c'
    run(['cc', '-O3', '-dynamiclib', '-I'+str(dest), '-I'+str(openssl/'include'),
         str(private/'sha2_256.c'), str(private/'sha2_512.c'), '-L'+str(openssl/'lib'), '-lcrypto', '-o', str(out)])
    return ctypes.CDLL(str(out))

base = library('baseline', a.baseline, '#define OQS_USE_SHA2_OPENSSL 1\n')
configs = {
    'openssl': '#define OQS_USE_SHA2_OPENSSL 1\n',
    'portable': '',
    'dlopen-fallback': '#define OQS_USE_SHA2_OPENSSL 1\n#define OQS_DLOPEN_OPENSSL 1\n',
    'no-deprecated-fallback': '#define OQS_USE_SHA2_OPENSSL 1\n#define OPENSSL_NO_DEPRECATED\n',
}
results = {}
rng = random.Random(1804205)
raw_inputs = [rng.randbytes(256) for _ in range(2048)]
for name, definitions in configs.items():
    lib = library(name, a.candidate, definitions)
    checks = 0
    for bits, word in ((256, ctypes.c_uint32), (512, ctypes.c_uint64)):
        block = word * 32
        for raw in raw_inputs:
            b = block.from_buffer_copy(raw[:ctypes.sizeof(block)])
            c = block.from_buffer_copy(bytes(b))
            getattr(base, f'sha2_{bits}_compress')(ctypes.byref(b))
            getattr(lib, f'sha2_{bits}_compress')(ctypes.byref(c))
            assert bytes(b) == bytes(c), (name, bits, 'raw state/block mismatch')
            checks += 1
    for algorithm in ('224', '256', '384', '512', '512_224', '512_256'):
        hname = 'sha'+algorithm
        for length in list(range(261)) + [511, 512, 513, 1023, 1024, 1025, 4096, 8193]:
            message = rng.randbytes(length)
            digest = ctypes.create_string_buffer(64)
            getattr(lib, 'sha2_'+algorithm)(digest, message, ctypes.c_size_t(length))
            expect = expected_digest(hname, message)
            assert digest.raw[:len(expect)] == expect, (name, algorithm, length)
            checks += 1
    results[name] = {'passed_checks': checks}
# Instrument only the test build: production sources contain no counters/hooks.
private = a.candidate / 'src/sig/slh_dsa/slh_dsa_c'
probe = a.build/'probe'
(probe/'oqs').mkdir(parents=True, exist_ok=True)
(probe/'oqs/oqsconfig.h').write_text(configs['openssl'])
for bits in (256, 512):
    run(['cc', '-O3', '-I'+str(probe), '-I'+str(openssl/'include'), f'-DSHA{bits}_Transform=probe{bits}', '-DOPENSSL_cleanse=probe_cleanse', '-c', str(private/f'sha2_{bits}.c'), '-o', str(probe/f'{bits}.o')])
run(['cc', '-O3', '-I'+str(private), '-I'+str(openssl/'include'), str(Path(__file__).with_name('backend_probe.c')), str(probe/'256.o'), str(probe/'512.o'), '-L'+str(openssl/'lib'), '-lcrypto', '-o', str(probe/'probe')])
result = run([str(probe/'probe')])
report = {'results': results, 'backend_probe': result.stdout.strip(), 'commands': commands}
(a.evidence/'hash-checks.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({'results': results, 'backend_probe': report['backend_probe']}, indent=2))
