#!/usr/bin/env python3
"""Recheck saved C-provider resource evidence and record local source bindings.

No cryptographic workload or timing experiment is executed. Existing build paths
are derived from this checkout's sibling worktrees, as in the saved commands.
"""
import datetime, hashlib, importlib.util, json, platform, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PERSONAL = ROOT.parents[2]
FROZEN = ROOT.parent / 'provider-performance'
OQS = ROOT.parent / 'liboqs-performance/libs/liboqs/deps/liboqs'
SSL = PERSONAL / 'openssl'
def need(value, message):
    if not value: raise ValueError(message)
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):
    return json.loads(Path(path).read_text())
def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')
def command(argv):
    p = subprocess.run(list(map(str, argv)), capture_output=True, text=True)
    need(p.returncode == 0, 'command failed: ' + repr(argv) + p.stderr)
    return dict(command=list(map(str, argv)), returncode=p.returncode, stdout=p.stdout, stderr=p.stderr)
def git(repo, *args):
    return command(['git', '-C', repo, *args])['stdout'].strip()
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
def identities(provider, repo, measured, runtime):
    directory = ROOT / 'results' / provider / 'resource-audit'
    pr = read(directory / 'live-pr.json'); head = pr['headRefOid']; base = pr['baseRefOid']
    source = repo / 'worktrees/signoff-20261012'
    need(git(source, 'rev-parse', 'HEAD') == head, 'wrong signed source head')
    files = {}
    for path in runtime:
        data = (source / path).read_bytes()
        blob = subprocess.check_output(['git', '-C', str(repo), 'show', head + ':' + path])
        old = subprocess.check_output(['git', '-C', str(repo), 'show', measured + ':' + path])
        need(data == blob == old, 'changed signed/measured runtime: ' + path)
        files[path] = hashlib.sha256(data).hexdigest()
    return dict(checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), live_pr=pr,
        baseline=base, signed_head=head, measured_candidate=measured,
        signed_tree=git(repo, 'rev-parse', head + '^{tree}'),
        measured_tree=git(repo, 'rev-parse', measured + '^{tree}'),
        runtime_identical=True, runtime_sha256=files, architecture=platform.machine(),
        compiler=command(['cc', '--version'])['stdout'])

def openssl():
    directory = ROOT / 'results/openssl/resource-audit'
    experiment = ROOT / 'libs/openssl/experiments/resource-audit'
    module = load('ssl_resource', experiment / 'run.py')
    provenance = identities('openssl', SSL, 'cb722554afced3c3232104b15693c203734864cf',
        ['crypto/slh_dsa/slh_hash.c', 'crypto/slh_dsa/slh_dsa_hash_ctx.c', 'crypto/slh_dsa/slh_dsa_local.h'])
    need(provenance['signed_tree'] == provenance['measured_tree'], 'OpenSSL measured tree mismatch')
    gate_path = ROOT / 'results/openssl/experiments/sha512-prefix-final-gate.json'
    gate = read(gate_path)
    variants = {}
    for side in ['baseline', 'candidate']:
        for suffix in ['build', 'run']:
            need(read(directory / (side + '-' + suffix + '.json'))['returncode'] == 0, 'failed probe command')
        rows = module.validate([json.loads(line) for line in (directory / (side + '.jsonl')).read_text().splitlines()], side == 'candidate')
        library = FROZEN / 'libs/openssl/build/sha512-prefix' / side / 'libcrypto.a'
        need(sha(library) == gate['identities'][side]['libcrypto.a'], 'changed sealed libcrypto')
        variants[side] = dict(rows=len(rows), failure_cases=sum(bool(r['fail_at']) for r in rows),
            successes=[r for r in rows if not r['fail_at']], raw_sha256=sha(directory / (side + '.jsonl')),
            binary_sha256=sha(ROOT / 'libs/openssl/build/resource-audit' / side),
            libcrypto_path=str(library), libcrypto_sha256=sha(library))
    outputs = lambda side: {(r['parameter'], r['action']): r['output_hex'] for r in variants[side]['successes']}
    need(outputs('baseline') == outputs('candidate'), 'different H/T/PRF results')
    provenance.update(complete=True, variants=variants, sealed_gate_sha256=sha(gate_path), probe_sha256=sha(experiment / 'ctx-lifecycle.c'),
        validator=command(['python3', experiment / 'test_runner.py']),
        limits=['Synthetic key.hmac=NULL; focused hash contexts, not complete EVP allocation totals.', 'Success buffers checked for clearing; OOM partial buffers checked only for leaks.', 'Requested bytes, not allocator rounded bytes or RSS.'])
    write(directory / 'provenance.json', provenance)

def liboqs():
    directory = ROOT / 'results/liboqs/resource-audit'
    experiment = ROOT / 'libs/liboqs/experiments/resource-audit'
    provenance = identities('liboqs', OQS, 'b14f1b616f938698ebc0bf8b75b3736c30e1502c',
        ['src/sig/slh_dsa/slh_dsa_c/sha2_256.c', 'src/sig/slh_dsa/slh_dsa_c/sha2_512.c'])
    trim_tree = git(OQS, 'rev-parse', 'dd039f5f899aefb24b86b94c4b5cba1b2ec39f2f^{tree}')
    need(trim_tree == provenance['signed_tree'], 'signed/trim source differs')
    provenance['trim_tree'] = trim_tree
    provenance['measurement_to_trim_diff'] = git(OQS, 'diff', 'b14f1b6', 'dd039f5', '--stat')
    library = Path('/opt/homebrew/Cellar/openssl@3/3.6.4_1/lib/libcrypto.3.dylib')
    need(sha(library) == 'a7e687f76c5b69423480050f6bfa91dc2c2f616866476cca485ebc2b68ed0b15', 'backend differs from measured backend')
    variants = {}; frames = {}
    for side in ['baseline', 'candidate']:
        commands = read(directory / (side + '-commands.json'))
        need(len(commands) == 4 and all(c['returncode'] == 0 for c in commands), 'failed/missing probe command')
        source = OQS if side == 'baseline' else OQS / 'worktrees/signoff-20261012'
        source_head = git(source, 'rev-parse', 'HEAD')
        need(source_head == provenance['baseline' if side == 'baseline' else 'signed_head'], 'wrong source checkout')
        build = ROOT / 'libs/liboqs/build/resource-audit' / side
        variant_frames = {}
        for bits in [256, 512]:
            source_path = source / ('src/sig/slh_dsa/slh_dsa_c/sha2_' + str(bits) + '.c')
            cmd = commands[0 if bits == 256 else 1]['command']
            need('-O3' in cmd and '-fstack-usage' in cmd and str(source_path) in cmd, 'wrong stack compile flags/source')
            saved = directory / (side + '-' + str(bits) + '-stack.txt')
            need(saved.read_bytes() == (build / ('sha2_' + str(bits) + '.su')).read_bytes(), 'stack report differs from build output')
            for line in saved.read_text().splitlines():
                location, size, kind = line.split('\t')
                function = location.rsplit(':', 1)[-1]
                need(kind == 'static' and function not in variant_frames, 'unsupported/duplicate stack record')
                variant_frames[function] = int(size)
        frames[side] = variant_frames
        variants[side] = dict(binary_sha256=sha(build / 'probe'), object_sha256={str(bits): sha(build / ('sha2_' + str(bits) + '.o')) for bits in [256,512]},
            config_sha256=sha(build / 'oqs/oqsconfig.h'), linked_libraries=command(['otool', '-L', build / 'probe'])['stdout'])
    need(frames['baseline'].keys() == frames['candidate'].keys(), 'stack function mismatch')
    table = [dict(function=f, baseline_bytes=frames['baseline'][f], candidate_bytes=frames['candidate'][f], delta_bytes=frames['candidate'][f]-frames['baseline'][f]) for f in sorted(frames['baseline'])]
    provenance.update(complete=True, variants=variants, stack_frames=table,
        stack_max_local_delta_bytes=max(r['delta_bytes'] for r in table),
        backend_path=str(library), backend_sha256=sha(library), probe_sha256=sha(experiment / 'hash-resources.c'),
        saved_output_check=json.loads(command(['python3', experiment / 'check.py'])['stdout']),
        validator=command(['python3', experiment / 'test_checker.py']),
        limits=['OpenSSL allocator hooks only; not all libc or whole SLH API allocations.', 'Individual compiler stack frames include inlining choices; exclude callee and full-operation peak stack.', 'No RSS, no new latency measurements.'])
    write(directory / 'provenance.json', provenance)
    text = '| Function | Original local frame | Candidate local frame | Delta |\n|---|---:|---:|---:|\n'
    text += ''.join('| `' + r['function'] + '` | ' + str(r['baseline_bytes']) + ' B | ' + str(r['candidate_bytes']) + ' B | ' + ('+' if r['delta_bytes'] >= 0 else '') + str(r['delta_bytes']) + ' B |\n' for r in table)
    (directory / 'STACK.md').write_text('# Individual compiler stack frames\n\nApple clang 21, arm64, `-O3 -fstack-usage`; same flags on both versions. These are individual function frames, not complete call-chain maxima. The source rows and compile commands are retained alongside this table.\n\n' + text)

if __name__ == '__main__':
    openssl(); liboqs()
    print('OpenSSL and liboqs saved evidence, signed-source identity, linked backend and stack bindings PASS')
