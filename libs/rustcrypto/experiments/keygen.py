#!/usr/bin/env python3
"""Prepare pinned RustCrypto sources and collect explicitly requested paired measurements."""
import argparse
import datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = HERE.parent / 'build' / 'keygen-reuse'
PIN = 'a84081789729c96dabb35f96cd000e434b247e02'
PATCH = HERE.parent / 'patches' / 'mldsa-keygen-reuse.patch'
SOURCES = [HERE / name for name in ['keygen.py', 'keygen.rs']]
LOCK = HERE / 'keygen.Cargo.lock'
ENV_KEYS = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
    'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN']


def compiler_environment():
    names = set(ENV_KEYS)
    names.update(k for k in os.environ if k.startswith('CARGO_PROFILE_') or
        (k.startswith('CARGO_TARGET_') and k.endswith(('_RUSTFLAGS', '_LINKER'))))
    return {k: os.environ.get(k, '') for k in sorted(names)}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(path):
    h = hashlib.sha256()
    for p in sorted(Path(path).rglob('*')):
        if p.is_file() and '.git' not in p.parts:
            h.update(str(p.relative_to(path)).encode() + b'\0' + bytes.fromhex(sha(p)))
    return h.hexdigest()


def run(command, *, cwd=None, logfile=None, env=None):
    result = subprocess.run([str(x) for x in command], cwd=cwd, env=env, capture_output=True, text=True)
    if logfile:
        Path(logfile).write_text('$ ' + ' '.join(map(str, command)) + '\n' + result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'exit {result.returncode}: {command}\n{result.stdout[-1000:]}\n{result.stderr[-6000:]}')
    return result.stdout


def provenance(m):
    return {**{str(p.relative_to(ROOT)): sha(p) for p in SOURCES + [PATCH, LOCK]},
        'binary': sha(m['binary']), 'fixtures': sha(m['fixtures']), 'corpus': sha(m['corpus']),
        'cargo_lock': sha(m['cargo_lock']), 'cargo_manifest': sha(m['cargo_manifest']),
        'driver_copy': sha(Path(m['cargo_manifest']).parent / 'src/main.rs'),
        'baseline_source': tree(m['baseline_source']), 'candidate_source': tree(m['candidate_source'])}


def corpus():
    def data(i, label, n):
        return b''.join(hashlib.sha256(f'mldsa-keygen-v1/204/{i}/{label}/{j}'.encode()).digest()
            for j in range((n + 31) // 32))[:n].hex()
    return {'version': 'mldsa-keygen-v1/204', 'cases': [
        {'seed': data(i, 'seed', 32), 'message': data(i, 'message', [0, 1, 32, 1024][i % 4]),
         'context': data(i, 'context', [0, 1, 31, 255][(i // 4) % 4]),
         'randomness': data(i, 'randomness', 32)} for i in range(16)]}


def prepare(args):
    upstream = Path(args.upstream).resolve()
    compiler = run(['rustc', '-Vv'])
    environment = compiler_environment()
    assert not environment['CARGO_TARGET_DIR'], 'use the isolated target directory'
    assert not environment['CARGO_BUILD_TARGET'], 'this experiment measures the native host target'
    assert not environment['RUSTC_WRAPPER'] and not environment['RUSTC_WORKSPACE_WRAPPER'], 'wrappers are not supported'
    identity = sha(PATCH) + ''.join(sha(s) for s in SOURCES) + compiler + json.dumps(environment)
    if LOCK.exists(): identity += sha(LOCK)
    dest = BUILD / ('prepared-' + hashlib.sha256(identity.encode()).hexdigest()[:16])
    dest.mkdir(parents=True, exist_ok=False)
    evidence = dest / 'checks'; evidence.mkdir()
    archive = subprocess.check_output(['git', '-C', str(upstream), 'archive', PIN, 'ml-dsa', 'Cargo.toml'])
    for side in ['baseline', 'candidate']:
        source = dest / side; source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar.getmembers():
                assert not member.name.startswith('/') and '..' not in Path(member.name).parts
                assert member.isdir() or member.isfile()
            tar.extractall(source)
        if side == 'candidate':
            run(['git', 'init', '-q'], cwd=source)
            run(['git', 'apply', '--check', PATCH], cwd=source)
            run(['git', 'apply', PATCH], cwd=source)
        # Only package names/workspace membership change in the experiment copies, allowing
        # the exact baseline and candidate implementations to coexist in one paired process.
        manifest = source / 'ml-dsa/Cargo.toml'
        original = manifest.read_text()
        assert original.count('name = "ml-dsa"') == 1
        manifest.write_text(original.replace('name = "ml-dsa"',
            f'name = "ml-dsa-{side}"\nworkspace = ".."', 1))
        workspace = source / 'Cargo.toml'; original = workspace.read_text()
        lints = original[original.index('[workspace.lints.clippy]'):original.index('[patch.crates-io]')]
        workspace.write_text('[workspace]\nresolver = "2"\nmembers = ["ml-dsa"]\n\n' + lints)
    cargo = dest / 'Cargo.toml'
    cargo.write_text('''[package]
name = "mldsa-keygen-experiment"
version = "0.0.0"
edition = "2024"
[workspace]
exclude = ["baseline", "candidate"]
[dependencies]
baseline = { package = "ml-dsa-baseline", path = "baseline/ml-dsa", features = ["zeroize"] }
candidate = { package = "ml-dsa-candidate", path = "candidate/ml-dsa", features = ["zeroize"] }
serde = { version = "=1.0.228", features = ["derive"] }
serde_json = "=1.0.150"
hex = "=0.4.3"
libc = "=0.2.186"
''')
    (dest / 'src').mkdir(); shutil.copyfile(HERE / 'keygen.rs', dest / 'src/main.rs')
    if LOCK.exists(): shutil.copyfile(LOCK, dest / 'Cargo.lock')
    build_env = dict(os.environ, CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0')
    command = ['cargo', 'build', '--release', '--offline'] + (['--locked'] if LOCK.exists() else [])
    run(command, cwd=dest, env=build_env, logfile=evidence / 'build.txt')
    if not LOCK.exists(): shutil.copyfile(dest / 'Cargo.lock', LOCK)
    binary = dest / 'target/release/mldsa-keygen-experiment'
    input_path = dest / 'corpus.json'; input_path.write_text(json.dumps(corpus(), indent=2) + '\n')
    fixtures = dest / 'fixtures.json'
    fixtures.write_text(run([binary, 'fixtures', input_path]))
    correctness = json.loads(run([binary, 'check', fixtures], logfile=evidence / 'differential.txt'))
    assert correctness['cases'] == 48 and correctness['exact_signatures'] == 96
    m = {'schema': 'rust-mldsa-keygen-prepared-v1', 'upstream_commit': PIN, 'compiler': compiler,
        'cargo': run(['cargo', '-V']), 'features': ['default', 'zeroize'], 'profile': 'release',
        'compiler_environment': environment, 'build_environment': {'CARGO_BUILD_JOBS': '1', 'CARGO_INCREMENTAL': '0'},
        'binary': str(binary), 'fixtures': str(fixtures), 'corpus': str(input_path),
        'cargo_lock': str(dest / 'Cargo.lock'), 'cargo_manifest': str(cargo),
        'baseline_source': str(dest / 'baseline'), 'candidate_source': str(dest / 'candidate'),
        'checks': str(evidence), 'correctness': correctness}
    m['provenance'] = provenance(m)
    path = dest / 'manifest.json'; path.write_text(json.dumps(m, indent=2) + '\n'); print(path)


def collect(args):
    m = json.loads(Path(args.manifest).read_text())
    assert m['schema'] == 'rust-mldsa-keygen-prepared-v1' and m['upstream_commit'] == PIN
    assert 5 <= args.forks <= 30 and 2 <= args.rounds <= 100 and args.rounds % 2 == 0
    assert 100 <= args.budget_ms <= 10000 and 0 <= args.start < 1000000
    ops = args.operations.split(',')
    assert ops and len(set(ops)) == len(ops) and set(ops) <= {'keygen', 'keygen_sign', 'sign', 'verify'}
    expected = m['provenance']; assert provenance(m) == expected
    assert m['compiler_environment'] == compiler_environment()
    assert expected['driver_copy'] == expected[str((HERE / 'keygen.rs').relative_to(ROOT))]
    output = Path(args.out).resolve()
    if output.exists(): raise FileExistsError(output)
    lock = BUILD / '.timing-lock'; lock.mkdir()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    rows = []
    try:
        for fork in range(args.start, args.start + args.forks):
            for op in ops:
                print(f'Fresh process fork {fork}: {op}', flush=True)
                raw = run([m['binary'], 'bench', m['fixtures'], fork, args.rounds, args.budget_ms, op])
                current = [json.loads(line) for line in raw.splitlines()]
                assert len(current) == 3 * args.rounds
                assert {(r['parameter'], r['round']) for r in current} == {
                    (p, i) for p in ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] for i in range(args.rounds)}
                for r in current:
                    assert r['fork'] == fork and r['operation'] == op
                    assert r['order'] == (['baseline', 'candidate'] if (fork + r['round']) % 2 == 0 else ['candidate', 'baseline'])
                    for side in ['baseline', 'candidate']:
                        v = r[side]
                        assert v['iterations'] >= 16 and v['iterations'] % 16 == 0
                        assert v['elapsed_ns'] >= args.budget_ms * 1000000 and v['cpu_ns'] > 0
                        assert math.isfinite(v['ns_per_op']) and v['ns_per_op'] > 0
                        assert math.isclose(v['ns_per_op'], v['elapsed_ns'] / v['iterations'], rel_tol=1e-12)
                    assert math.isclose(r['speedup'], r['baseline']['ns_per_op'] / r['candidate']['ns_per_op'], rel_tol=1e-12)
                rows.extend(current)
                assert provenance(m) == expected, 'prepared inputs changed'
        summary = []
        for op, param in sorted({(r['operation'], r['parameter']) for r in rows}):
            forks = []
            for fork in range(args.start, args.start + args.forks):
                selected = [r for r in rows if (r['operation'], r['parameter'], r['fork']) == (op, param, fork)]
                assert sorted(r['round'] for r in selected) == list(range(args.rounds))
                forks.append({'fork': fork, 'speedup': statistics.median(r['speedup'] for r in selected),
                    'baseline_ns': statistics.median(r['baseline']['ns_per_op'] for r in selected),
                    'candidate_ns': statistics.median(r['candidate']['ns_per_op'] for r in selected)})
            speeds = [f['speedup'] for f in forks]
            summary.append({'operation': op, 'parameter': param, 'speedup': statistics.median(speeds),
                'fork_min': min(speeds), 'fork_max': max(speeds), 'forks': forks})
        result = {'schema': 'rust-mldsa-keygen-v1', 'prepared': m, 'started_at': started,
            'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'host': platform.platform(), 'arch': platform.machine(), 'forks': args.forks,
            'start_fork': args.start, 'rounds': args.rounds, 'budget_ms': args.budget_ms, 'warmup_ms': 300,
            'statistic': 'median of within-fork median paired baseline/candidate latency ratios; ranges are descriptive, not confidence intervals',
            'summary': summary, 'rows': rows}
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as temp:
            json.dump(result, temp, indent=2); temp.write('\n'); name = temp.name
        try: os.link(name, output)
        finally: os.unlink(name)
        print(output)
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare'); p.add_argument('--upstream', required=True)
    r = sub.add_parser('run'); r.add_argument('--manifest', required=True); r.add_argument('--out', required=True)
    r.add_argument('--forks', type=int, default=5); r.add_argument('--start', type=int, default=10)
    r.add_argument('--rounds', type=int, default=6); r.add_argument('--budget-ms', type=int, default=200)
    r.add_argument('--operations', default='keygen,keygen_sign,sign,verify')
    args = parser.parse_args(); (prepare if args.command == 'prepare' else collect)(args)


if __name__ == '__main__': main()
