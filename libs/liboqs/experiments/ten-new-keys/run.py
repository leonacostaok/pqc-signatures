"""One ten-key batch per side; collect candidate and baseline in separate grants."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BUILD = ROOT / 'libs/liboqs/build/ten-new-keys'
OLD_BUILD = ROOT / 'libs/liboqs/build/sha2-openssl'
OLD = HERE.parent / 'sha2-openssl'
EVIDENCE = HERE / 'evidence'
PARAMETERS = ['SLH_DSA_PURE_SHA2_' + p for p in ['128F', '128S', '192F', '192S', '256F', '256S']]
SIZES = dict(zip(PARAMETERS, [16, 16, 24, 24, 32, 32]))
SIGS = dict(zip(PARAMETERS, [17088, 7856, 35664, 16224, 49856, 29792]))
ENV = ['DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_armcap', 'OPENSSL_ia32cap']
LIBCRYPTO = Path('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2, allow_nan=False); f.write('\n')


def check_records(rows, expected, sizes):
    require(len(rows) == len(expected), 'missing or extra rows')
    seen = []
    for r in rows:
        identity = (r['parameter'], r['key']); seen.append(identity)
        require(identity in expected, 'unexpected row identity')
        require(r.get('valid') is True and r.get('tamper_rejected') is True, 'failed verdict')
        n = sizes[r['parameter']]
        require(r['rng_keygen_bytes'] == 3*n and r['rng_sign_bytes'] == n, 'wrong RNG work')
        for op in ('keygen', 'sign', 'verify'):
            for clock in ('wall', 'cpu'):
                v = r[op + '_' + clock + '_ns']
                require(type(v) is int and math.isfinite(v) and v > 0, 'invalid elapsed time')
    require(seen == expected and len(set(seen)) == len(expected), 'incomplete/duplicate/reordered coverage')


def derive(label, length):
    prefix = ('pqc-ten-new-keys-v1/liboqs/' + label + '/').encode()
    return b''.join(hashlib.sha256(prefix + str(i).encode()).digest()
                    for i in range((length + 31)//32))[:length]


def corpus(mode, count):
    output = bytearray(b'OQSTENK1'); metadata = []
    messages = [0, 32, 256, 4096, 64, 1024, 7, 513, 2048, 8192]
    contexts = [0, 1, 17, 255, 0, 1, 17, 255, 32, 128]
    for p in PARAMETERS:
        for key in range(-1, count):
            label = mode + '/' + p + '/' + ('warmup' if key == -1 else str(key))
            mlen, clen = (31, 3) if key == -1 else (messages[key], contexts[key])
            n = SIZES[p]
            seed, rnd = derive(label + '/seed', 3*n), derive(label + '/sign-entropy', n)
            msg, ctx = derive(label + '/message', mlen), derive(label + '/context', clen)
            output.extend(struct.pack('<II', mlen, clen) + seed + rnd + msg + ctx)
            metadata.append(dict(parameter=p, key=key, label=label, message_bytes=mlen, context_bytes=clen,
                                 seed_sha256=hashlib.sha256(seed).hexdigest(), signing_entropy_sha256=hashlib.sha256(rnd).hexdigest()))
    require(len({r['seed_sha256'] for r in metadata}) == len(metadata), 'duplicate key seed')
    return bytes(output), metadata


def old_identities():
    seal_path = OLD/'evidence/final-paired/ready-manifest.json'
    seal = json.loads(seal_path.read_text())
    for relative, want in seal['files'].items():
        require(sha(OLD_BUILD/relative) == want, 'original sealed build changed: ' + relative)
    for path, want in seal['experiment_files'].items():
        require(sha(path) == want, 'original experiment changed: ' + path)
    for relative, want in seal['source_files'].items():
        require(sha(Path(seal['candidate_source'])/relative) == want, 'original candidate source changed: ' + relative)
    backend = json.loads((OLD/'evidence/linked-backend-provenance.json').read_text())
    require(sha(LIBCRYPTO) == backend['crypto_sha256'], 'linked OpenSSL changed')
    return {'original_seal_sha256': sha(seal_path), 'original_build_hashes': seal['files'],
            'original_sealed_files_verified': len(seal['files'])+len(seal['experiment_files'])+len(seal['source_files']),
            'libcrypto_path': str(LIBCRYPTO.resolve()), 'libcrypto_sha256': sha(LIBCRYPTO),
            'libcrypto_version': backend['runtime_openssl_version'],
            'baseline_commit': 'fd44469daeffe6b28f031f54f9bb66cbae69a572',
            'candidate_commit': 'b14f1b616f938698ebc0bf8b75b3736c30e1502c'}


def identities():
    return {**old_identities(), 'sources': {p.name: sha(p) for p in [HERE/'driver.c', HERE/'run.py', HERE/'check_runner.py']},
            'drivers': {s: sha(BUILD/s/'driver') for s in ('baseline', 'candidate')},
            'input_sha256': sha(EVIDENCE/'inputs.bin'),
            'environment': {k: os.environ.get(k) for k in ENV}}


def parse_outputs(path, count):
    data = Path(path).read_bytes(); require(data[:8] == b'OQSTENO1', 'output magic'); offset = 8; digests = []
    for p in PARAMETERS:
        for key in range(count):
            lengths = struct.unpack_from('<III', data, offset); offset += 12
            require(lengths == (2*SIZES[p], 4*SIZES[p], SIGS[p]), 'output sizes')
            row = {'parameter': p, 'key': key}
            for field, size in zip(('pk', 'sk', 'signature'), lengths):
                value = data[offset:offset+size]; require(len(value) == size, 'truncated artifact'); offset += size
                row[field + '_sha256'] = hashlib.sha256(value).hexdigest()
            digests.append(row)
    require(offset == len(data), 'trailing artifact bytes')
    require(len({r['pk_sha256'] for r in digests}) == len(digests), 'duplicate public keys')
    return digests


def execute(side, input_file, count, dest):
    dest.mkdir(parents=True, exist_ok=False)
    cmd = [str(BUILD/side/'driver'), str(input_file), str(dest/'outputs.bin'), str(count)]
    write_json(dest/'command.json', {'command': cmd, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    with (dest/'stdout.jsonl').open('x') as out, (dest/'stderr.txt').open('x') as err:
        rc = subprocess.run(cmd, stdout=out, stderr=err).returncode
    write_json(dest/'status.json', {'returncode': rc, 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    require(rc == 0, 'driver failed; raw logs retained')
    rows = [json.loads(line) for line in (dest/'stdout.jsonl').read_text().splitlines()]
    check_records(rows, [(p, k) for p in PARAMETERS for k in range(count)], SIZES)
    expected = {(r['parameter'],r['key']):r for r in corpus('irrelevant', count)[1] if r['key'] >= 0}
    for r in rows:
        for name in ('message_bytes','context_bytes'):
            require(r[name] == expected[r['parameter'],r['key']][name], 'wrong workload size')
    return rows, parse_outputs(dest/'outputs.bin', count)


def prepare():
    EVIDENCE.mkdir(exist_ok=True); BUILD.mkdir(parents=True, exist_ok=False)
    original = old_identities(); commands = []
    for side in ('baseline', 'candidate'):
        dest = BUILD/side; dest.mkdir()
        cmd = ['cc', '-std=c11', '-O3', '-Wall', '-Wextra', '-Werror', '-I'+str(OLD_BUILD/side/'include'),
               str(HERE/'driver.c'), str(OLD_BUILD/side/'lib/liboqs.a'), '-L'+str(LIBCRYPTO.resolve().parent),
               '-lcrypto', '-lpthread', '-o', str(dest/'driver')]
        result = subprocess.run(cmd, capture_output=True, text=True)
        write_json(EVIDENCE/(side+'-build.json'), {'command':cmd,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        require(result.returncode == 0, 'driver compilation failed'); commands.append(cmd)
    for mode, count in [('final',10), ('smoke',1)]:
        data, meta = corpus(mode, count)
        path = EVIDENCE/'inputs.bin' if mode == 'final' else BUILD/'smoke-inputs.bin'
        with path.open('xb') as f: f.write(data)
        if mode == 'final': write_json(EVIDENCE/'inputs.json', {'domain':'pqc-ten-new-keys-v1/liboqs','cases':meta,'sha256':sha(path)})
    smoke = {}
    for side in ('candidate','baseline'):
        rows, hashes = execute(side, BUILD/'smoke-inputs.bin', 1, EVIDENCE/('smoke-'+side))
        smoke[side] = {'rows':rows,'output_hashes':hashes}
    require(smoke['baseline']['output_hashes'] == smoke['candidate']['output_hashes'], 'smoke byte mismatch')
    require((EVIDENCE/'smoke-baseline/outputs.bin').read_bytes()==(EVIDENCE/'smoke-candidate/outputs.bin').read_bytes(), 'smoke output difference')
    write_json(EVIDENCE/'smoke.json', {'complete':True,'purpose':'correctness smoke, not final timing','per_variant_keys':6,'both_variants_byte_equal':True,'results':smoke})
    write_json(EVIDENCE/'ready.json', {'complete':True,'identity':identities(),'smoke_sha256':sha(EVIDENCE/'smoke.json'),
               'platform':platform.platform(),'machine':platform.machine(),'compiler':subprocess.check_output(['cc','--version'],text=True),
               'cpu':subprocess.check_output(['sysctl','-n','machdep.cpu.brand_string'],text=True).strip(),
               'scope':'6 SHA2 parameter sets, 10 measured new keys each, 1 disjoint warmup per parameter; public OQS API with fixed test RNG input; object/buffer creation outside timers; native operations inside',
               'ordering':'Final candidate batch before any final baseline batch; cross-provider scheduling is controlled externally.'})
    print('READY', EVIDENCE/'ready.json')


def collect(args):
    require(args.exclusive_window, 'exclusive window grant required')
    ready = json.loads((EVIDENCE/'ready.json').read_text())
    require(ready['complete'] is True and ready['identity']==identities(), 'sealed input changed')
    require(sha(EVIDENCE/'smoke.json')==ready['smoke_sha256'], 'smoke evidence changed')
    if args.variant == 'baseline':
        candidate = json.loads((EVIDENCE/'final-candidate/result.json').read_text())
        require(candidate['complete'] is True and candidate['ready_sha256']==sha(EVIDENCE/'ready.json'), 'candidate phase incomplete')
        require(candidate['artifact_sha256']==sha(EVIDENCE/'final-candidate/outputs.bin'), 'candidate artifact changed')
        require(candidate['raw_sha256']==sha(EVIDENCE/'final-candidate/stdout.jsonl'), 'candidate timing evidence changed')
        raw = [json.loads(line) for line in (EVIDENCE/'final-candidate/stdout.jsonl').read_text().splitlines()]
        require(raw==candidate['rows'], 'candidate recorded rows changed')
        check_records(raw, [(p,k) for p in PARAMETERS for k in range(10)], SIZES)
        require(parse_outputs(EVIDENCE/'final-candidate/outputs.bin',10)==candidate['output_hashes'], 'candidate output identities changed')
    dest = EVIDENCE/('final-'+args.variant)
    rows, outputs = execute(args.variant, EVIDENCE/'inputs.bin', 10, dest)
    require(ready['identity']==identities(), 'frozen inputs changed during collection')
    result = {'complete':True,'variant':args.variant,'ready_sha256':sha(EVIDENCE/'ready.json'),'rows':rows,
              'output_hashes':outputs,'artifact_sha256':sha(dest/'outputs.bin'),'validated_each_key':True,
              'raw_sha256':sha(dest/'stdout.jsonl'),
              'started_utc':json.loads((dest/'command.json').read_text())['started_utc'],
              'finished_utc':json.loads((dest/'status.json').read_text())['finished_utc'],
              'cross_variant_comparison':'pending baseline' if args.variant=='candidate' else 'byte-identical'}
    if args.variant == 'baseline':
        require(candidate['finished_utc'] < result['started_utc'], 'candidate-first ordering violated')
        require((dest/'outputs.bin').read_bytes()==(EVIDENCE/'final-candidate/outputs.bin').read_bytes(),'final key/signature bytes differ')
        require(outputs==candidate['output_hashes'],'final per-key digest mismatch')
    write_json(dest/'result.json',result)
    if args.variant == 'baseline':
        lookup={(r['parameter'],r['key']):r for r in candidate['rows']}; summary=[]
        for p in PARAMETERS:
            for op in ('keygen','sign','verify'):
                selected=[r for r in rows if r['parameter']==p]; row={'parameter':p,'operation':op}
                for clock in ('wall','cpu'):
                    field=op+'_'+clock+'_ns'
                    ratios=[r[field]/lookup[p,r['key']][field] for r in selected]
                    row[clock+'_median_paired_speedup']=statistics.median(ratios)
                    row[clock+'_ratio_of_total_times']=sum(r[field] for r in selected)/sum(lookup[p,r['key']][field] for r in selected)
                    row[clock+'_per_key_ratios']=ratios
                    row[clock+'_baseline_total_ns']=sum(r[field] for r in selected)
                    row[clock+'_candidate_total_ns']=sum(lookup[p,r['key']][field] for r in selected)
                    row[clock+'_min_key_speedup']=min(ratios)
                    row[clock+'_max_key_speedup']=max(ratios)
                    row[clock+'_key_losses']=sum(v<1 for v in ratios)
                summary.append(row)
        write_json(EVIDENCE/'summary.json', {'complete':True,'keys_per_parameter':10,'matched_keys_signatures':True,'summary':summary,
                   'primary_statistic':'Baseline total wall time divided by candidate total wall time across the ten matched keys; CPU totals and per-key ratios are secondary.',
                   'candidate_started_utc':candidate['started_utc'],'candidate_finished_utc':candidate['finished_utc'],
                   'baseline_started_utc':result['started_utc'],'baseline_finished_utc':result['finished_utc'],
                   'limitation':'One candidate-first then baseline sensitivity batch; order and elapsed-time confounding remain. No independent-fork confidence interval.'})
    print('COMPLETE',args.variant,len(rows),'keys',dest/'result.json')


def main():
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('prepare'); p=sub.add_parser('measure'); p.add_argument('--variant',choices=['candidate','baseline'],required=True)
    p.add_argument('--exclusive-window',action='store_true'); args=parser.parse_args()
    prepare() if args.command=='prepare' else collect(args)


if __name__=='__main__': main()
