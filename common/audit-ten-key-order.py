#!/usr/bin/env python3
"""Independently recompute the saved candidate-first ten-key comparison."""
import argparse
import hashlib
import json
import statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ['openssl', 'liboqs', 'noble', 'circl', 'rustcrypto', 'bouncycastle']
COUNTS = dict(zip(PROVIDERS, [7, 6, 3, 7, 3, 12]))

def read(p):
    return json.loads(p.read_text())

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(provider, root, side, bindings):
    if provider == 'openssl':
        base = root / 'results/openssl/ten-key-order'
        completion = read(base / side / 'complete.json')
        require(completion['complete'], 'OpenSSL incomplete')
        rows = []
        for name, digest in completion['raw_sha256'].items():
            path = base / side / name
            require(sha(path) == digest, 'OpenSSL raw hash mismatch')
            bindings[str(path)] = digest
            for row in map(json.loads, path.read_text().splitlines()):
                require(row['verified'] and row['tamper_rejected'], 'OpenSSL correctness')
                rows.append((row['parameter'], row['key_index'], tuple(row[k] for k in ['pk_hex', 'sk_hex', 'sig_hex']), {op: (row[op+'_wall_ns'], row[op+'_cpu_ns']) for op in ['keygen', 'sign', 'verify']}))
        return rows
    if provider == 'liboqs':
        base = root / 'libs/liboqs/experiments/ten-new-keys/evidence' / ('final-'+side)
        data = read(base / 'result.json')
        require(data['complete'] and sha(base/'outputs.bin') == data['artifact_sha256'], 'liboqs artifact')
        require(sha(base/'stdout.jsonl') == data['raw_sha256'], 'liboqs raw hash')
        bindings[str(base/'outputs.bin')] = sha(base/'outputs.bin')
        bindings[str(base/'result.json')] = sha(base/'result.json')
        hashes = {(r['parameter'], r['key']): tuple(r[k] for k in ['pk_sha256','sk_sha256','signature_sha256']) for r in data['output_hashes']}
        return [(r['parameter'], r['key'], hashes[(r['parameter'],r['key'])], {op: (r[op+'_wall_ns'],r[op+'_cpu_ns']) for op in ['keygen','sign','verify']}) for r in data['rows'] if check(r)]
    stem = 'tenkeys' if provider in ['noble','circl'] else 'tenkey'
    path = root / 'results' / provider / 'experiments' / (stem+'-'+side+'.json')
    data = read(path)
    require(data['variant'] == side and data['provider'] == provider, 'batch identity')
    bindings[str(path)] = sha(path)
    rows = []
    if provider in ['noble','circl']:
        for param, output in data['outputs'].items():
            require(output['measured_calls'] == dict(keygen=10,sign=10,verify=10), 'call count')
            for r in output['rows']:
                check(r)
                require(r['inputs_preserved'], 'mutated input')
                rows.append((param,r['index'],tuple(r[k] for k in ['public_key','secret_key','signature','seed']),{op:(m['wall_ns'],m['cpu_ns']) for op,m in r['timing'].items()}))
    else:
        for r in data['rows']:
            check(r)
            require(r['phase']=='measured' and r['variant']==side, 'row identity')
            rows.append((r['parameter'],r['index'],tuple(r[k] for k in ['pk','sk','signature','seed']),{op:(m['elapsed_ns'],m['cpu_ns']) for op,m in r['metrics'].items()}))
    return rows


def check(row):
    require(row['valid'] is True and row['tamper_rejected'] is True, 'correctness gate')
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-root', action='append', default=[], help='name=/path/to/evidence/checkout')
    parser.add_argument('--out', type=Path, required=True)
    args=parser.parse_args()
    roots={p:ROOT for p in PROVIDERS}
    for override in args.provider_root:
        p,path=override.split('=',1)
        require(p in roots, 'unknown provider')
        roots[p]=Path(path).resolve()
    execution=read(ROOT/'results/ten-key-order/execution/execution.json')
    require(execution['complete'] and len(execution['batches'])==12, 'incomplete execution')
    require(sha(ROOT/'results/ten-key-order/plan.json')==execution['plan_sha256'], 'plan hash')
    require(sha(ROOT/'common/run-ten-key-order.py')==execution['coordinator_sha256'], 'coordinator hash')
    expected=[(p,s) for s in ['candidate','baseline'] for p in PROVIDERS]
    last=None
    for batch,identity in zip(execution['batches'],expected):
        require((batch['provider'],batch['variant'])==identity and batch['exit_code']==0,'order/status')
        start,end=map(datetime.fromisoformat,[batch['started_at'],batch['finished_at']])
        require(start<=end and (last is None or last<=start),'overlapping batches')
        last=end
        for stream in ['stdout','stderr']:
            require(sha(ROOT/'results/ten-key-order/execution'/batch[stream])==batch[stream+'_sha256'],'log hash')
    bindings={}
    summary=[]
    key_count=0
    for provider in PROVIDERS:
        sides={s:load(provider,roots[provider],s,bindings) for s in ['candidate','baseline']}
        if provider=='liboqs':
            base=roots[provider]/'libs/liboqs/experiments/ten-new-keys/evidence'
            require((base/'final-candidate/outputs.bin').read_bytes()==(base/'final-baseline/outputs.bin').read_bytes(),'liboqs exact bytes')
        maps={s:{(p,i):(outputs,metrics) for p,i,outputs,metrics in rows} for s,rows in sides.items()}
        require(all(len(maps[s])==len(sides[s]) for s in sides),'duplicate rows')
        require(maps['candidate'].keys()==maps['baseline'].keys(),'case mismatch')
        params=sorted({p for p,i in maps['candidate']})
        require(len(params)==COUNTS[provider], 'parameter count')
        for param in params:
            require(sorted(i for p,i in maps['candidate'] if p==param)==list(range(10)), 'ten keys')
            outputs=[maps['candidate'][param,i][0] for i in range(10)]
            require(len({o[0] for o in outputs})==10 and len({o[1] for o in outputs})==10,'repeated keys')
            ops={'keygen','sign','verify'} | ({'keygen_sign'} if provider=='rustcrypto' else set())
            for i in range(10):
                c,b=(maps[s][param,i] for s in ['candidate','baseline'])
                require(c[0]==b[0], 'different keys/signatures/seed')
                require(set(c[1])==set(b[1])==ops,'operation set')
                for m in [c[1],b[1]]:
                    for wall,cpu in m.values():
                        require(type(wall) is int and wall>0 and type(cpu) is int and cpu>=0,'invalid timing')
            key_count+=10
            for op in sorted(ops):
                c=[maps['candidate'][param,i][1][op] for i in range(10)]
                b=[maps['baseline'][param,i][1][op] for i in range(10)]
                ratios=[y[0]/x[0] for x,y in zip(c,b)]
                ct,bt=([sum(v[j] for v in values) for j in [0,1]] for values in [c,b])
                summary.append(dict(provider=provider,parameter=param,operation=op,keys=10,candidate_wall_ns=ct[0],baseline_wall_ns=bt[0],total_wall_speedup=bt[0]/ct[0],candidate_cpu_ns=ct[1],baseline_cpu_ns=bt[1],total_cpu_speedup=bt[1]/ct[1] if ct[1] else None,per_key_wall_speedups=ratios,median_wall_speedup=statistics.median(ratios),wall_losses=sum(r<1 for r in ratios)))
    require(key_count==380 and len(summary)==117,'overall coverage')
    args.out.write_text(json.dumps(dict(complete=True,exact_outputs_match=True,all_candidates_before_baselines=True,distinct_key_pairs=key_count,operation_pairs=len(summary)*10,input_sha256=bindings,summary=summary),indent=2)+'\n')
    print(f'PASS: {key_count} exact key/signature pairs, {len(summary)*10} operation pairs, 12 ordered batches')

if __name__=='__main__':
    main()
