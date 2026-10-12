#!/usr/bin/env python3
"""Independent raw-record and exact-output review of the completed ten-key batches."""
import datetime
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PROVIDER=HERE.parent.name
RUST=PROVIDER=='rustcrypto'
RESULTS=ROOT/'results'/PROVIDER/'experiments'
PARAMETERS=['ML-DSA-44','ML-DSA-65','ML-DSA-87'] if RUST else [f'{a}_{b}{c}' for a in ['sha2','shake'] for b in [128,192,256] for c in ['f','s']]
OPERATIONS=['keygen','sign','verify','keygen_sign'] if RUST else ['keygen','sign','verify']

def read(p): return json.loads(Path(p).read_text())
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def median(values):
    x=sorted(values); n=len(x)
    return x[n//2] if n%2 else (x[n//2-1]+x[n//2])/2

def tree(path,classes=False):
    h=hashlib.sha256(); root=Path(path)
    for p in sorted(root.rglob('*.class' if classes else '*')):
        if p.is_file() and '.git' not in p.parts: h.update(str(p.relative_to(root)).encode()+b'\0'+bytes.fromhex(sha(p)))
    return h.hexdigest()

candidate=read(RESULTS/'tenkey-candidate.json'); baseline=read(RESULTS/'tenkey-baseline.json')
comparison=read(RESULTS/'tenkey-comparison.json'); prepared=candidate['prepared']; original=prepared['old']
assert prepared==baseline['prepared'] and prepared['provider']==PROVIDER
assert prepared['parameters']==PARAMETERS and prepared['operations']==OPERATIONS
assert prepared['measured_keys']==10 and prepared['warmup_keys']==2
assert candidate['finished_at']<baseline['started_at']
assert candidate['manifest_sha256']==baseline['manifest_sha256']
manifest=(Path(prepared['cargo_manifest']).parent if RUST else Path(prepared['driver']).parent)/'manifest.json'
assert read(manifest)==prepared and sha(manifest)==candidate['manifest_sha256']
if RUST: cases=read(prepared['fixtures'])['cases']; inputs=read(prepared['corpus'])['cases']
else:
    fields=['phase','parameter','index','seed','message','context','entropy','pk','sk','signature']
    def corpus(p):
        lines=Path(p).read_text().splitlines(); assert lines[0]=='pqc-tenkeys-v1/bouncycastle'
        result=[dict(zip(fields,line.split('\t'))) for line in lines[1:]]
        for row in result: row['index']=int(row['index'])
        return result
    cases=corpus(prepared['fixtures']); inputs=corpus(prepared['corpus'])
assert len(cases)==len(inputs)==12*len(PARAMETERS)
assert len({x['seed'] for x in cases})==len(cases)
assert len({x['pk'] for x in cases})==len(cases)
for c,i in zip(cases,inputs):
    for k in ['phase','parameter','index','seed','message','context','entropy']: assert c[k]==i[k]
expected=[c for c in cases if c['phase']=='measured']
assert [(x['parameter'],x['index']) for x in expected]==[(p,i) for p in PARAMETERS for i in range(10)]
processes=0; operation_pairs=0; zero_cpu=0
for side,data in [('candidate',candidate),('baseline',baseline)]:
    assert data['schema']=='pqc-tenkey-batch-v1' and data['provider']==PROVIDER and data['variant']==side and data['python_optimize']==0
    assert len(data['rows'])==10*len(PARAMETERS)
    raw=Path(data['raw_directory']); plan=read(raw/'plan.json')
    assert plan['prepared']==prepared and plan['variant']==side and plan['started_at']==data['started_at']
    assert plan['manifest_sha256']==data['manifest_sha256']
    assert len(list(raw.iterdir()))==1+5*len(PARAMETERS)
    previous=data['started_at']
    for p in PARAMETERS:
        rows=[r for r in data['rows'] if r['parameter']==p]
        assert rows==read(raw/(p+'.rows.json'))
        assert rows==[json.loads(line) for line in (raw/(p+'.stdout.txt')).read_text().splitlines()]
        assert not (raw/(p+'.stderr.txt')).read_text()
        command=read(raw/(p+'.command.json')); status=read(raw/(p+'.status.json'))
        assert status['exit_code']==0
        assert previous<=command['started_at']<status['finished_at']<=data['finished_at']
        previous=status['finished_at']
        want=[prepared['binary'],'bench',prepared['fixtures'],p,side] if RUST else [original['java'],'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',':'.join([prepared['driver'],original[side]]),'TenKeyBenchmark','bench',prepared['fixtures'],p,side]
        assert command['command']==want and command['cwd'] is None
        processes+=1
    for row,case in zip(data['rows'],expected):
        for k in ['parameter','phase','index','seed','pk','sk','signature']: assert row[k]==case[k],k
        assert row['variant']==side and row['valid'] is True and row['tamper_rejected'] is True
        if not RUST: assert row['class_source']==str(Path(original[side]).resolve())
        assert set(row['metrics'])==set(OPERATIONS)
        for m in row['metrics'].values():
            assert type(m['elapsed_ns']) is int and m['elapsed_ns']>0
            assert type(m['cpu_ns']) is int and m['cpu_ns']>=0
            if not RUST: assert type(m['thread_cpu_ns']) is int and m['thread_cpu_ns']>=0
            zero_cpu+=m['cpu_ns']==0
assert len(comparison['summary'])==len(PARAMETERS)*len(OPERATIONS)
for parameter in PARAMETERS:
    changed=[x for x in candidate['rows'] if x['parameter']==parameter]
    unchanged=[x for x in baseline['rows'] if x['parameter']==parameter]
    for operation in OPERATIONS:
        record=next(x for x in comparison['summary'] if x['parameter']==parameter and x['operation']==operation)
        ratios=[]
        for c,b in zip(changed,unchanged):
            for key in ['parameter','phase','index','seed','pk','sk','signature','valid','tamper_rejected']: assert c[key]==b[key]
            ratios.append(b['metrics'][operation]['elapsed_ns']/c['metrics'][operation]['elapsed_ns']); operation_pairs+=1
        cwall=sum(x['metrics'][operation]['elapsed_ns'] for x in changed); bwall=sum(x['metrics'][operation]['elapsed_ns'] for x in unchanged)
        ccpu=sum(x['metrics'][operation]['cpu_ns'] for x in changed); bcpu=sum(x['metrics'][operation]['cpu_ns'] for x in unchanged)
        assert record['candidate_wall_total_ns']==cwall and record['baseline_wall_total_ns']==bwall
        assert record['speedup']==bwall/cwall and record['key_ratios']==ratios
        assert record['median_key_ratio']==median(ratios) and record['min_key_ratio']==min(ratios) and record['max_key_ratio']==max(ratios)
        assert record['losses']==sum(r<1 for r in ratios)
        assert record['candidate_cpu_total_ns']==ccpu and record['baseline_cpu_total_ns']==bcpu
        assert record['cpu_speedup']==(bcpu/ccpu if ccpu else None)
        assert record['zero_cpu_samples']==sum(x['metrics'][operation]['cpu_ns']==0 for x in changed+unchanged)
        if not RUST:
            for side,rows in [('candidate',changed),('baseline',unchanged)]: assert record[side+'_thread_cpu_total_ns']==sum(x['metrics'][operation]['thread_cpu_ns'] for x in rows)
assert comparison['candidate_sha256']==sha(RESULTS/'tenkey-candidate.json') and comparison['baseline_sha256']==sha(RESULTS/'tenkey-baseline.json')
for side,data in [('candidate',candidate),('baseline',baseline)]:
    for point in ['started_at','finished_at']: assert comparison[side+'_'+point]==data[point]
provenance=prepared['provenance']
assert provenance['collector']==sha(HERE/'tenkey.py')
assert provenance['driver_source']==sha(HERE/('tenkey.rs' if RUST else 'TenKeyBenchmark.java'))
for key in ['corpus','fixtures']: assert provenance[key]==sha(prepared[key])
if RUST:
    for key in ['binary','cargo_manifest','cargo_lock']: assert provenance[key]==sha(prepared[key])
    assert provenance['driver_copy']==sha(Path(prepared['cargo_manifest']).parent/'src/main.rs')==provenance['driver_source']
else:
    assert provenance['driver_classes']==tree(prepared['driver'],True)
    assert provenance['java_binary']==sha(original['java'])
assert provenance['original']==original['provenance']
for key,want in original['provenance'].items():
    if RUST and key in ['baseline_source','candidate_source']: actual=tree(original[key])
    elif RUST and key=='driver_copy': actual=sha(Path(original['cargo_manifest']).parent/'src/main.rs')
    elif RUST and key in ['binary','fixtures','corpus','cargo_lock','cargo_manifest']: actual=sha(original[key])
    elif not RUST and key=='fixture': actual=sha(original['fixtures'])
    elif not RUST and key.endswith('_classes'): actual=tree(original[key.removesuffix('_classes')],True)
    else: actual=sha(ROOT/key)
    assert actual==want,key
review={'schema':'pqc-tenkey-independent-review-v1','provider':PROVIDER,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'candidate_sha256':sha(RESULTS/'tenkey-candidate.json'),'baseline_sha256':sha(RESULTS/'tenkey-baseline.json'),
    'comparison_sha256':sha(RESULTS/'tenkey-comparison.json'),'reviewer_sha256':sha(__file__),
    'key_pairs':len(expected),'operation_pairs':operation_pairs,'processes':processes,'summary_cells':len(comparison['summary']),
    'zero_process_cpu_samples':zero_cpu,'exact_output_comparisons':True,
    'checks':['All distinct seed and public-key counts; disjoint warmup and ten measured indices per parameter',
        'Every raw stdout/rows/command/status matches complete batches; no stderr and all processes exit zero',
        'Every generated key/signature byte matches prepared fixture and other variant; every valid/tampered outcome checked',
        'Independent integer wall/CPU totals and all key ratios, sorted-middle medians, ranges and loss counts recomputed',
        'Prepared manifest, driver/collector, binary/classes, corpus/fixtures, original source/classes and production patch hashes match',
        'Candidate completes before baseline starts for this provider; global six-provider order is recorded by the root coordinator']}
output=RESULTS/'tenkey-independent-review.json'
with output.open('x') as f: json.dump(review,f,indent=2); f.write('\n')
print(json.dumps(review,indent=2))
