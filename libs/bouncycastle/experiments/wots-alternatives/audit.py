#!/usr/bin/env python3
"""Independent raw evidence and arithmetic audit. Never executes cryptography."""
import collections,datetime,gzip,hashlib,json,pathlib,statistics,sys,tarfile
if sys.flags.optimize:
    raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')
root=pathlib.Path(sys.argv[1]).resolve() if len(sys.argv)>1 else pathlib.Path(__file__).resolve().parents[4]
p=root/'results/bouncycastle/wots-alternatives'
read=lambda n:json.loads((p/n).read_text())
sha=lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
m=read('manifest.json');g=read('gates.json');plan=read('plan.json')
assert g['passed'] and g['manifest_sha256']==sha(p/'manifest.json')==plan['manifest_sha256']
assert all(sha(root/k)==v for k,v in m['files'].items())
for name,key in [('run.py','collector_sha256'),('prescribe.py','plan_writer_sha256'),('audit.py','audit_sha256')]:assert sha(root/'libs/bouncycastle/experiments/wots-alternatives'/name)==plan[key]
assert sha(m['java'])==m['java_sha256'] and sha(m['javac'])==m['javac_sha256']
for field,hashes in [('classes','class_hashes'),('drivers','driver_hashes')]:
    for v,folder in m[field].items():
        folder=pathlib.Path(folder);actual={str(f.relative_to(folder)):sha(f) for f in sorted(folder.rglob('*.class'))};assert actual==m[hashes][v]
        if field=='drivers':assert not any(k.endswith('/WotsPlus.class') for k in actual)
parent=read('preparation/parent-manifest.json')
assert sha(p/'preparation/parent-manifest.json')==m['parent_manifest_sha256']
assert sha(m['fixtures'])==parent['provenance']['files'][parent['fixtures']]
with gzip.open(p/'preparation/baseline-source.tar.gz','rb') as f:
    archive_digest=hashlib.sha256(f.read()).hexdigest()
assert archive_digest==next(h for k,h in parent['provenance']['files'].items() if k.endswith('/baseline-source.tar'))
expected={};check_count={};trace0=None
for v in m['variants']:
    traces=[json.loads(x) for x in (p/('trace-'+v+'.stdout.jsonl')).read_text().splitlines()]
    if trace0 is None:trace0=traces
    assert traces==trace0 and len(traces)==24 and all(r['ownership'] for r in traces)
    chain=[json.loads(x) for x in (p/('chain-'+v+'.stdout.jsonl')).read_text().splitlines()];assert chain==[dict(checked=True,cases=g['native_chain_cases_per_variant'])]
    check_count[v]=0
    for parameter in m['parameters']:
        name='check-'+v+'-'+parameter;rs=[json.loads(x) for x in (p/(name+'.stdout.jsonl')).read_text().splitlines()]
        coverage={(phase,i,op) for phase,n in [('warmup',2),('measured',10)] for i in range(n) for op in ['keygen.total','sign.total','verify.total']} if parameter.endswith('f') else {('measured',0,op) for op in ['keygen.total','sign.total','verify.total']}
        assert len(rs)==len(coverage) and {(x['phase'],x['case'],x['operation']) for x in rs}==coverage
        assert read(name+'.status.json')['exit_code']==0;check_count[v]+=len(rs)
        for x in rs:
            assert x['checked'] and x['class_source']==m['classes'][v] and x['variant']==v and x['parameter']==parameter
            key=(parameter,x['phase'],x['case'],x['operation'])
            if v=='baseline':expected[key]=x['output_sha256']
            assert x['output_sha256']==expected[key]
assert set(check_count.values())=={234} and g['whole_checks_per_variant']==234
assert len(plan['jobs'])==288
if not (p/'execution.json').exists():
    print(json.dumps(dict(audit='preparation_passed',trace_cases=24,chain_cases_per_variant=g['native_chain_cases_per_variant'],checks_per_variant=234,variants=len(m['variants']),planned_processes=288)));sys.exit(0)
e=read('execution.json');s=read('summary.json');assert e['passed'] and e['manifest_sha256']==sha(p/'manifest.json') and e['plan_sha256']==sha(p/'plan.json');assert s['execution_sha256']==sha(p/'execution.json')
assert len(e['runs'])==288;slots={};counts=collections.Counter();ends=[];starts=[]
for i,(record,job) in enumerate(zip(e['runs'],plan['jobs'])):
    assert record['job']==job;name=f'run-{i:03d}';v=job['variant'];assert record['raw']==name+'.stdout.jsonl' and sha(p/record['raw'])==record['sha256']
    c=read(name+'.command.json');status=read(name+'.status.json');assert status['exit_code']==0
    assert c['command']==[m['java'],*m['jvm_args'],'-cp',m['drivers'][v]+':'+m['classes'][v],'org.bouncycastle.crypto.signers.slhdsa.WotsAlternativeProbe',job['mode'],m['fixtures'],job['parameter'],v,job['operation'],str(job['fork']),str(job['warmup_calls'])]
    starts.append(datetime.datetime.fromisoformat(c['started_at']));ends.append(datetime.datetime.fromisoformat(status['finished_at']))
    rs=[json.loads(x) for x in (p/record['raw']).read_text().splitlines()];assert len(rs)==10 and [x['case'] for x in rs]==list(range(10));counts[job['mode']]+=len(rs)
    for x in rs:
        assert all(x[k]==job[k] for k in ['mode','variant','parameter','operation','fork','warmup_calls']) and x['warmup_calls']==20
        assert x['checked'] and x['class_source']==m['classes'][v] and x['output_sha256']==expected[(x['parameter'],'measured',x['case'],x['operation'])]
        assert all(x[k]>=0 for k in ['wall_ns','cpu_ns','thread_cpu_ns','allocated_bytes'])
        assert (x['allocated_bytes']==0) if job['mode']=='bench' else (x['wall_ns']==x['cpu_ns']==x['thread_cpu_ns']==0)
    key=(job['mode'],job['parameter'],job['operation'],*job['comparison']);slots.setdefault(key,{})[(job['fork'],v)]={k:statistics.mean(x[k] for x in rs) for k in ['wall_ns','thread_cpu_ns','allocated_bytes']}
assert all(ends[i]<=starts[i+1] for i in range(287));assert len(s['cells'])==72 and len(slots)==72
for cell in s['cells']:
    key=(cell['mode'],cell['parameter'],cell['operation'],*cell['comparison']);a,b=cell['comparison']
    for metric,x in cell['metrics'].items():
        aa=[slots[key][i,a][metric] for i in range(2)];bb=[slots[key][i,b][metric] for i in range(2)]
        assert x['reference_process_means']==aa and x['candidate_process_means']==bb
        assert x['paired_change_percent']==[100*(y/z-1) for z,y in zip(aa,bb)]
        assert x['aggregate_change_percent']==100*(statistics.mean(bb)/statistics.mean(aa)-1)
print(json.dumps(dict(audit='passed',processes=288,rows=counts,cells=72,checks_per_variant=234,variants=6,no_overlapping_recorded_processes=True),indent=2))
