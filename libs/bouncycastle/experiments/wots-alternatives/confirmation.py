#!/usr/bin/env python3
"""Selected192/256f confirmation. Plan and audit are read-only with respect to crypto."""
import argparse,datetime,json,os,shutil,statistics,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')
sys.path.insert(0,str(Path(__file__).resolve().parent))
import run
SCREEN=run.OUT
OUT=SCREEN/'confirmation'
def prescribe():
    OUT.mkdir(exist_ok=False)
    selection=json.loads((SCREEN/'selection.json').read_text());initial=json.loads((SCREEN/'plan.json').read_text())
    selected=[d['variant'] for d in selection['decisions'] if d['selected']]
    assert selected==['object_hoist','field_rewrite','two_addresses','buffer']
    for name in ['manifest.json','gates.json']:shutil.copyfile(SCREEN/name,OUT/name)
    jobs=[]
    for mode in ['bench','allocation']:
        for p in initial['followup']['parameters']:
            for op in run.OPS:
                for variant in selected:
                    for fork in range(2):
                        for v in (['baseline',variant] if fork==0 else [variant,'baseline']):jobs.append(dict(mode=mode,parameter=p,operation=op,comparison=['baseline',variant],fork=fork,variant=v,warmup_calls=20))
    assert len(jobs)==384
    run.write(OUT/'plan.json',dict(created_at=run.stamp(),jobs=jobs,manifest_sha256=run.sha(OUT/'manifest.json'),screen_plan_sha256=run.sha(SCREEN/'plan.json'),screen_summary_sha256=run.sha(SCREEN/'summary.json'),selection_sha256=run.sha(SCREEN/'selection.json'),script_sha256=run.sha(__file__),scope='Selected confirmation of four individual mechanisms in all four192/256f configurations.20 warmup calls on2 disjoint keys;10 measured keys once/process;two balanced pairs;separate timing/allocation. Keep every screen loss. Field rewrite advanced through signing improvement despite repeatable128f keygen loss; peeled was rejected due direct-stock128f keygen loss. No winner combination.'))
    print('Sealed384process selected confirmation; no measurements started.')
def audit():
    m=json.loads((OUT/'manifest.json').read_text());p=json.loads((OUT/'plan.json').read_text());e=json.loads((OUT/'execution.json').read_text());s=json.loads((OUT/'summary.json').read_text())
    assert run.sha(__file__)==p['script_sha256'] and run.sha(SCREEN/'selection.json')==p['selection_sha256']
    assert run.sha(SCREEN/'plan.json')==p['screen_plan_sha256'] and run.sha(SCREEN/'summary.json')==p['screen_summary_sha256']
    assert run.sha(OUT/'manifest.json')==p['manifest_sha256']==e['manifest_sha256'] and run.sha(OUT/'plan.json')==e['plan_sha256'] and run.sha(OUT/'execution.json')==s['execution_sha256']
    assert len(p['jobs'])==len(e['runs'])==384
    expected={}
    for parameter in ['sha2_192f','sha2_256f','shake_192f','shake_256f']:
        for x in map(json.loads,(SCREEN/('check-baseline-'+parameter+'.stdout.jsonl')).read_text().splitlines()):
            if x['phase']=='measured':expected[(parameter,x['case'],x['operation'])]=x['output_sha256']
    slots={};starts=[];ends=[]
    for i,(record,j) in enumerate(zip(e['runs'],p['jobs'])):
        assert record['job']==j;stem=f'run-{i:03d}';v=j['variant'];assert record['raw']==stem+'.stdout.jsonl' and run.sha(OUT/record['raw'])==record['sha256']
        command=json.loads((OUT/(stem+'.command.json')).read_text());status=json.loads((OUT/(stem+'.status.json')).read_text());assert status['exit_code']==0
        assert command['command']==run.command(m,v,'WotsAlternativeProbe',j['mode'],m['fixtures'],j['parameter'],v,j['operation'],j['fork'],j['warmup_calls'])
        starts.append(datetime.datetime.fromisoformat(command['started_at']));ends.append(datetime.datetime.fromisoformat(status['finished_at']))
        rows=list(map(json.loads,(OUT/record['raw']).read_text().splitlines()));assert len(rows)==10 and [r['case'] for r in rows]==list(range(10))
        for x in rows:
            assert all(x[k]==j[k] for k in ['mode','variant','parameter','operation','fork','warmup_calls']) and x['warmup_calls']==20
            assert x['checked'] and x['class_source']==m['classes'][v] and x['output_sha256']==expected[(x['parameter'],x['case'],x['operation'])]
            assert all(x[k]>=0 for k in ['wall_ns','thread_cpu_ns','cpu_ns','allocated_bytes'])
            assert x['allocated_bytes']==0 if j['mode']=='bench' else x['wall_ns']==x['thread_cpu_ns']==x['cpu_ns']==0
        key=(j['mode'],j['parameter'],j['operation'],tuple(j['comparison']));slots.setdefault(key,{})[(j['fork'],v)]={k:statistics.mean(r[k] for r in rows) for k in ['wall_ns','thread_cpu_ns','allocated_bytes']}
    assert all(ends[i]<=starts[i+1] for i in range(383));assert len(s['cells'])==len(slots)==96
    for c in s['cells']:
        key=(c['mode'],c['parameter'],c['operation'],tuple(c['comparison']));a,b=c['comparison']
        for metric,x in c['metrics'].items():
            aa=[slots[key][i,a][metric] for i in range(2)];bb=[slots[key][i,b][metric] for i in range(2)]
            assert x['reference_process_means']==aa and x['candidate_process_means']==bb
            assert x['paired_change_percent']==[100*(y/z-1) for z,y in zip(aa,bb)] and x['aggregate_change_percent']==100*(statistics.mean(bb)/statistics.mean(aa)-1)
    print(json.dumps(dict(audit='saved_confirmation_passed',processes=384,observations=3840,cells=96,binary_checks='Use audit.py for local binary seals or audit_portable.py for explicit binary availability; this checker verifies saved confirmation data.')))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['plan','collect','audit']);parser.add_argument('--window');a=parser.parse_args()
    if a.mode=='plan':prescribe()
    elif a.mode=='audit':audit()
    else:run.OUT=OUT;run.collect(a.window)
