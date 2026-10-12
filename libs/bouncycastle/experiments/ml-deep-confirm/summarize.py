#!/usr/bin/env python3
"""Summarize paired screen outputs; the separate reviewer checks raw/source/corpus bindings."""
import argparse, hashlib, json, statistics, sys
from pathlib import Path
if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def metrics(before, after):
    assert set(before)==set(after) and before
    original_wall=sum(s['wall_ns'] for s in before.values());changed_wall=sum(s['wall_ns'] for s in after.values())
    original_cpu=sum(s['cpu_ns'] for s in before.values());changed_cpu=sum(s['cpu_ns'] for s in after.values())
    original_alloc=sum(s['allocated_bytes'] for s in before.values());changed_alloc=sum(s['allocated_bytes'] for s in after.values())
    ratios=[before[k]['wall_ns']/after[k]['wall_ns'] for k in before]
    assert all(before[k]['output_sha256']==after[k]['output_sha256'] for k in before)
    return {'count':len(ratios),'original_wall_ns_sum':original_wall,'changed_wall_ns_sum':changed_wall,
        'wall_speedup':original_wall/changed_wall,'original_cpu_ns_sum':original_cpu,'changed_cpu_ns_sum':changed_cpu,
        'thread_cpu_speedup':original_cpu/changed_cpu,'original_alloc_bytes_sum':original_alloc,
        'changed_alloc_bytes_sum':changed_alloc,'allocated_bytes_saved_per_call':(original_alloc-changed_alloc)/len(ratios),
        'losses':sum(x<1 for x in ratios),'ratio_median':statistics.median(ratios),'ratio_min':min(ratios),'ratio_max':max(ratios)}
def summarize(folder):
    path=folder/'execution.json';execution=json.loads(path.read_text())
    assert execution.get('completed_at') and not execution['profile_only']
    assert execution['measurement_variants']==['baseline','combined'] and execution['rounds']==6
    rows={}
    for run in execution['runs']:
        assert run['exit_code']==0 and sha(folder/run['raw'])==run['raw_sha256'] and sha(folder/run['stdout'])==run['stdout_sha256']
        raw=json.loads((folder/run['raw']).read_text());stdout=json.loads((folder/run['stdout']).read_text())
        assert all(raw[k]==v for k,v in stdout.items())
        key=(run['parameter'],run['operation'],run['variant'],run['round']);assert key not in rows
        samples={s['case_id']:s for s in raw['samples']};assert len(samples)==len(raw['samples'])==128
        rows[key]=samples
    cells=[]
    for parameter,operation in sorted({key[:2] for key in rows}):
        for variant in ['combined']:
            all_before={};all_after={};per_round=[];per_key=[]
            for rnd in range(execution['rounds']):
                before=rows[(parameter,operation,'baseline',rnd)];after=rows[(parameter,operation,variant,rnd)]
                per_round.append({'round':rnd,**metrics(before,after)})
                for case_id in sorted(before):
                    all_before[(rnd,case_id)]=before[case_id];all_after[(rnd,case_id)]=after[case_id]
                    per_key.append({'round':rnd,'case_id':case_id,'ratio':before[case_id]['wall_ns']/after[case_id]['wall_ns']})
            cells.append({'parameter':parameter,'operation':operation,'variant':variant,'paired_rounds':execution['rounds'],
                **metrics(all_before,all_after),'per_round':per_round,'per_key_ratios':per_key})
    result={'schema':'bc-ml-deep-confirm-summary-v1','execution_sha256':sha(path),'sampler_only':execution['sampler_only'],
        'primary':'sum(original wall ns) / sum(changed wall ns), identical keys and rounds','cells':cells}
    out=folder/'summary.json'
    with out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    return out
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('folder',type=Path);args=p.parse_args();print(summarize(args.folder))
