#!/usr/bin/env python3
"""Recompute complete C-provider indicator summaries from sealed raw processes."""
import argparse, datetime, json, statistics
from pathlib import Path
import collect

ROOT=Path(__file__).resolve().parents[4]
def relative(path):return str(Path(path).resolve().relative_to(ROOT))
def percent(candidate,baseline):return 100*(candidate/baseline-1) if baseline else None
def metric(original,changed,statistic='mean',unit='bytes'):
    fn=statistics.mean if statistic=='mean' else statistics.median
    a,b=fn(original),fn(changed)
    return dict(unit=unit,statistic=statistic,baseline=a,candidate=b,change_percent=percent(b,a),percent_denominator='baseline '+statistic,percent_unavailable_reason=None if a else 'zero baseline',baseline_observations=original,candidate_observations=changed,paired_changes_percent=[percent(y,x) for x,y in zip(original,changed)])
def execution(path,ready,manifest,phase):
    status=json.loads((path/'execution.json').read_text());plan=collect.jobs(ready,phase)
    collect.need(status['complete'] is True and status['jobs']==plan and len(status['executed'])==len(plan),'incomplete/wrong execution plan')
    collect.need(status['manifest_sha256']==collect.sha(manifest) and status['collector_sha256']==collect.sha(Path(__file__).with_name('collect.py')),'collector/manifest binding changed')
    result=[];previous=datetime.datetime.fromisoformat(status['started_at']);specs={p['parameter']:p for p in ready['parameters']}
    for i,(job,run) in enumerate(zip(plan,status['executed'])):
        spec=specs[job['parameter']]
        cmd=[ready['binaries'][job['side']],job['mode'],spec['native_parameter'],spec['input'],spec['corpus'],str(job['op']),str(job['key'])]
        collect.need(run['index']==i and run['job']==job and run['command']==cmd and type(run['returncode']) is int and run['returncode']==0,'wrong/failed process')
        start=datetime.datetime.fromisoformat(run['started_at']);finish=datetime.datetime.fromisoformat(run['finished_at'])
        collect.need(previous<=start<=finish,'overlapping/out-of-order process intervals');previous=finish
        raw=path/run['raw_file'];err=path/run['stderr_file']
        collect.need(raw.name==f'{i:03d}.jsonl' and err.name==f'{i:03d}.stderr' and collect.sha(raw)==run['raw_sha256'] and collect.sha(err)==run['stderr_sha256'],'raw evidence changed')
        rows=collect.validate([json.loads(line) for line in raw.read_text().splitlines()],job,spec)
        result.append(dict(job=job,rows=rows,source=relative(raw)))
    collect.need(previous<=datetime.datetime.fromisoformat(status['finished_at']),'wrong completion time')
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--timings',type=Path,required=True);p.add_argument('--resources',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    ready=collect.checked_manifest(args.manifest);timings=execution(args.timings,ready,args.manifest,'baseline-timing');resources=execution(args.resources,ready,args.manifest,'resources')
    baseline=[]
    for spec in ready['parameters']:
        if not spec['baseline_timing']:continue
        for op in range(3):
            batches=[b for b in timings if b['job']['parameter']==spec['parameter'] and b['job']['op']==op]
            collect.need(len(batches)==3 and {b['job']['fork'] for b in batches}==set(range(3)),'missing timing forks')
            wall=[r['wall_ns'] for b in batches for r in b['rows']];cpu=[r['cpu_ns'] for b in batches for r in b['rows']]
            baseline.append(dict(library=ready['provider'],parameter=spec['parameter'],operation=collect.OPS[op],comparison='baseline_only',wall_ns=statistics.mean(wall),cpu_ns=statistics.mean(cpu),unit='ns/op',statistic='arithmetic mean of 30 calls (10 distinct keys repeated in 3 fresh processes)',protocol='c-provider-indicators-v1: one disjoint warmup, fresh operation object/context per call, key import and output checking outside clocks',source=relative(args.out),raw_sources=[b['source'] for b in batches],wall_process_means=[statistics.mean(r['wall_ns'] for r in b['rows']) for b in batches],cpu_process_means=[statistics.mean(r['cpu_ns'] for r in b['rows']) for b in batches],wall_min_ns=min(wall),wall_max_ns=max(wall),candidate_wall_ns=None,candidate_reason='Published patch does not change this algorithm path; no candidate gain measured'))
    records=[]
    allocation_fields=['allocations','allocated_requested_bytes','peak_tracked_live_bytes','retained_at_return_bytes','net_after_cleanup_bytes','frees']
    for spec in ready['parameters']:
        if not spec['paired_resource']:continue
        for op in range(3):
            record=dict(library=ready['provider'],parameter=spec['parameter'],operation=collect.OPS[op],comparison='paired',measurement_kind='resource diagnostic; no timing',metrics={},raw_sources=[])
            for mode in ['allocation','rss','stack-a5']:
                sides={}
                for side in ['baseline','candidate']:
                    batches=sorted([b for b in resources if b['job']['parameter']==spec['parameter'] and b['job']['op']==op and b['job']['mode']==mode and b['job']['side']==side],key=lambda b:b['job']['key'])
                    collect.need(len(batches)==4 and [b['job']['key'] for b in batches]==[1,2,3,4],'missing resource key pairs')
                    sides[side]=[b['rows'][0] for b in batches];record['raw_sources'].extend(b['source'] for b in batches)
                fields=allocation_fields if mode=='allocation' else ['peak_rss_pre_bytes','peak_rss_post_bytes'] if mode=='rss' else ['observed_overwritten_thread_stack_bytes']
                for field in fields:
                    record['metrics'][field]=metric([r[field] for r in sides['baseline']],[r[field] for r in sides['candidate']],statistic='mean' if mode=='allocation' else 'median',unit='count' if field in ['allocations','frees'] else 'bytes')
                if mode=='rss':record['metrics']['peak_rss_new_high_water_bytes']=metric([r['peak_rss_post_bytes']-r['peak_rss_pre_bytes'] for r in sides['baseline']],[r['peak_rss_post_bytes']-r['peak_rss_pre_bytes'] for r in sides['candidate']],statistic='median')
            record.update(wall_ns=None,cpu_ns=None,stack_label='Observed overwritten dedicated-thread stack extent with 0xa5 paint; includes thread startup/exit, detects changed bytes only, not an exact operation peak',allocation_label='Full public operation through configured OpenSSL/OQS allocation hooks; caller buffers and preexisting/imported key outside window; returned new key freed after return accounting',rss_label='Cold fresh-process getrusage peak RSS, before/after core; includes runtime, loaded corpus, imported key and process overhead; independent of stack-paint process')
            records.append(record)
    controls=[dict(job=b['job'],source=b['source'],observed_overwritten_thread_stack_bytes=b['rows'][0]['observed_overwritten_thread_stack_bytes']) for b in resources if b['job']['mode'] in ['stack-5a','stack-control-a5','stack-control-5a']]
    collect.need(len(controls)==8,'missing stack controls')
    summary=dict(schema='c-provider-indicators-summary-v1',complete=True,library=ready['provider'],source_binding=ready['source_binding'],protocol=ready['protocol'],manifest_sha256=collect.sha(args.manifest),execution_sha256={phase:collect.sha(path/'execution.json') for phase,path in [('baseline-timing',args.timings),('resources',args.resources)]},baseline_timings=baseline,resource_records=records,stack_controls=controls,capabilities=[dict(library=ready['provider'],parameter=c['parameter'],supported=c['supported'],baseline_timings=None,reason=c['scope']) for c in ready['capabilities']],limits=['Within-provider observations only; no cross-provider ranking.','Peak RSS is a noisy process measure; small differences do not resolve an operation-level byte delta.','Painted-stack extent is a diagnostic lower bound on touched depth, includes startup/exit, and is not a formal maximum stack-use proof. No-op floor is reported, not subtracted.','Metrics not collected in a mode are omitted or null; raw zero placeholders are not zero-resource claims.','Full-operation allocation counters cover configured OpenSSL/OQS allocator entry points, not all possible system mmap/allocator internals.'])
    summary['unsupported']=[dict(library=ready['provider'],parameter=c['parameter'],operations=collect.OPS,reason=c['scope']+' at pinned baseline '+ready['baseline_commit']+'; EVP_PKEY_CTX_new_from_name returned unavailable',source=relative(Path(ready['parameters'][0]['input']).parent/(c['parameter']+'-support.json'))) for c in ready['capabilities'] if not c['supported']]
    collect.write(args.out,summary);print(args.out)
if __name__=='__main__':main()
