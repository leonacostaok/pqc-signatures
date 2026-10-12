import collections,hashlib,json,math,pathlib,statistics,sys
if sys.flags.optimize: raise SystemExit('Assertions must remain enabled')
p=pathlib.Path(sys.argv[1]); d=json.loads(p.read_text()); raw=pathlib.Path(str(p)+'.raw')
assert (d['schema'],d['forks'],d['start_fork'],d['rounds'],d['budget_ms'],d['warmup_ms'],d['python_optimize'])==('bc-fors-isolated-verify-v1',6,20,6,250,2000,0)
params={f'{f}_{s}{k}' for f in ['sha2','shake'] for s in [128,192,256] for k in ['f','s']}
expected={(p,f) for p in params for f in range(20,26)}; seen=set();groups=collections.defaultdict(list);nrows=0
close=lambda a,b: math.isclose(a,b,rel_tol=1e-12)
for q in d['process_pairs']:
 key=(q['parameter'],q['fork']);assert key in expected and key not in seen;seen.add(key)
 assert q==json.loads((raw/f"{q['fork']:04d}-{q['parameter']}.pair.json").read_text())
 for side in ['baseline','candidate']:
  record=q[side]; rows=record['rows'];assert len(rows)==6 and [r['round'] for r in rows]==list(range(6))
  stem=f"{q['fork']:04d}-{q['parameter']}-{side}"
  assert json.loads((raw/(stem+'.status.json')).read_text())['exit_code']==0
  assert [json.loads(line) for line in (raw/(stem+'.stdout.txt')).read_text().splitlines()]==rows
  assert json.loads((raw/(stem+'.command.json')).read_text())['command']==record['command']
  for r in rows:
   assert (r['variant'],r['parameter'],r['fork'])==(side,*key)
   assert r['iterations']>0 and r['iterations']%2==0 and r['elapsed_ns']>=250000000 and r['cpu_ns']>0
   assert r['class_source']==str(pathlib.Path(d['prepared']['prepared'][side]).resolve())
   nrows+=1
  assert close(record['median_ns'],statistics.median(r['elapsed_ns']/r['iterations'] for r in rows))
  assert close(record['median_cpu_ns'],statistics.median(r['cpu_ns']/r['iterations'] for r in rows))
 assert close(q['speedup'],q['baseline']['median_ns']/q['candidate']['median_ns'])
 assert close(q['cpu_speedup'],q['baseline']['median_cpu_ns']/q['candidate']['median_cpu_ns'])
 groups[q['parameter']].append(q)
assert seen==expected and nrows==864
summaries=[];recorded={r['parameter']:r for r in d['summary']};assert set(recorded)==params and len(d['summary'])==12
for parameter,rows in sorted(groups.items()):
 assert sum(r['order']==['baseline','candidate'] for r in rows)==3
 assert sum(r['order']==['candidate','baseline'] for r in rows)==3
 ratios=[r['speedup'] for r in rows]; cpu=[r['cpu_speedup'] for r in rows]
 result={'parameter':parameter,'speedup':statistics.median(ratios),'cpu_speedup':statistics.median(cpu),'fork_min':min(ratios),'fork_max':max(ratios)}
 assert all(close(result[k],recorded[parameter][k]) for k in ['speedup','cpu_speedup','fork_min','fork_max'])
 result.update(wall_fork_ratios=ratios,cpu_fork_ratios=cpu,wall_fork_losses=sum(v<1 for v in ratios),cpu_fork_losses=sum(v<1 for v in cpu))
 summaries.append(result)
out={'complete':True,'source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'process_pairs_checked':len(seen),'round_rows_checked':nrows,'parameter_cells_checked':12,'orders_balanced':True,'raw_process_output_and_status_matched':True,'summaries':summaries}
pathlib.Path(sys.argv[2]).write_text(json.dumps(out,indent=2)+'\n')
for r in summaries: print(r['parameter'],r['speedup'],r['cpu_speedup'],r['fork_min'],r['fork_max'],r['wall_fork_losses'])
