#!/usr/bin/env python3
"""Render all provider/parameter cells without imputing unmeasured timings."""
import csv, hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=ROOT/'results/ten-key-order/independent-check.json'
data=json.loads(source.read_text())
assert data['complete'] and data['exact_outputs_match']
libs={'noble':('Noble','TypeScript / JavaScript'),'liboqs':('liboqs','C'),'openssl':('OpenSSL','C'),'circl':('CIRCL','Go'),'rustcrypto':('RustCrypto','Rust'),'bouncycastle':('Bouncy Castle','Java')}
def param(p):
 p=str(p)
 if p in ['44','65','87']:return 'ML-DSA-'+p
 if p.startswith('SLH_DSA_PURE_'):p=p.replace('SLH_DSA_PURE_','SLH-DSA-').replace('_','-')
 if p.startswith(('sha2_','shake_')):p='SLH-DSA-'+p.replace('_','-')
 if p.startswith('SLH-DSA-'):p=p.upper();p=p[:-1]+p[-1].lower()
 return p
cells={(r['provider'],param(r['parameter']),r['operation']):r for r in data['summary']}
assert len(cells)==117
completion_path=ROOT/'results/measurement-completion/coverage.json'
completion=json.loads(completion_path.read_text()) if completion_path.exists() else {}
base_cells={(r['library'],param(r['parameter']),r['operation']):r for r in completion.get('baseline_timings',[])}
unsupported={(r['library'],param(r['parameter']),r['operation']):r for r in completion.get('unsupported',[])}
def completion_cell(lib,p,op):
 k=(lib,p,op)
 if k in base_cells:
  r=base_cells[k]
  return f"⚪ {number(r['wall_ns']/1e6)} baseline only [new](../../{r['summary']}); no patch gain"
 if k in unsupported:return '⚪ Not provided by selected implementation'
 return '⚪ NM'
params=['ML-DSA-'+p for p in ['44','65','87']]+['SLH-DSA-'+h+'-'+p for h in ['SHA2','SHAKE'] for p in ['128f','128s','192f','192s','256f','256s']]+['Falcon-512','Falcon-1024']
def prior_cost(lib,p):
 if lib=='noble' and p.startswith('ML-DSA'):
  n=p[-2:];k={'44':16,'65':30,'87':56}[n]
  return f'🟢 {k} KiB fewer polynomial payload bytes in keygen/verify; signing depends on retries. 🔴 More simultaneous public-row storage; post-GC heap medians +1.7–9.8 KB across cells. ⚪ Peak/stack unmeasured.'
 if lib=='rustcrypto' and p.startswith('SLH-DSA'):
  return '⚪ New baseline-only probes measured zero scoped heap allocations for all three actions; encoding/public-key extraction excluded. No evaluated patch or gain. Stack consumption unavailable; not zero process memory.'
 if lib=='rustcrypto' and p.startswith('ML-DSA'):
  n=p[-2:];v={'44':'182,384 → 142,352','65':'214,736 → 176,800','87':'398,704 → 343,328'}[n]
  return f'⚪ Heap counts/bytes/retention unchanged in tested cases. 🟢 Constructor local frame {v} B. No tracing GC; total stack peak unmeasured.'
 if lib=='liboqs' and 'SLH-DSA-SHA2' in p:
  if '128' in p:return '⚪ No OpenSSL allocator calls in focused hashes. SHA256 local frames: 🟢 compression −16 B; 🔴 update/final +112 B, one-shot +128 B. No tracing GC; total stack peak unmeasured.'
  return '⚪ No OpenSSL allocator calls in focused hash probes. 🔴 Some local stack frames +112–240 B; SHA256 compression −16 B. No tracing GC; total stack peak unmeasured.'
 if lib=='openssl' and p.startswith('SLH-DSA'):
  if 'SHA2' in p and ('192' in p or '256' in p):return '🔴 +1 allocation and +224 requested B per hash context; clone has same cost. 🟢 Tested failure cleanup passes. ⚪ Stack peak unmeasured; no tracing GC.'
  return '🔴 Hash-context structure +8 B; no extra context allocation. Timing control. ⚪ Stack peak unmeasured; no tracing GC.'
 if lib=='circl' and 'SLH-DSA-SHA2' in p:
  b=1088 if '128' in p else 1376
  return f'🔴 Normally +12 objects / +{b:,} allocated B per operation. Potential extra GC pressure, not measured GC latency. Setup local frames unchanged; argument/result areas +24/+32 B; peak unknown.'
 if lib=='circl' and 'SHAKE' in p:return '⚪ No changed SHAKE path. Earlier 128f control allocations were unchanged; other sets now have baseline-only timings, without paired resource gains.'
 if lib=='bouncycastle' and p.startswith('SLH-DSA'):return '🟢 Earlier FORS candidate: verification allocation −2.8–7.3% across sets. 🟡 Latency mixed. Stack/peak/GC pause gain unmeasured. New WOTS experiment is separate.'
 return '⚪ No evaluated patch/resource delta in this comparison; not a zero-cost or zero-gain measurement.'
resource_path=ROOT/'results/measurement-completion/resource-observations.json'
resource_data=json.loads(resource_path.read_text()) if resource_path.exists() else {}
resource_rows=resource_data.get('observations',[])
baseline_resource_rows=resource_data.get('baseline_only',[])
def resource_range(rows,metric,settings=None):
 rs=[r for r in rows if r['metric']==metric and (settings is None or r['settings']==settings)]
 if not rs:return None
 if all(r['baseline']==r['candidate'] for r in rs):return '⚪ unchanged in every cell'
 ps=[r['change_percent'] for r in rs if r['change_percent'] is not None]
 if not ps:return '⚪ zero baselines; see absolute changes'
 lo,hi=min(ps),max(ps)
 icon='🟢' if hi<=0 and lo<0 else '🔴' if lo>=0 and hi>0 else '🟡'
 text=icon+' '+(f'{lo:+.2f}%' if lo==hi else f'{lo:+.2f}% to {hi:+.2f}%')
 if len(ps)<len(rs):text+='; some zero baselines'
 return text

def cost(lib,p):
 rs=[r for r in resource_rows if r['library']==lib and param(r['parameter'])==p]
 if not rs:
  note=prior_cost(lib,p)
  bs=[r for r in baseline_resource_rows if r['library']==lib and param(r['parameter'])==p and r['metric']=='process_highwater_rss_bytes']
  if bs:
   vals=[r['baseline']/1048576 for r in bs];a,b=min(vals),max(vals)
   value=f'{a:.2f}' if a==b else f'{a:.2f}–{b:.2f}'
   note+=f' Baseline process high-water RSS {value} MiB (includes startup/warmup/earlier phases); no candidate. [Baseline resources](../../results/measurement-completion/baseline-resource-observations.csv).'
  return note
 link='[New resource details](completed-resource-measurements.md)'
 if lib=='rustcrypto':
  n=p[-2:];frame={'44':'−21.95%','65':'−17.67%','87':'−13.89%'}[n]
  return f'⚪ Operation heap accounting unchanged. 🟢 Constructor-local frame {frame}. Whole-process RSS {resource_range(rs,"whole_process_max_rss_bytes")}; total consumed stack unavailable. {link}.'
 if lib in ['liboqs','openssl']:
  return f'Full-call tracked allocated bytes: {resource_range(rs,"allocated_requested_bytes")}. Process RSS: {resource_range(rs,"peak_rss_post_bytes")}. Observed touched thread-stack extent: {resource_range(rs,"observed_overwritten_thread_stack_bytes")}, not an exact operation peak. No tracing GC. {link}.'
 if lib=='noble':
  n=p[-2:];k={'44':16,'65':30,'87':56}[n]
  return f'🟢 {k} KiB fewer polynomial payload bytes in keygen/verify; total JS allocation traffic unavailable. Observed GC events: default {resource_range(rs,"observed_gc_cycles","default")}; constrained {resource_range(rs,"observed_gc_cycles","constrained")}. Process RSS across both settings: {resource_range(rs,"process_lifetime_highwater_rss")}. {link}.'
 if lib=='circl':
  b=1088 if '128' in p else 1376
  return f'🔴 Isolated calls allocate +{b:,} B / +12 objects. Checked-workload GC cycles: default {resource_range(rs,"gc_cycles_per_workload","default")}; constrained {resource_range(rs,"gc_cycles_per_workload","constrained")}. Process RSS across settings: {resource_range(rs,"process_lifetime_highwater_rss")}. Go reserved stacks are not consumed peak. {link}.'
 if lib=='bouncycastle':
  parts=[]
  for patch in sorted({r['patch'] for r in rs}):
   subset=[r for r in rs if r['patch']==patch]
   parts.append(f'{patch}: allocated B/call {resource_range(subset,"allocated_bytes_per_op")}, process RSS {resource_range(subset,"max_rss_bytes")}')
  return '; '.join(parts)+f'. Separate candidates; GC and retained latency losses in {link}.'
 return prior_cost(lib,p)
def number(v):return f'{v:.3f}' if v<1 else f'{v:.2f}'
def show(r):
 if r is None:return '⚪ NM'
 b=r['baseline_wall_ns']/r['keys']/1e6;c=r['candidate_wall_ns']/r['keys']/1e6;d=100*(1-c/b)
 icon='🟢' if d>0 else '🔴' if d<0 else '⚪'
 return f'{number(b)} → {number(c)}; {icon} {abs(d):.2f}% '+('less' if d>=0 else 'more')+' time'
lines=['# Complete signature performance and resource comparison','',
'Every library appears for every parameter in the original project scope. Every cell distinguishes a paired patch result, a baseline-only timing, an explicitly unsupported selected implementation, or a remaining unmeasured value (NM). The older x86 harness has separate known audit defects and is not substituted into missing cells. New baseline-only measurements fill supported gaps using the separately declared protocols; no gain is calculated where no patch exists.','',
'🟢 = observed favorable direction; 🔴 = observed unfavorable direction; 🟡 = mixed, provisional, or an inference; ⚪ = unchanged, unmeasured, or no evaluated patch. Colors apply to each metric independently and do not imply statistical significance, security approval, or universal performance.','',
'## Timing basis','',
'Paired times below are milliseconds per operation: original → changed, arithmetic means over ten matched distinct keys. Newly added single baseline values use the statistic/protocol linked in each cell, and are not pooled with that earlier run. Percentage time saved = 100 × (1 − changed/original). The changed providers ran before originals, so order drift is a limitation. APIs, fixtures, builds and runtimes differ between providers: compare within a row, not as a language or library ranking. Small control differences must not be called optimization gains. The Rust keygen column measures construction from a seed; sign/verify use existing keys. Bouncy Castle here is the earlier FORS candidate, not the newer sampling/WOTS experiments.','',
f'Source: [independent calculation](../../results/ten-key-order/independent-check.json), SHA256 `{hashlib.sha256(source.read_bytes()).hexdigest()}`. [Protocol and boundaries](../ten-key-order.md). [Resource audit](published-resource-regressions.md). [New memory and GC details](completed-resource-measurements.md). Original raw hashes were rechecked when preparing this comparison.','',
'## Memory and GC interpretation','',
'Allocation traffic is the sum of bytes requested over an operation; live memory is what is still reachable; peak memory is the maximum simultaneously occupied; stack frames are function-local storage. These are not interchangeable. Lower allocation traffic can coexist with a higher live heap or slower code. Local stack frames cannot be added indiscriminately when inlining and call paths differ.','',
'Noble runs under a JavaScript GC: unreachable objects can be reclaimed, while live objects remain. V8 has generational collection; eliminating short-lived arrays may reduce collection work, but greater row liveness and runtime/JIT storage can increase observed memory. Typed-array backing stores and ordinary JS heap are separate counters. Our post-GC snapshots do not measure operation peaks or prove leak absence. [V8 explanation](https://v8.dev/blog/trash-talk).','',
'CIRCL runs under Go GC. Higher allocation rate can make collection more frequent and consume CPU, while live heap and the configured memory budget affect the collection target. The earlier isolated allocation probe disabled automatic GC. The new default/constrained workloads measure GC cycles, pauses, CPU, heap and reserved stacks separately; their copies/checks/sampling are part of those workload counters. +1,376 B per call at a hypothetical 10,000 calls/s is 13.76 MB/s additional allocation traffic, not retained heap growth and not an achieved throughput claim. [Go GC guide](https://go.dev/doc/gc-guide).','',
'Bouncy Castle runs under JVM GC. Allocations and reclamation consume resources, but the selected collector, JIT and object lifetimes affect outcomes. Lower allocated bytes do not guarantee faster operations or fewer pauses; our newer BC candidates demonstrate this directly. The new diagnostic records collection counts/time, heap snapshots and process RSS for each candidate separately; its small quantized GC totals do not establish tail-pause improvements. [HotSpot GC guide](https://docs.oracle.com/en/java/javase/21/gctuning/index.html).','',
'liboqs and OpenSSL use C allocation/free and stack lifetimes; RustCrypto uses ownership/drop rather than a tracing GC. They can still incur allocation costs, fragmentation, large stack frames, or retained storage. Freeing memory does not guarantee immediate reduction of OS resident memory. Rust zeroization remains feature-dependent; unchanged allocation accounting is not a complete secret-erasure guarantee.','']
records=[]
for p in params:
 lines+=['## '+p,'','| Library | Language | Keygen / construction (ms) | Sign (ms) | Verify (ms) | Resources and behavior |','|---|---|---|---|---|---|']
 for lib,(name,lang) in libs.items():
  cs=[cells.get((lib,p,o)) for o in ['keygen','sign','verify']]
  lines+=['| '+' | '.join([name,lang]+[show(c) if c else completion_cell(lib,p,o) for c,o in zip(cs,['keygen','sign','verify'])]+[cost(lib,p)])+' |']
  for op,c in zip(['keygen','sign','verify'],cs):
   records.append(dict(library=name,language=lang,parameter=p,operation=op,status='measured' if c else 'baseline_only' if (lib,p,op) in base_cells else 'not_provided' if (lib,p,op) in unsupported else 'not_measured',baseline_ms=c['baseline_wall_ns']/c['keys']/1e6 if c else base_cells[(lib,p,op)]['wall_ns']/1e6 if (lib,p,op) in base_cells else '',candidate_ms=c['candidate_wall_ns']/c['keys']/1e6 if c else '',time_saved_percent=100*(1-c['candidate_wall_ns']/c['baseline_wall_ns']) if c else '',resource_note=cost(lib,p)))
 lines+=['']
lines+=['## Rust construction plus signing','','| Parameter | Original → changed (ms), time saved |','|---|---|']
for p in params[:3]:
 c=cells[('rustcrypto',p,'keygen_sign')];lines+=['| '+p+' | '+show(c)+' |']
 records.append(dict(library='RustCrypto',language='Rust',parameter=p,operation='keygen_sign',status='measured',baseline_ms=c['baseline_wall_ns']/c['keys']/1e6,candidate_ms=c['candidate_wall_ns']/c['keys']/1e6,time_saved_percent=100*(1-c['candidate_wall_ns']/c['baseline_wall_ns']),resource_note=cost('rustcrypto',p)))
lines+=['','## Newer Bouncy Castle alternatives: separate experiments','',
'These results must not be combined with the earlier FORS times above. They compare separate patches to their own upstream baseline. ML sampling is a six-round confirmation; WOTS is a two-pair pilot limited to the two listed sets. These earlier runs did not establish lower peak heap, less stack usage, or fewer GC pauses. The separately linked resource follow-up adds GC and RSS observations without replacing their latency evidence. Time change below is candidate/original minus one; positive is slower.','',
'| Candidate | Parameter / action | Time change | Allocated bytes change | Interpretation |',
'|---|---|---|---|---|',
'| ML sampling buffers | 44 sign | 🟢 −0.91% | 🟢 −24.26% | Mixed rounds |',
'| ML sampling buffers | 44 verify | 🔴 +3.22% | 🟢 −21.36% | All six rounds slower |',
'| ML sampling buffers | 65 sign | 🔴 +2.06% | 🟢 −28.45% | All six rounds slower |',
'| ML sampling buffers | 65 verify | 🟢 −1.70% | 🟢 −25.82% | Mixed rounds |',
'| ML sampling buffers | 87 sign | 🔴 +0.26% | 🟢 −30.30% | Mixed rounds |',
'| ML sampling buffers | 87 verify | 🟢 −5.18% | 🟢 −30.15% | All six rounds faster |',
'| WOTS buffer | SHA2-128f keygen | 🔴 +4.10% | 🟢 −73.23% | Both pairs slower |',
'| WOTS buffer | SHA2-128f sign | 🔴 +2.60% | 🟢 −66.67% | Both pairs slower |',
'| WOTS buffer | SHA2-128f verify | 🟢 −0.66% | 🟢 −61.64% | Mixed pairs |',
'| WOTS buffer | SHAKE-128f keygen | 🔴 +1.24% | 🟢 −73.45% | Both pairs slower |',
'| WOTS buffer | SHAKE-128f sign | 🟢 −4.82% | 🟢 −66.83% | Mixed pairs; weak CPU corroboration |',
'| WOTS buffer | SHAKE-128f verify | 🔴 +0.79% | 🟢 −62.19% | Mixed pairs |','',
'Evidence: [ML confirmation](../bouncycastle/ml-deep/confirmation.md), imported unchanged from `ecf5f803a2df24bd93abb0cfae0300a4b2cdfeb3`; [WOTS pilot](../bouncycastle/slh-deep.md), imported unchanged from `cfafbb4641bbf1dac5acc496b99b881303933136`; [independent review](../../results/bouncycastle/deep-independent/README.md). ML sampling key generation was subsequently measured in the [new resource follow-up](../bouncycastle/completion.md); other WOTS parameter sets remain outside that pilot.','']
lines+=['','## Interpretation limits','','OpenSSL SHA2-128 and SHAKE are controls. Its 192s key-generation wall improvement is not corroborated by a comparable CPU improvement. Rust existing-key signing/verification are unchanged code. Noble warmed operation benefits are not a startup or tail-latency guarantee. Falcon has no validated production-patch comparison in this exercise; NM does not assert library support. New baseline timings and resource indicators are linked separately; this report changes no cryptographic implementation.','']
out=ROOT/'docs/audit/complete-performance-comparison.md';out.write_text('\n'.join(lines))
p=ROOT/'results/resource-regressions/complete-performance-comparison.csv'
with p.open('w') as f:
 w=csv.DictWriter(f,fieldnames=list(records[0]),lineterminator="\n");w.writeheader();w.writerows(records)
assert len(records)==309 and sum(r['status']=='measured' for r in records)==117
counts={v:sum(r['status']==v for r in records) for v in sorted({r['status'] for r in records})}
print(f'Generated {len(params)*len(libs)} library/parameter rows, {len(records)} action cells; statuses: {counts}')
