#!/usr/bin/env python3
"""Render a compact view of the new resource observations; CSV retains all metrics."""
import json
from collections import defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
d = json.loads((ROOT/'results/measurement-completion/resource-observations.json').read_text())
groups = defaultdict(dict)
for r in d['observations']:
    groups[tuple(r[k] for k in ['library','patch','settings','parameter','operation'])][r['metric']] = r
names = {'liboqs':'liboqs · C','openssl':'OpenSSL · C','noble':'noble · TypeScript/JavaScript','circl':'CIRCL · Go','rustcrypto':'RustCrypto · Rust','bouncycastle':'Bouncy Castle · Java'}

def number(v):
    return f'{v:,.0f}' if v == int(v) else f'{v:,.2f}'

def show(m, key, label=''):
    if key not in m: return '—'
    r = m[key]; p = r['change_percent']; a = r['baseline']; b = r['candidate']
    icon = '⚪' if a == b else '🟢' if b < a else '🔴'
    change = f'{p:+.2f}%' if p is not None else f'Δ {number(b-a)}; % undefined'
    return f'{label}{number(a)} → {number(b)} ({icon} {change})'

lines = ['# Completed memory and GC measurements','',
'Original → changed. Byte values are bytes; GC time is milliseconds per fixed workload, not per operation. Percent resource change is `100 × (changed/original − 1)`. Green/red indicates smaller/larger observations only. Small RSS or heap changes can be runtime noise; fewer GC events can coexist with slower code. A zero denominator has no percentage.','',
'[Short recommendations](../performance-summary.md) · [Complete timing table](complete-performance-comparison.md) · [All paired resource metrics as CSV](../../results/measurement-completion/resource-observations.csv) · [Additional baseline-only memory/GC observations](../../results/measurement-completion/baseline-resource-observations.csv) · [Machine-readable metrics and source hashes](../../results/measurement-completion/resource-observations.json) · [Earlier focused allocation/frame audit](resource-percentages.md).','',
'These are diagnostic workloads with their own boundaries, separate from the clean timing experiments. The CSV also retains instrumented API/workload times, allocation rates, counters, end snapshots and each metric’s source and statistic. The baseline-only CSV also exposes already-collected Rust SLH allocator counters, BC ML/Falcon allocation and GC counters, and baseline process-RSS observations. Those rows have no candidate or gain percentage. C unchanged-path timing probes did not measure resources; their raw placeholder zeros are not reported as measurements.','']
notes = {
 'liboqs':'Allocation hooks cover the configured allocator entry points during the public call, excluding caller buffers. RSS is a cold process high-water. The painted dedicated-thread stack extent includes startup/exit and can miss bytes equal to its paint; it is not an exact operation peak. No-op controls are retained and not subtracted. No tracing GC.',
 'openssl':'Allocation hooks cover the public call, excluding imported keys/caller buffers; returned new keys are accounted before cleanup. RSS is a cold process high-water. Painted-stack extent is a diagnostic, not an exact peak or a sum of local frames. No tracing GC.',
 'noble':'Each row is four fresh processes per variant; default and constrained V8 settings are separate. Heap values are post-call sampled maxima, not internal peaks. RSS includes startup/warmup. GC values are observed events/durations over copies, calls, checks and sampling. Exact total JS allocation traffic, GC CPU and consumed stack are unavailable from these counters.',
 'circl':'Each row is four fresh processes per variant under separate default/constrained GC settings. Allocated bytes per operation include the checked workload’s copies, imports and instrumentation; they differ from the earlier isolated operation counters. Heap maxima are sampled after calls. GC pause is stop-the-world time, not total GC CPU; the CSV retains GC CPU separately. StackInuse is reserved runtime stack memory, not consumed stack.',
 'rustcrypto':'The allocator binary is separate from timing/RSS. Allocations exclude encoding and public-key extraction; all matched ML accounting values agree. RSS compares four whole processes containing all three actions, not individual operations. There is no tracing GC. All twelve SLH baseline sets also report zero scoped heap allocations for each of keygen/sign/verify; that is baseline-only evidence, not a patch improvement or zero process-memory claim. Consumed stack remains unmeasured; earlier compiler-local frames are separate evidence.',
 'bouncycastle':'FORS, combined ML sampling and WOTS are separate candidates. Each row uses two fresh processes per variant with balanced order, G1, a 64–512 MiB heap and two active processors. Allocation is thread-accounted per API call; GC counters cover the checked batch. Heap after a requested GC does not guarantee collection completed. RSS is the whole process. These short instrumented runs do not replace the earlier repeated latency confirmation. [Tradeoffs and retained regressions](../bouncycastle/completion.md).'}
for lib in ['liboqs','openssl','noble','circl','rustcrypto','bouncycastle']:
    selected = [(k,m) for k,m in groups.items() if k[0] == lib]
    if not selected: continue
    lines += ['## '+names[lib], '', notes[lib], '']
    source = next(iter(selected[0][1].values()))['source']
    report = '../../libs/'+lib+'/experiments/complete-indicators/RESULTS.md' if lib in ['liboqs','openssl'] else '../'+lib+('/completion.md' if lib in ['rustcrypto','bouncycastle'] else '/resource-followup.md')
    lines += [f'[Findings and protocol]({report}) · [Provider summary and raw references](../../{source}).','',
              '| Candidate / setting | Parameter / action | Allocated B per call | Heap / process RSS (B) | GC per workload | Stack diagnostic (B) |',
              '|---|---|---|---|---|---|']
    for (_,patch,setting,parameter,op), m in sorted(selected):
        alloc = heap = gc = stack = '—'
        if lib in ['liboqs','openssl']:
            alloc = show(m,'allocated_requested_bytes')
            heap = show(m,'peak_tracked_live_bytes','Tracked peak: ')+'; '+show(m,'peak_rss_post_bytes','RSS: ')
            gc = 'No tracing GC'; stack = show(m,'observed_overwritten_thread_stack_bytes','Touched extent: ')
        elif lib == 'noble':
            alloc = 'Exact JS total unavailable'
            heap = show(m,'sampled_max_heapUsed','Sampled heap: ')+'; '+show(m,'process_lifetime_highwater_rss','RSS: ')
            gc = show(m,'observed_gc_cycles','Events: ')+'; '+show(m,'observed_gc_duration','ms: ')
            stack = 'Consumed peak unavailable'
        elif lib == 'circl':
            alloc = show(m,'allocated_bytes_per_op')
            heap = show(m,'sampled_max_heap_alloc_bytes','Sampled heap: ')+'; '+show(m,'process_lifetime_highwater_rss','RSS: ')
            pause = m.get('gc_pause_per_workload')
            if pause:
                pause = {**pause, 'baseline':pause['baseline']/1e6, 'candidate':pause['candidate']/1e6}
            gc = show(m,'gc_cycles_per_workload','Cycles: ')+'; '+show({'pause':pause} if pause else {},'pause','pause ms: ')
            stack = show(m,'sampled_max_runtime_reserved_stack_bytes','Reserved: ')
        elif lib == 'rustcrypto':
            alloc = show(m,'allocated_bytes')
            heap = show(m,'peak_above_entry_bytes','Tracked peak: ') if op != 'whole process' else show(m,'whole_process_max_rss_bytes','RSS: ')
            gc = 'No tracing GC'; stack = 'Consumed peak unavailable'
        else:
            alloc = show(m,'allocated_bytes_per_op')
            heap = show(m,'heap_post_requested_gc_bytes','After requested GC: ')+'; '+show(m,'max_rss_bytes','RSS: ')
            gc = show(m,'gc_count','Collections: ')+'; '+show(m,'gc_time_ms','ms: ')
            stack = 'Consumed peak unavailable'
        lines.append('| '+' | '.join([patch+' / '+setting, parameter+' / '+op, alloc,heap,gc,stack])+' |')
    lines += ['']
lines += ['## Remaining limits','',
'Exact total consumed stack and exact intra-operation managed-heap peaks are not established. Node does not expose total JS allocation traffic or GC CPU through these probes. Unsupported Falcon cells refer to the selected pinned OpenSSL, CIRCL and RustCrypto implementations. Unchanged paths have baseline timings, not invented patch gains. Unmeasured metrics are not zeros.','',
'This supporting measurement work is AI-assisted. Preserved sources, scripts and observations allow independent reproduction; the reports are not an independent cryptographic security audit.','']
(ROOT/'docs/audit/completed-resource-measurements.md').write_text('\n'.join(lines))
print(f'Rendered {len(groups)} scoped resource rows')
