#!/usr/bin/env python3
"""Apply the predeclared initial-screen selection rule without changing it."""
import json,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')
sys.path.insert(0,str(Path(__file__).resolve().parent))
import run
plan=json.loads((run.OUT/'plan.json').read_text());s=json.loads((run.OUT/'summary.json').read_text())
lookup={(c['mode'],c['parameter'],c['operation'],tuple(c['comparison'])):c for c in s['cells']}
decisions=[]
for variant in run.VARIANTS[1:]:
    ops=run.OPS if variant.startswith('buffer') else run.OPS[:2]
    lower=[];regressions=[];improvements=[]
    for p in ['sha2_128f','shake_128f']:
        for op in ops:
            comparison=('baseline',variant)
            a=lookup['allocation',p,op,comparison]['metrics']['allocated_bytes']['paired_change_percent']
            t=lookup['bench',p,op,comparison]['metrics'];w=t['wall_ns']['paired_change_percent'];cpu=t['thread_cpu_ns']['paired_change_percent']
            if all(x<0 for x in a):lower.append([p,op])
            if all(x>2 for x in w+cpu):regressions.append([p,op])
            if all(x<=-2 for x in w+cpu):improvements.append([p,op])
    decisions.append(dict(variant=variant,selected=bool((lower and not regressions) or improvements),lower_allocation_both_pairs=lower,clear_regressions=regressions,repeatable_improvements=improvements))
run.write(run.OUT/'selection.json',dict(plan_sha256=run.sha(run.OUT/'plan.json'),summary_sha256=run.sha(run.OUT/'summary.json'),script_sha256=run.sha(__file__),decisions=decisions,rule=plan['followup']['selection'],limits='Selected confirmation is conditional on this short warmup/noisy host screen; all initial results remain retained. No mechanisms are combined.'))
print(json.dumps(decisions,indent=2))
