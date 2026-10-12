#!/usr/bin/env python3
"""Write the six-comparison screen before collection; no benchmarks are executed."""
import hashlib, json, sys
from pathlib import Path
if sys.flags.optimize:
    raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import run
comparisons=[('baseline','object_hoist'),('baseline','field_rewrite'),('baseline','two_addresses'),('baseline','buffer'),('buffer','buffer_peeled'),('baseline','buffer_peeled')]
jobs=[]
for mode in ['bench','allocation']:
    for parameter in ['sha2_128f','shake_128f']:
        for operation in run.OPS:
            for a,b in comparisons:
                for fork in range(2):
                    for variant in ([a,b] if fork==0 else [b,a]):
                        jobs.append(dict(mode=mode,parameter=parameter,operation=operation,comparison=[a,b],fork=fork,variant=variant,warmup_calls=20))
assert len(jobs)==288
run.write(run.OUT/'plan.json',dict(created_at=run.stamp(),jobs=jobs,manifest_sha256=run.sha(run.OUT/'manifest.json'),collector_sha256=run.sha(HERE/'run.py'),plan_writer_sha256=run.sha(__file__),audit_sha256=run.sha(HERE/'audit.py'),scope='SHA2/SHAKE128f lean screen;20 calls on2 disjoint warmup keys;10 distinct measured keys once/process;two balanced independent process pairs per comparison;timing and allocation separate;no steady-state claim.',followup=dict(parameters=['sha2_192f','sha2_256f','shake_192f','shake_256f'],warmup_calls=20,measured_keys_per_process=10,pairs=2,modes=['bench','allocation'],selection='Evaluate each address/buffer mechanism separately against stock. Advance if any targeted128f operation shows both pairs with lower allocation and no targeted128f cell shows a clear latency regression, OR any targeted128f operation has repeatable latency improvement. Clear regression means wall and thread CPU each exceed stock by more than2% in both pairs. Repeatable improvement means wall and thread CPU each fall by at least2% in both pairs. Address targets are keygen/sign; buffer targets include verification. Keep all initial losers and explicitly label confirmation as selected. Never combine mechanisms. Compare selected buffer peeling to both stock and old buffer.',limits='Selection thresholds are screening rules,not significance tests; unchanged address-verification controls remain visible. All four192/256f configurations run for every selected mechanism.')))
print('Prescribed288 fresh processes; no collection started.')
