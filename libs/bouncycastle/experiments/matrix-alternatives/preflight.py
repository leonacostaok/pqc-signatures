#!/usr/bin/env python3
"""Bounded arithmetic/plan checks and fail-closed Python invocation checks; no JVM runs."""
import sys
if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')
import ast, json, subprocess
from pathlib import Path
from collect import schedule, require

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parents[3] / 'results/bouncycastle/matrix-alternatives'

def main():
    checks = []
    for path in sorted(HERE.glob('*.py')):
        ast.parse(path.read_text())
        run = subprocess.run([sys.executable, '-O', str(path), '--help'], capture_output=True, text=True)
        require(run.returncode != 0 and ('Run without Python optimization' in run.stderr or 'Python optimization disables required checks' in run.stderr), 'optimized Python did not fail closed')
        checks.append({'file': path.name, 'optimized_exit': run.returncode})
    jobs = schedule()
    require(len(jobs) == 288 and len({(j['mode'], j['parameter'], j['operation'], j['variant'], j['round']) for j in jobs}) == 288, 'plan coverage')
    for offset in range(0, 288, 8):
        group = jobs[offset:offset+8]
        require([x['variant'] for x in group[:4]] == [x['variant'] for x in reversed(group[4:])], 'unbalanced pair')
    q, r = 8380417, 1 << 32
    mr = lambda b: (b + (1 << 31) * q + r - 1) // r
    bounds = {'lazy_sum': 63*q*q, 'q_times_2pow31': q*(1 << 31),
              'lazy_numerator': 63*q*q+(1 << 31)*q, 'lazy_output': mr(63*q*q),
              'individual_product_output': mr(9*q*q), 'original_row_output': 7*mr(9*q*q),
              'challenge_product_output': mr(81*q*q), 'inverse_final_output': mr(41978*256*q)}
    require(bounds['lazy_sum'] < q*(1 << 31) and bounds['lazy_numerator'] < (1 << 63), 'long overflow bound')
    require(bounds['lazy_output'] < q and 256*q < (1 << 31) and mr(128*q*q) < q, 'inverse bound')
    require((58728449*q) % r == 1, 'Montgomery inverse')
    require(bounds['original_row_output'] + bounds['challenge_product_output'] + (1 << 22) < (1 << 31), 'verifier int bound')
    result = {'schema': 'bc-matrix-preflight-v1', 'optimized_python': checks, 'balanced_jobs': 288, 'conservative_integer_bounds': bounds}
    (RESULTS / 'preflight.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))

if __name__ == '__main__':
    main()
