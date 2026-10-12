#!/usr/bin/env python3
"""Build a separate public verifier and run fail-closed NIST/shared validation."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--validation', type=Path, required=True)
p.add_argument('--evidence', type=Path, required=True)
a = p.parse_args()
experiment = Path(__file__).resolve().parent
upstream = a.build / 'candidate/tests/vectors_sig'
library = a.build / 'candidate/lib/liboqs.a'
adapter = a.build / 'public_verify'
prefix = subprocess.check_output(['pkg-config', '--variable=prefix', 'openssl'], text=True).strip()
compile_command = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-I' + str(a.build / 'candidate/include'), str(experiment / 'public_verify.c'),
                   str(library), '-L' + prefix + '/lib', '-lcrypto', '-lpthread', '-o', str(adapter)]
report = {'complete': False, 'compile_command': compile_command, 'controls': [], 'runs': []}
report_path = a.evidence / 'external-validation-run.json'
if report_path.exists():
    raise SystemExit('refusing to replace prior validation run')

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save():
    report_path.write_text(json.dumps(report, indent=2) + '\n')

def check_control(label, command, expected_rc, marker=None):
    result = subprocess.run(command, capture_output=True, text=True)
    passed = result.returncode == expected_rc and (marker is None or marker in result.stdout)
    report['controls'].append({'label': label, 'expected_returncode': expected_rc,
                               'actual_returncode': result.returncode, 'passed': passed,
                               'stdout': result.stdout if len(result.stdout) < 1024 else 'omitted'})
    save()
    if not passed:
        raise SystemExit(label + ': unexpected control result')

report['library_sha256_before'] = sha256(library)
report['upstream_binary_sha256_before'] = sha256(upstream)
save()
print('compiling separate public verifier', flush=True)
compilation = subprocess.run(compile_command, capture_output=True, text=True)
(a.evidence / 'public-verify-build.log').write_text(compilation.stdout + compilation.stderr)
report['compile_returncode'] = compilation.returncode
save()
if compilation.returncode:
    raise SystemExit('adapter compilation failed')
report['adapter_sha256'] = sha256(adapter)
report['adapter_source_sha256'] = sha256(experiment / 'public_verify.c')

groups = json.loads((a.build / 'acvp/sigVer.json').read_text())['testGroups']
group = next(g for g in groups if g['parameterSet'] == 'SLH-DSA-SHA2-128f'
             and g['signatureInterface'] == 'external' and g['preHash'] != 'preHash')
positive = next(t for t in group['tests'] if t['testPassed'])
negative = next(t for t in group['tests'] if not t['testPassed'])
name = 'SLH_DSA_PURE_SHA2_128F'

def args(case, expected):
    return [name, case['pk'], case['message'], case['signature'], case['context'], str(expected)]

check_control('positive vector executes and accepts', [str(adapter)] + args(positive, 1), 0,
              'public_verify_executed: 1')
check_control('inverted expectation fails', [str(adapter)] + args(positive, 0), 1,
              'public_verify_executed: 1')
check_control('negative vector executes and rejects', [str(adapter)] + args(negative, 0), 0,
              'public_verify_executed: 0')
old_result = subprocess.run([str(upstream), name, 'sigVer_ext'] + args(positive, 1)[1:],
                            capture_output=True, text=True)
report['upstream_external_skip_reproduction'] = {
    'parameter': group['parameterSet'], 'tgId': group['tgId'], 'tcId': positive['tcId'],
    'returncode': old_result.returncode,
    'execution_marker_present': any(s.startswith('testPassed: ') for s in old_result.stdout.splitlines())}
save()
if old_result.returncode != 0 or report['upstream_external_skip_reproduction']['execution_marker_present']:
    raise SystemExit('upstream external skip assumption changed; inspect before continuing')

controls = a.build / 'validation-controls'
controls.mkdir(exist_ok=True)
shutil.copyfile(a.evidence / 'acvp-vectors.json', controls / 'acvp-vectors.json')
acvp_command = [sys.executable, str(experiment / 'check_acvp_executed.py'), '--vectors', str(a.build / 'acvp'),
                '--binary', str(upstream), '--public-verify', str(adapter), '--evidence', str(a.evidence)]
shared_command = [sys.executable, str(experiment / 'check_shared.py'), '--validation', str(a.validation),
                  '--binary', str(upstream), '--public-verify', str(adapter),
                  '--output', str(a.evidence / 'shared-validation.json')]
missing = acvp_command.copy()
missing[missing.index('--binary') + 1] = '/usr/bin/true'
missing[missing.index('--evidence') + 1] = str(controls)
check_control('NIST rejects exit-zero without execution', missing, 1)
gate = json.loads((controls / 'acvp-checked-execution.json').read_text())
assert not gate['complete'] and len(gate['cases']) == 1
assert gate['cases'][0]['returncode'] == 0 and not gate['cases'][0]['execution_marker']
missing = shared_command.copy()
missing[missing.index('--binary') + 1] = '/usr/bin/true'
missing[missing.index('--output') + 1] = str(controls / 'shared.json')
check_control('shared driver rejects exit-zero without execution', missing, 1)
gate = json.loads((controls / 'shared.json').read_text())
assert not gate['complete'] and len(gate['cases']) == 1
assert gate['cases'][0]['returncode'] == 0 and not gate['cases'][0]['execution_marker']
for label, command in [('acvp-checked-execution', acvp_command), ('shared-validation', shared_command)]:
    print('running ' + label, flush=True)
    started = time.monotonic()
    with (a.evidence / (label + '.log')).open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    report['runs'].append({'label': label, 'command': command, 'returncode': result.returncode,
                           'elapsed_seconds': time.monotonic() - started})
    save()
    if result.returncode:
        raise SystemExit(label + ' failed; see saved log')
report['library_sha256_after'] = sha256(library)
report['upstream_binary_sha256_after'] = sha256(upstream)
assert report['library_sha256_before'] == report['library_sha256_after']
assert report['upstream_binary_sha256_before'] == report['upstream_binary_sha256_after']
report['complete'] = True
save()
print('all checked-execution validation passed', flush=True)
