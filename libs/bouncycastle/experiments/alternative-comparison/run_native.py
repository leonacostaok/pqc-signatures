#!/usr/bin/env python3
"""Run native suites against already sealed candidate classes, never time them."""
import argparse
import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path

if not __debug__:
    raise SystemExit('optimized Python is unsupported')
p = argparse.ArgumentParser()
p.add_argument('--family', choices=['ml', 'slh'], required=True)
p.add_argument('--label', required=True)
p.add_argument('--classes', type=Path, required=True)
p.add_argument('--slh-data', type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parents[4]
out = root / 'results/bouncycastle/alternative-comparison/native'
m = json.loads((out / 'manifest.json').read_text())
classes = a.classes.resolve()
assert classes.is_dir()
label = a.label
assert label and all(c.isalnum() or c in '-_' for c in label)
record_path = out / (label + '.json')
assert not record_path.exists(), 'do not overwrite native evidence'
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
before = {str(f.relative_to(classes)): sha(f) for f in sorted(classes.rglob('*.class'))}
native = Path(m['classes'])
for name, expected in m['class_hashes'].items():
    assert sha(native / name) == expected
for name, expected in m['dependencies'].items():
    assert sha(Path(name)) == expected
assert sha(Path(m['java'])) == m['java_sha256']
driver = root / 'libs/bouncycastle/build/alternative-comparison/driver'
driver.mkdir(exist_ok=True)
source = Path(__file__).with_name('NativeMethods.java')
compile_cmd = [str(Path(m['java']).with_name('javac')), '-J-XX:ActiveProcessorCount=2', '--release', '8', '-cp', m['junit'], '-d', str(driver), str(source)]
subprocess.run(compile_cmd, check=True)
family = 'mldsa' if a.family == 'ml' else 'slhdsa'
origins = ['Ntt', 'PolyVecMatrix', 'Poly', 'MLDSAEngine'] if a.family == 'ml' else ['WotsPlus', 'ADRS', 'SLHDSAEngine']
origins = ','.join('org.bouncycastle.crypto.signers.' + family + '.' + n for n in origins)
data = Path(m['test_data']) if a.family == 'ml' else a.slh_data.resolve()
tests = ['org.bouncycastle.pqc.crypto.test.MLDSATest', 'org.bouncycastle.pqc.crypto.test.MLDSAWycheproofTest'] if a.family == 'ml' else ['org.bouncycastle.pqc.crypto.test.SLHDSATest#' + name for name in ['testSigVerSingleFile', 'testSigVer', 'testComponentLengthChecks', 'testUninitialisedSignerThrowsIllegalStateException']]
# Variant first; compiled native dependencies supply ASN.1/test utilities only.
cp = ':'.join(map(str, [classes, driver, native, m['junit'], m['hamcrest']]))
cmd = [m['java'], '-Xmx512m', '-XX:ActiveProcessorCount=2', '-Dtest.full=true', '-Dbc.test.data.home=' + str(data), '-cp', cp, 'NativeMethods', str(classes), origins] + tests
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
(out / (label + '.txt')).write_text(result.stdout)
after = {str(f.relative_to(classes)): sha(f) for f in sorted(classes.rglob('*.class'))}
assert before == after, 'variant changed during native suite'
data_records = {str(f.relative_to(data)): sha(f) for f in sorted(data.rglob('*')) if f.is_file()}
record = {'label': label, 'family': a.family, 'start': started, 'end': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'command': cmd, 'returncode': result.returncode, 'class_hashes': before, 'test_data_hashes': data_records, 'manifest_sha256': sha(out / 'manifest.json'), 'runner_sha256': sha(Path(__file__)), 'driver_source_sha256': sha(source), 'driver_class_sha256': sha(driver / 'NativeMethods.class'), 'output_sha256': sha(out / (label + '.txt'))}
record_path.write_text(json.dumps(record, indent=2) + '\n')
print(result.stdout[-3000:])
raise SystemExit(result.returncode)
