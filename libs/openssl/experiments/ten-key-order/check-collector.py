#!/usr/bin/env python3
"""Exercise the collector's acceptance checks without running any timed operation."""
import ast
import hashlib
import json
import pathlib
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
source = HERE / 'run.py'
# Load definitions only; leave the collector's command-line dispatch unexecuted.
tree = ast.parse(source.read_text(), filename=str(source))
dispatch = next(i for i, node in enumerate(tree.body)
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'p' for t in node.targets))
tree.body = tree.body[:dispatch]
namespace = {'__file__': str(source)}
exec(compile(tree, str(source), 'exec'), namespace)
root = namespace['ROOT']
build = namespace['BUILD']
sample = namespace['rows']((build / 'candidate-smoke.jsonl').read_text(),
                           'candidate', namespace['PARAMETERS'][0])
sample[0]['sign_wall_ns'] = float('inf')
try:
    namespace['rows']('\n'.join(json.dumps(row) for row in sample),
                      'candidate', namespace['PARAMETERS'][0])
    raise RuntimeError('infinite timing accepted')
except AssertionError:
    pass
with tempfile.TemporaryDirectory(dir=build) as directory:
    result = pathlib.Path(directory)
    namespace['RESULTS'] = result
    (result / 'prepared.json').write_text('{}')
    out = result / 'candidate'
    out.mkdir()
    hashes = {}
    for parameter in namespace['PARAMETERS']:
        path = out / (parameter + '.jsonl')
        path.write_text('test raw\n')
        hashes[path.name] = namespace['sha'](path)
    completed = {'complete': True, 'variant': 'candidate', 'keys': 70,
                 'manifest_sha256': namespace['sha'](result / 'prepared.json'),
                 'raw_sha256': hashes, 'started_at': '2026-10-12T00:00:00+00:00',
                 'finished_at': '2026-10-12T00:01:00+00:00'}
    (out / 'complete.json').write_text(json.dumps(completed))
    namespace['completion']('candidate')
    path = out / (namespace['PARAMETERS'][0] + '.jsonl')
    path.write_text('changed raw\n')
    try:
        namespace['completion']('candidate')
        raise RuntimeError('changed raw accepted')
    except AssertionError:
        pass
    path.write_text('test raw\n')
    (result / 'prepared.json').write_text('{"changed":true}')
    try:
        namespace['completion']('candidate')
        raise RuntimeError('changed manifest accepted')
    except AssertionError:
        pass
print(json.dumps({'complete': True,
                  'collector_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'checks': ['valid completion accepted', 'infinite timing rejected',
                             'changed raw output rejected', 'changed manifest rejected']}))
