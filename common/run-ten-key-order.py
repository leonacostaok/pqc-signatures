#!/usr/bin/env python3
"""Run six candidate batches, then six baseline batches, strictly sequentially."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    if sys.flags.optimize:
        raise SystemExit('Assertions must remain enabled')
    parser = argparse.ArgumentParser()
    parser.add_argument('plan', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    providers = ['openssl', 'liboqs', 'noble', 'circl', 'rustcrypto', 'bouncycastle']
    expected = [(side, provider) for side in ['candidate', 'baseline'] for provider in providers]
    assert [(r['variant'], r['provider']) for r in plan['batches']] == expected
    assert plan['keys_per_parameter'] == 10
    for batch in plan['batches']:
        assert Path(batch['cwd']).is_dir()
        assert isinstance(batch['argv'], list) and all(isinstance(a, str) for a in batch['argv'])
    args.out.mkdir(parents=True, exist_ok=False)
    state = {'schema': 'pqc-ten-key-global-order-v1', 'complete': False,
             'started_at': now(), 'plan_sha256': hashlib.sha256(args.plan.read_bytes()).hexdigest(),
             'coordinator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'plan': plan, 'batches': [],
             'method': 'One ten-key batch per parameter and variant; all candidate batches finish before the first baseline batch starts; no concurrent child processes.'}
    target = args.out / 'execution.json'
    def checkpoint():
        temporary = args.out / 'execution.json.pending'
        temporary.write_text(json.dumps(state, indent=2) + '\n')
        temporary.replace(target)
    checkpoint()
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for index, batch in enumerate(plan['batches']):
        stem = f"{index+1:02d}-{batch['provider']}-{batch['variant']}"
        record = {**batch, 'started_at': now(), 'exit_code': None,
                  'stdout': stem + '.stdout.txt', 'stderr': stem + '.stderr.txt'}
        state['batches'].append(record); checkpoint()
        print('START', stem, record['started_at'], flush=True)
        try:
            with (args.out / record['stdout']).open('x') as stdout, (args.out / record['stderr']).open('x') as stderr:
                result = subprocess.run(batch['argv'], cwd=batch['cwd'], env=environment,
                                        stdout=stdout, stderr=stderr)
            record['exit_code'] = result.returncode
        except Exception as error:
            record['error'] = repr(error)
            raise
        finally:
            record['finished_at'] = now()
            for stream in ['stdout', 'stderr']:
                path = args.out / record[stream]
                if path.exists(): record[stream + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            checkpoint()
        print('END', stem, 'exit', record['exit_code'], record['finished_at'], flush=True)
        if record['exit_code'] != 0:
            raise SystemExit(f"Batch failed; prior output retained: {stem}")
    for previous, following in zip(state['batches'], state['batches'][1:]):
        assert previous['finished_at'] <= following['started_at']
    state['complete'] = True; state['finished_at'] = now(); checkpoint()


if __name__ == '__main__':
    main()
