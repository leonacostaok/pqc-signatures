#!/usr/bin/env python3
"""Write compact, loss-preserving views of completed exploratory result files."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('results', nargs='+')
    args = parser.parse_args()
    for name in args.results:
        path = Path(name)
        content = path.read_bytes()
        result = json.loads(content)
        if result['schema'] != 'bc-slh-deep-results-v1':
            raise ValueError('unexpected result schema')
        pairs = []
        for pair in result['process_pairs']:
            entry = {key: pair[key] for key in ['fork', 'parameter', 'operation', 'order']}
            for side in ['baseline', 'candidate']:
                entry[side] = {key: pair[side][key] for key in ['rounds', 'medians']}
                entry[side]['sample_count'] = len(pair[side]['rows'])
                entry[side]['zero_thread_cpu_samples'] = sum(row['thread_cpu_ns'] == 0 for row in pair[side]['rows'])
            for metric in ['wall_ns', 'cpu_ns', 'thread_cpu_ns', 'allocated_bytes']:
                entry[metric + '_ratio'] = pair[metric + '_ratio']
            pairs.append(entry)
        output = path.with_name(path.stem + '-summary.json')
        compact = {'schema': 'bc-slh-deep-compact-v1', 'original': str(path),
                   'original_sha256': hashlib.sha256(content).hexdigest(),
                   'plan': result['plan'], 'finished_at': result['finished_at'],
                   'statistic': result['statistic'], 'summary': result['summary'],
                   'process_pairs': pairs, 'raw_directory': result['raw_directory'],
                   'limits': 'Compact view only; exact per-call data, logs and chronology are preserved in the original result and raw directory.'}
        with output.open('x') as stream:
            json.dump(compact, stream, indent=2)
            stream.write('\n')
        print(output)


if __name__ == '__main__':
    main()
