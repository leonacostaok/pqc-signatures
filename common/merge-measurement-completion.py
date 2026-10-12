#!/usr/bin/env python3
"""Validate and collect new baseline-only timings; never manufacture a candidate."""
import argparse
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIBRARIES = {'noble', 'liboqs', 'openssl', 'circl', 'rustcrypto', 'bouncycastle'}
PARAMETERS = {f'ML-DSA-{p}' for p in [44, 65, 87]} | {f'SLH-DSA-{h}-{p}{v}' for h in ['SHA2', 'SHAKE'] for p in [128, 192, 256] for v in ['f', 's']} | {'Falcon-512', 'Falcon-1024'}

def normalize(value):
    text = str(value)
    if text in ['44', '65', '87']:
        return 'ML-DSA-' + text
    text = text.replace('SLH_DSA_PURE_', 'SLH-DSA-').replace('_', '-')
    if text.lower().startswith(('sha2-', 'shake-')):
        text = 'SLH-DSA-' + text
    if text.upper().startswith('SLH-DSA-'):
        text = text.upper()[:-1] + text[-1].lower()
    return text

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', action='append', required=True, type=Path)
    parser.add_argument('--out', type=Path, default=ROOT/'results/measurement-completion/coverage.json')
    args = parser.parse_args()
    rows, seen, sources, unsupported = [], set(), {}, []
    for name in args.summary:
        path = name.resolve()
        relative = str(path.relative_to(ROOT))
        raw = path.read_bytes()
        data = json.loads(raw)
        sources[relative] = hashlib.sha256(raw).hexdigest()
        for entry in data['baseline_timings']:
            row = dict(entry)
            row['parameter'] = normalize(row['parameter'])
            key = row['library'], row['parameter'], row['operation']
            if row['library'] not in LIBRARIES or row['parameter'] not in PARAMETERS or row['operation'] not in ['keygen', 'sign', 'verify', 'getPublicKey']:
                raise ValueError(f'Unknown cell: {key}')
            if key in seen:
                raise ValueError(f'Duplicate baseline cell: {key}')
            if isinstance(row['wall_ns'], bool) or not math.isfinite(row['wall_ns']) or row['wall_ns'] <= 0:
                raise ValueError(f'Invalid baseline time: {key}')
            for field in ['statistic', 'protocol', 'source']:
                if not isinstance(row[field], str) or not row[field].strip():
                    raise ValueError(f'Missing {field}: {key}')
            source = ROOT / row['source']
            if not source.is_file():
                raise ValueError(f'Missing evidence: {source}')
            row['source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
            row['summary'] = relative
            row['status'] = 'baseline_only'
            row['candidate_wall_ns'] = None
            row['time_saved_percent'] = None
            rows.append(row)
            seen.add(key)
        for entry in data.get('unsupported', []):
            for operation in entry['operations']:
                key = entry['library'], normalize(entry['parameter']), operation
                if key[0] not in LIBRARIES or key[1] not in PARAMETERS or operation not in ['keygen', 'sign', 'verify']:
                    raise ValueError(f'Unknown unsupported cell: {key}')
                if key in seen or not entry.get('reason'):
                    raise ValueError(f'Duplicate or unexplained unsupported cell: {key}')
                unsupported.append(dict(library=key[0], parameter=key[1], operation=operation,
                                        reason=entry['reason'], summary=relative, provider_evidence=entry.get('source')))
                seen.add(key)
    result = dict(schema='measurement-completion-coverage-v1', summaries=sources, baseline_timings=rows,
                  unsupported=unsupported, limits='Baseline-only observations use their declared protocol; never a candidate gain or a controlled cross-provider ranking.')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, allow_nan=False)+'\n')
    print(f'Collected {len(rows)} baseline-only cells from {len(sources)} summaries')

if __name__ == '__main__':
    main()
