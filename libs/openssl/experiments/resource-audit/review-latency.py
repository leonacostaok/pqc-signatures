#!/usr/bin/env python3
"""Recompute loss counts from retained C-provider latency observations only."""
import collections, hashlib, json, math, statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
def need(value, message):
    if not value: raise ValueError(message)
def read(path): return json.loads((ROOT / path).read_text())
def sha(path): return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
def close(a, b): need(math.isclose(a, b, rel_tol=1e-12), 'saved ratio mismatch')
def stats(values):
    need(bool(values) and all(math.isfinite(x) and x > 0 for x in values), 'invalid ratios')
    return dict(pairs=len(values), losses=sum(v < 1 for v in values), minimum=min(values), maximum=max(values), median=statistics.median(values))
def write(provider, value):
    (ROOT / 'results' / provider / 'resource-audit/latency-review.json').write_text(json.dumps(value, indent=2) + '\n')
def openssl():
    balanced_path = 'results/openssl/experiments/sha512-prefix-final.json'
    final = read(balanced_path); need(final['complete'] is True and len(final['pairs']) == 1260, 'incomplete balanced result')
    groups = collections.defaultdict(list); cells = collections.defaultdict(list)
    for p in final['pairs']:
        wall = p['ns_per_op']['baseline'] / p['ns_per_op']['candidate']
        cpu = p['cpu_ns_per_op']['baseline'] / p['cpu_ns_per_op']['candidate']
        close(wall, p['speedup']); close(cpu, p['cpu_speedup'])
        parameter = p['case'].rsplit('-', 1)[0]
        group = 'affected' if any(x in parameter for x in ['SHA2-192', 'SHA2-256']) else 'controls'
        groups[group].append((wall, cpu)); cells[(parameter, p['operation'])].append(p)
    cell_results = []
    for (parameter, op), pairs in sorted(cells.items()):
        need(len(pairs) == 90, 'bad parameter coverage')
        fw = []; fc = []
        for fork in range(5):
            rw = []; rc = []
            for round_ in range(6):
                subset = [p for p in pairs if p['fork'] == fork and p['round'] == round_]
                need(len(subset) == 3 and len({p['case'] for p in subset}) == 3, 'bad case coverage')
                for field, target in [('ns_per_op',rw), ('cpu_ns_per_op',rc)]:
                    target.append(sum(p[field]['baseline'] for p in subset) / sum(p[field]['candidate'] for p in subset))
            fw.append(statistics.median(rw)); fc.append(statistics.median(rc))
        cell_results.append(dict(parameter=parameter, operation=op, wall_median_fork_ratio=statistics.median(fw), cpu_median_fork_ratio=statistics.median(fc), wall_fork_ratios=fw, cpu_fork_ratios=fc, wall_pairs=stats([p['speedup'] for p in pairs]), cpu_pairs=stats([p['cpu_speedup'] for p in pairs])))
    loss_rows = [{k:p[k] for k in ['fork','round','case','operation','speedup','cpu_speedup']} for p in final['pairs'] if p['speedup'] < 1 or p['cpu_speedup'] < 1]
    ten_path = 'results/openssl/ten-key-order/summary.json'; ten = read(ten_path)
    need(ten['complete'] is True and len(ten['pairs']) == 210, 'incomplete ten-key result')
    ten_cells = []
    for cell in ten['summary']:
        rows = [p for p in ten['pairs'] if p['parameter'] == cell['parameter'] and p['operation'] == cell['operation']]
        need(len(rows) == 10 and {p['key_index'] for p in rows} == set(range(10)), 'missing ten-key rows')
        wall = [p['baseline_wall_ns']/p['candidate_wall_ns'] for p in rows]; cpu = [p['baseline_cpu_ns']/p['candidate_cpu_ns'] for p in rows]
        ratio = sum(p['baseline_wall_ns'] for p in rows) / sum(p['candidate_wall_ns'] for p in rows)
        close(ratio, cell['total_time_speedup']); need(sum(v<1 for v in wall) == cell['key_losses'], 'bad losses')
        ten_cells.append(dict(parameter=cell['parameter'], operation=cell['operation'], wall_total_ratio=ratio, cpu_total_ratio=sum(p['baseline_cpu_ns'] for p in rows)/sum(p['candidate_cpu_ns'] for p in rows), wall=stats(wall), cpu=stats(cpu)))
    write('openssl', dict(complete=True, no_new_measurements=True, balanced=dict(source=balanced_path, sha256=sha(balanced_path), groups={g:dict(wall=stats([r[0] for r in v]),cpu=stats([r[1] for r in v])) for g,v in groups.items()}, parameters=cell_results, losses=loss_rows), candidate_first_ten_keys=dict(source=ten_path, sha256=sha(ten_path), cells=ten_cells, limitation='One pass; all candidate batches precede all baseline batches, so elapsed-time drift is confounded with variant order.')))

def liboqs():
    prefix = 'libs/liboqs/experiments/sha2-openssl/evidence/final-paired/'
    summary = read(prefix + 'summary.json'); by_cell = collections.defaultdict(list); individual = []
    raw_hashes = {}
    for fork in range(1,7):
        variants = {}
        for side in ['baseline','candidate']:
            path = prefix + f'{fork:02d}-{side}.jsonl'; raw_hashes[path] = sha(path)
            rows = [json.loads(line) for line in (ROOT/path).read_text().splitlines()]
            variants[side] = {(r['parameter'],r['operation'],r['case']):r['total_ns']/r['iterations'] for r in rows}
            need(len(rows) == len(variants[side]) == 48, 'missing/duplicate balanced raw rows')
        need(variants['baseline'].keys() == variants['candidate'].keys(), 'different paired inputs')
        for key in variants['baseline']:
            individual.append(variants['baseline'][key]/variants['candidate'][key])
        for parameter, op in sorted({(k[0], k[1]) for k in variants['baseline']}):
            keys = [(parameter,op,i) for i in range(4)]
            by_cell[(parameter,op)].append(sum(variants['baseline'][k] for k in keys)/sum(variants['candidate'][k] for k in keys))
    for cell in summary:
        values = by_cell[(cell['parameter'],cell['operation'])]
        need(len(values) == len(cell['paired_speedups']) == 6, 'bad paired summary')
        for actual,saved in zip(values,cell['paired_speedups']): close(actual,saved)
    ten_path = 'libs/liboqs/experiments/ten-new-keys/evidence/summary.json'; ten = read(ten_path)
    need(ten['complete'] is True and len(ten['summary']) == 18, 'incomplete ten-key result')
    ten_cells = []
    for cell in ten['summary']:
        need(len(cell['wall_per_key_ratios']) == len(cell['cpu_per_key_ratios']) == 10, 'bad ten-key pair count')
        for clock in ['wall','cpu']:
            close(cell[clock+'_baseline_total_ns']/cell[clock+'_candidate_total_ns'],cell[clock+'_ratio_of_total_times'])
            need(sum(v<1 for v in cell[clock+'_per_key_ratios']) == cell[clock+'_key_losses'], 'bad ten-key losses')
        ten_cells.append(dict(parameter=cell['parameter'],operation=cell['operation'],wall_total_ratio=cell['wall_ratio_of_total_times'],cpu_total_ratio=cell['cpu_ratio_of_total_times'],wall=stats(cell['wall_per_key_ratios']),cpu=stats(cell['cpu_per_key_ratios'])))
    ablation = 'libs/liboqs/experiments/sha2-ablation/evidence/final/summary.json'; ab = read(ablation)
    need(ab['complete'] is True, 'incomplete ablation')
    full = [r for r in ab['summary'] if r['variant'] == 'full']; need(len(full) == 18, 'missing full ablation cells')
    ablation_cells = []
    for cell in full:
        clocks = {}
        for clock in ['wall','cpu']:
            m = cell[clock]; ratios = [a/b for a,b in zip(m['round_total_ns']['original'],m['round_total_ns']['full'])]
            need(len(ratios) == 6, 'bad ablation round count')
            for actual,saved in zip(ratios,m['speedup_vs_original']): close(actual,saved)
            clocks[clock] = dict(round_totals=stats(ratios), individual_keys=stats(m['individual_key_speedups_vs_original']))
        ablation_cells.append(dict(parameter=cell['parameter'],operation=cell['operation'],**clocks))
    write('liboqs', dict(complete=True,no_new_measurements=True,balanced=dict(source=prefix+'summary.json',sha256=sha(prefix+'summary.json'),raw_sha256=raw_hashes,individual_case_pairs=stats(individual),parameter_operation_round_pairs=stats([v for values in by_cell.values() for v in values]),cells=summary,cpu='Not recorded in this first balanced experiment.'), candidate_first_ten_keys=dict(source=ten_path,sha256=sha(ten_path),cells=ten_cells,limitation=ten['limitation']),full_patch_ablation=dict(source=ablation,sha256=sha(ablation),cells=ablation_cells),scope='Final published runtime only; reduced SHA256-only/SHA512-only ablations and pre-cleanse pilots are not the published implementation. Source-bound prior independent checks remain the full corpus/binary validation record.'))
if __name__ == '__main__':
    openssl(); liboqs(); print('Retained OpenSSL/liboqs ratios and all loss counts recomputed; no new timings')
