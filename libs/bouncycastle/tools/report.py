#!/usr/bin/env python3
"""Preliminary results tables for docs/bouncycastle/{keygen,sign,verify}.md from results/bouncycastle/bench.jsonl.
Everything after the <!-- RESULTS --> marker is replaced (the orchestrator's common/report.mjs does the same for
the final run). Usage: report.py <bench.jsonl> <docs dir> [label]"""
import json, sys, statistics
from collections import defaultdict

bench, docs = sys.argv[1], sys.argv[2]
label = sys.argv[3] if len(sys.argv) > 3 else "preliminary, --budget-ms 200 on a shared 4-core box"
rows = [json.loads(l) for l in open(bench) if l.strip()]
by_op = defaultdict(lambda: defaultdict(dict))  # op -> param -> variant -> row
for r in rows:
    by_op[r["op"]][r["param"]][r["variant"]] = r

def fmt_us(ns):
    return f"{ns/1e3:,.1f}"

for op in ("keygen", "sign", "verify"):
    path = f"{docs}/{op}.md"
    text = open(path).read()
    head = text.split("<!-- RESULTS -->")[0]
    out = [head + "<!-- RESULTS -->\n", f"\n## Results ({label})\n",
           "\nMedian wall time per op (us), process CPU per op (us), cpu_util, and speedup of median wall vs v0.\n",
           "Parallel variants: wall = batch wall / batch size, i.e. throughput-equivalent per-op time on all cores.\n"]
    params = list(by_op[op].keys())
    variants = sorted({v for p in params for v in by_op[op][p]})
    names = {v: next(r["variant_name"] for p in params for vv, r in by_op[op][p].items() if vv == v) for v in variants}
    for p in params:
        out.append(f"\n### {p}\n\n| variant | iters | wall median us | wall p95 us | cpu/op us | cpu_util | ops/s | speedup | match |\n|---|---|---|---|---|---|---|---|---|\n")
        base = by_op[op][p].get(f"{op}.v0", {}).get("wall_ns_median")
        for v in variants:
            r = by_op[op][p].get(v)
            if not r:
                continue
            sp = f"{base / r['wall_ns_median']:.2f}x" if base and r["wall_ns_median"] else "-"
            thr = f" (t={r['threads']})" if r.get("threads", 1) > 1 else ""
            out.append(f"| {v} `{names[v]}`{thr} | {r['iterations']} | {fmt_us(r['wall_ns_median'])} | {fmt_us(r['wall_ns_p95'])} | {fmt_us(r['cpu_ns_per_op'])} | {r['cpu_util']:.2f} | {r['ops_per_sec']:,.1f} | {sp} | {r['match']} |\n")
    # geometric-mean speedup per variant across params
    out.append("\n### Geometric mean speedup vs v0 across parameter sets\n\n| variant | ML-DSA | SLH-DSA | all |\n|---|---|---|---|\n")
    for v in variants:
        groups = {"ML-DSA": [], "SLH-DSA": [], "all": []}
        for p in params:
            r, b = by_op[op][p].get(v), by_op[op][p].get(f"{op}.v0")
            if r and b and r["wall_ns_median"] and b["wall_ns_median"]:
                s = b["wall_ns_median"] / r["wall_ns_median"]
                groups["all"].append(s)
                groups["ML-DSA" if p.startswith("ML") else "SLH-DSA"].append(s)
        cells = [f"{statistics.geometric_mean(g):.2f}x" if g else "-" for g in (groups["ML-DSA"], groups["SLH-DSA"], groups["all"])]
        out.append(f"| {v} `{names[v]}` | " + " | ".join(cells) + " |\n")
    open(path, "w").write("".join(out))
    print("wrote", path)
