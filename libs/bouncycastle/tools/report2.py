#!/usr/bin/env python3
"""Preliminary tables for docs/bouncycastle/{verify-stages,memory,validation}.md (everything after <!-- RESULTS -->
is replaced). Usage: report2.py <results dir> <docs dir> [label]"""
import json, sys, os, statistics
from collections import defaultdict, OrderedDict

res, docs = sys.argv[1], sys.argv[2]
label = sys.argv[3] if len(sys.argv) > 3 else "preliminary dev run on a shared 4-core box"

def replace_results(path, body):
    text = open(path).read()
    head = text.split("<!-- RESULTS -->")[0]
    open(path, "w").write(head + "<!-- RESULTS -->\n" + body)
    print("wrote", path)

def us(ns): return f"{ns/1e3:,.1f}"

# ---------------------------------------------------------------- stages
f = os.path.join(res, "stages.jsonl")
if os.path.exists(f):
    rows = [json.loads(l) for l in open(f) if l.strip()]
    by = defaultdict(lambda: defaultdict(OrderedDict))  # param -> stage -> variant -> row
    for r in rows: by[r["param"]][r["stage"]][r["variant"]] = r
    out = [f"\n## Results ({label})\n", "\nMedian wall per stage execution (us); speedup = median of `<stage>.v0` / median of the variant; match = canonical output equals v0's.\n"]
    for param in by:
        out.append(f"\n### {param}\n\n| stage | variant | iters | median us | p95 us | cpu/op us | threads | speedup vs v0 | match |\n|---|---|---|---|---|---|---|---|---|\n")
        for stage, vs in by[param].items():
            base = vs.get(f"{stage}.v0", {}).get("wall_ns_median")
            for vid, r in vs.items():
                sp = f"{base / r['wall_ns_median']:.2f}x" if base and r.get("wall_ns_median") else "-"
                if stage == "total_best" and r.get("composition"): sp = sp + " vs total.v0" if False else sp
                comp = (" `" + ",".join(v.split(".")[-1] if False else v for v in r["composition"].values()) + "`") if r.get("composition") and stage == "total_best" else ""
                out.append(f"| {stage} | `{vid}` {r['variant_name']}{comp} | {r.get('iterations','')} | {us(r.get('wall_ns_median',0))} | {us(r.get('wall_ns_p95',0))} | {us(r.get('cpu_ns_per_op',0))} | {r.get('threads',1)} | {sp} | {r.get('match')} |\n")
        tb, tv = by[param].get("total_best", {}).get("total_best"), by[param].get("total", {}).get("total.v0")
        if tb and tv and tb.get("wall_ns_median"):
            out.append(f"\ntotal_best vs total.v0: {tv['wall_ns_median'] / tb['wall_ns_median']:.2f}x\n")
    # geometric means per family
    out.append("\n### Geometric mean speedup vs stage v0 (per family)\n\n| variant | ML-DSA | SLH-DSA SHA2 | SLH-DSA SHAKE |\n|---|---|---|---|\n")
    allv = OrderedDict()
    for param in by:
        for stage, vs in by[param].items():
            for vid in vs: allv[vid] = stage
    for vid, stage in allv.items():
        if stage in ("total", "total_best"): continue
        g = {"ML-DSA": [], "SHA2": [], "SHAKE": []}
        for param in by:
            r, b = by[param].get(stage, {}).get(vid), by[param].get(stage, {}).get(f"{stage}.v0")
            if r and b and r.get("wall_ns_median") and b.get("wall_ns_median"):
                k = "ML-DSA" if param.startswith("ML") else ("SHA2" if "SHA2" in param else "SHAKE")
                g[k].append(b["wall_ns_median"] / r["wall_ns_median"])
        cells = [f"{statistics.geometric_mean(x):.2f}x" if x else "-" for x in (g["ML-DSA"], g["SHA2"], g["SHAKE"])]
        out.append(f"| `{vid}` | " + " | ".join(cells) + " |\n")
    replace_results(os.path.join(docs, "verify-stages.md"), "".join(out))

# ---------------------------------------------------------------- memory
f = os.path.join(res, "memory.jsonl")
if os.path.exists(f):
    rows = [json.loads(l) for l in open(f) if l.strip()]
    out = [f"\n## Results ({label})\n", "\nstack = peak stack of one op (bytes, resolution = one compiled recursion frame); heap = allocated bytes per op.\n"]
    params = OrderedDict((r["param"], 1) for r in rows)
    for param in params:
        out.append(f"\n### {param}\n\n| op | variant | stack bytes | heap alloc bytes/op | threads | match |\n|---|---|---|---|---|---|\n")
        for r in rows:
            if r["param"] != param: continue
            v = r["variant"] + (f" ({r['stage']})" if r.get("stage") and r["stage"] not in r["variant"] else "")
            out.append(f"| {r['op']} | `{v}` | {r.get('stack_bytes')} | {r.get('heap_alloc_bytes_per_op')} | {r.get('threads')} | {r.get('match')}{(' ' + r['error']) if r.get('error') else ''} |\n")
    replace_results(os.path.join(docs, "memory.md"), "".join(out))

# ---------------------------------------------------------------- validation
f = os.path.join(res, "validation.json")
if os.path.exists(f):
    d = json.load(open(f))
    out = [f"\n## Results ({label})\n", "\n| variant | pass | fail | skipped |\n|---|---|---|---|\n"]
    for v, s in d["summary"].items():
        out.append(f"| `{v}` | {s['pass']} | {s['fail']} | {s['skipped']} |\n")
    fails = [r for r in d["results"] if not r.get("pass") and not r.get("skipped")]
    out.append(f"\nTotal results: {len(d['results'])}, failures: {len(fails)}\n")
    if fails:
        out.append("\n### Failures\n\n| id | variant | got | error | reason |\n|---|---|---|---|---|\n")
        for r in fails[:200]:
            out.append(f"| {r['id']} | `{r['variant']}` | {r.get('got')} | {r.get('error')} | {r.get('reason','')} |\n")
    replace_results(os.path.join(docs, "validation.md"), "".join(out))
