#!/usr/bin/env python3
"""Fresh-input noble row-dot checks and counterbalanced, isolated measurements."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BUILD = ROOT / "libs/noble/build/robustness"
VERSIONS = ["0.7.0", "0.7.1"]
VARIANTS = ["baseline", "candidate"]
LEVELS = [44, 65, 87]
OPS = ["keygen", "getPublicKey", "sign", "verify"]
PATCHES = [ROOT / "libs/noble/patches" / name for name in ["ml-dsa-rowdot.patch", "ml-dsa-rowdot-js.patch"]]
ENV = dict(os.environ, NODE_OPTIONS="")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(args, cwd=None, env=ENV):
    return subprocess.check_output([str(x) for x in args], cwd=cwd, env=env, text=True, stderr=subprocess.PIPE)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(path):
    files = {str(p.relative_to(path)): sha(p) for p in sorted(path.rglob("*")) if p.is_file()}
    return {"sha256": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(), "files": len(files)}


def inputs():
    files = list(HERE.glob("*.mjs")) + list(HERE.glob("*.py")) + PATCHES
    files += [HERE / "versions" / v / name for v in VERSIONS for name in ["package.json", "package-lock.json"]]
    files += [ROOT / "common/validation/validation.json.gz"]
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}


def atomic_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=path.name + ".", delete=False) as f:
        json.dump(value, f, indent=2); f.write("\n")
        temp = Path(f.name)
    try:
        os.link(temp, path)
    finally:
        temp.unlink()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def npm_module(path):
    return path / "node_modules/@noble/post-quantum"


def patch_env(path):
    return dict(ENV, GIT_CEILING_DIRECTORIES=str(path.parent))


def prepared():
    data = json.loads((BUILD / "prepared.json").read_text())
    require(data["inputs"] == inputs(), "experiment inputs changed; prepare and check again")
    return data


def provenance(node, version):
    data = prepared()
    root = BUILD / "snapshots" / data["snapshot"] / version
    sources = {v: tree(root / v) for v in VARIANTS}
    source_js = {v: sha(npm_module(root / v) / "ml-dsa.js") for v in VARIANTS}
    require(source_js["baseline"] != source_js["candidate"], "candidate is unchanged upstream")
    require(sources == data["versions"][version]["sources"], "prepared sources were modified")
    runtime = json.loads(run([node, "-e", "console.log(JSON.stringify({node:process.version,v8:process.versions.v8,arch:process.arch,platform:process.platform}))"]))
    require(runtime["node"].split(".")[0] in {"v22", "v24"}, "use Node 22 or 24")
    return {"version": version, "snapshot": data["snapshot"], "inputs": inputs(), "sources": sources, "source_js": source_js,
            "node_path": str(node), "node_sha256": sha(node), "runtime": runtime, "NODE_OPTIONS": ENV["NODE_OPTIONS"],
            "platform": platform.platform(), "machine": platform.machine(), "dependencies": data["versions"][version]["dependencies"]}


def prepare():
    for version in VERSIONS:
        deps = HERE / "versions" / version
        require((deps / "package-lock.json").exists(), "create and retain dependency locks before preparing")
        run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", deps])
    hashes = inputs()
    identity = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:16]
    root = BUILD / "snapshots" / identity
    require(not root.exists(), f"snapshot already exists: {root}")
    manifest = {"snapshot": identity, "inputs": hashes, "versions": {}}
    for version in VERSIONS:
        deps = HERE / "versions" / version
        lock = json.loads((deps / "package-lock.json").read_text())
        official = deps / "node_modules/@noble/post-quantum"
        require(json.loads((official / "package.json").read_text())["version"] == version, "wrong package version")
        for variant in VARIANTS:
            dest = root / version / variant
            dest.mkdir(parents=True)
            shutil.copytree(deps / "node_modules", dest / "node_modules")
            package = npm_module(dest)
            if variant == "candidate":
                for patch in PATCHES:
                    run(["git", "apply", "--check", patch], cwd=package, env=patch_env(package))
                    run(["git", "apply", patch], cwd=package, env=patch_env(package))
                    run(["git", "apply", "--reverse", "--check", patch], cwd=package, env=patch_env(package))
                js = (package / "ml-dsa.js").read_text()
                require(js.count("const DotNTTs =") == 1 and js.count("DotNTTs(") == 4, "missing row-dot helper or callsites")
                (package / "ml-dsa.audit.js").write_text(js + "\nexport { DotNTTs };\n")
        baseline, candidate = [root / version / v for v in VARIANTS]
        allowed = {"node_modules/@noble/post-quantum/ml-dsa.js", "node_modules/@noble/post-quantum/src/ml-dsa.ts"}
        baseline_files = {str(p.relative_to(baseline)) for p in baseline.rglob("*") if p.is_file()}
        candidate_files = {str(p.relative_to(candidate)) for p in candidate.rglob("*") if p.is_file()}
        require(candidate_files == baseline_files | {"node_modules/@noble/post-quantum/ml-dsa.audit.js"}, "unexpected candidate file set")
        for path in baseline.rglob("*"):
            if path.is_file() and str(path.relative_to(baseline)) not in allowed:
                require(sha(path) == sha(candidate / path.relative_to(baseline)), "unexpected candidate source change")
        for name in ["ml-dsa.js", "src/ml-dsa.ts"]:
            require(sha(npm_module(baseline) / name) == sha(official / name), "baseline differs from official package")
            require(sha(npm_module(baseline) / name) != sha(npm_module(candidate) / name), "patch was not applied")
        manifest["versions"][version] = {"sources": {v: tree(root / version / v) for v in VARIANTS},
                                         "dependencies": {k: {field: value[field] for field in ["version", "resolved", "integrity"] if field in value}
                                                          for k, value in lock["packages"].items() if k}}
    require(inputs() == hashes, "inputs changed while preparing")
    write_json(BUILD / "prepared.json", manifest)
    print(json.dumps({"prepared": str(root), "versions": VERSIONS}))


def locations(prov):
    root = BUILD / "snapshots" / prov["snapshot"] / prov["version"]
    return {v: npm_module(root / v) for v in VARIANTS}


def child(node, module, fixture, **kwargs):
    args = {"module": str(module / "ml-dsa.js"), "fixture": str(fixture), **kwargs}
    began = time.perf_counter_ns()
    raw = run([node, HERE / "worker.mjs", json.dumps(args)])
    total = time.perf_counter_ns() - began
    result = json.loads(raw)
    # Includes interpreter startup, module/fixture loading, the operation(s),
    # post-timing equality checks, JSON serialization and process termination.
    result["process_total_ns"] = total
    return result


def gate_path(node, version):
    return BUILD / ("gate-" + version + "-" + sha(node)[:12] + ".json")


def check(node, version):
    before = provenance(node, version); paths = locations(before)
    results = {"fresh_inputs": json.loads(run([node, HERE / "fresh-input-test.mjs"])),
               "worker_protocol": json.loads(run([node, HERE / "worker-test.mjs"])),
               "arithmetic": json.loads(run([node, HERE / "arithmetic.mjs", paths["candidate"] / "ml-dsa.audit.js"])),
               "correctness": json.loads(run([node, HERE / "correctness.mjs", paths["baseline"] / "ml-dsa.js", paths["candidate"] / "ml-dsa.js", paths["baseline"].parent / "hashes/sha2.js"]))}
    require(results["arithmetic"]["dotCases"] == 204 and results["correctness"]["checked"] == 219 and results["correctness"]["differentialCases"] == 72, "incomplete correctness tests")
    require(results["worker_protocol"]["checked"] == 8 and results["worker_protocol"]["first_operation_exactly_once"], "incomplete worker protocol regression")
    fixture = BUILD / ("gate-fixture-" + version + ".json")
    fixture.write_text(run([node, HERE / "fixture.mjs", paths["baseline"] / "ml-dsa.js", "0"]))
    results["fresh_corpus"] = {v: child(node, paths[v], fixture, mode="check") for v in VARIANTS}
    require(all(x["checked"] == 288 for x in results["fresh_corpus"].values()), "incomplete fresh corpus checks")
    require(provenance(node, version) == before, "sources/runtime changed during correctness")
    gate = {"provenance": before, "checks": results, "fixture_sha256": sha(fixture), "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    write_json(gate_path(node, version), gate)
    print(json.dumps(gate, indent=2))


def median(values):
    return statistics.median(values)


def benchmark(args):
    require(args.forks >= 5 and args.forks <= 30, "require 5..30 forks")
    require(args.rounds >= 2 and args.rounds <= 12 and args.rounds % 2 == 0, "rounds must be even, 2..12")
    require(1 <= args.single_cases <= 12 and 0 <= args.start < 1000000, "invalid corpus parameters")
    require(math.isfinite(args.budget_ms) and args.budget_ms >= 100 and math.isfinite(args.warmup_ms) and args.warmup_ms >= 100, "warmup/budget must be >=100ms")
    out = args.out.resolve(); require(not out.exists(), "refuse to overwrite evidence")
    before = provenance(args.node, args.version); paths = locations(before)
    gate = json.loads(gate_path(args.node, args.version).read_text())
    require(gate["provenance"] == before, "no matching correctness gate")
    # Retain each raw measurement as it is obtained, including losing/noisy rows
    # and incomplete runs; never replace an existing directory or report.
    evidence = out.with_name(out.name + ".raw"); evidence.mkdir(parents=True)
    write_json(evidence / "manifest.json", {"provenance": before, "gate": gate, "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}})
    rows = []; corpus_hashes = {}; started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        for fork in range(args.start, args.start + args.forks):
            fixture = evidence / f"corpus-{fork}.json"
            fixture.write_text(run([args.node, HERE / "fixture.mjs", paths["baseline"] / "ml-dsa.js", str(fork)]))
            corpus_hashes[str(fork)] = sha(fixture)
            for variant in VARIANTS:
                checked = child(args.node, paths[variant], fixture, mode="check")
                require(checked["checked"] == 288, "incomplete per-fork correctness")
            rng = random.Random(f"rowdot-fresh-v1/{fork}")
            cells = [(level, op) for level in LEVELS for op in OPS]; rng.shuffle(cells)
            for cell_index, (level, op) in enumerate(cells):
                case_order = list(range(12)); rng.shuffle(case_order)
                start_order = (fork + cell_index) % 2
                modes = ["warm", "single"]; rng.shuffle(modes)
                for mode in modes:
                    indices = range(args.rounds) if mode == "warm" else case_order[:args.single_cases]
                    for ordinal, index in enumerate(indices):
                        order = VARIANTS if (start_order + ordinal) % 2 == 0 else list(reversed(VARIANTS))
                        # Single cases also get a reversed pair, avoiding an
                        # unbalanced order when single_cases is odd.
                        repetitions = [0] if mode == "warm" else [0, 1]
                        for reversal in repetitions:
                            actual_order = order if reversal == 0 else list(reversed(order))
                            pair = {}
                            for variant in actual_order:
                                result = child(args.node, paths[variant], fixture, mode=mode, level=level, op=op, order=case_order,
                                               index=index if mode == "single" else None, budgetMs=args.budget_ms, warmupMs=args.warmup_ms)
                                require(result["mode"] == mode and result["level"] == level and result["op"] == op and result["fork"] == fork, "wrong timed operation")
                                require(result["runtime"] == before["runtime"]["node"], "wrong runtime")
                                require(math.isfinite(result["ns_per_op"]) and result["ns_per_op"] > 0, "invalid timing")
                                require(result["iterations"] == 1 if mode == "single" else result["iterations"] >= 12 and result["iterations"] % 12 == 0, "partial corpus cycle")
                                pair[variant] = result
                                atomic_new(evidence / f"sample-{len(rows):05d}-{variant}.json", {"fork": fork, "level": level, "op": op, "mode": mode, "ordinal": ordinal, "index": index, "reversal": reversal, "order": actual_order, "result": result})
                            rows.append({"fork": fork, "level": level, "op": op, "mode": mode, "ordinal": ordinal, "index": index, "reversal": reversal,
                                         "order": actual_order, "case_order": case_order, **pair, "speedup": pair["baseline"]["ns_per_op"] / pair["candidate"]["ns_per_op"],
                                         "startup_inclusive_speedup": pair["baseline"]["process_total_ns"] / pair["candidate"]["process_total_ns"]})
                print(f"Fork {fork}: ML-DSA-{level} {op} complete", file=sys.stderr)
            require(sha(fixture) == corpus_hashes[str(fork)], "corpus changed")
            require(provenance(args.node, args.version) == before, "source/runtime changed")
        summary = []
        for mode in ["warm", "single"]:
            for level in LEVELS:
                for op in OPS:
                    forks = []
                    for fork in range(args.start, args.start + args.forks):
                        selected = [r for r in rows if (r["mode"], r["level"], r["op"], r["fork"]) == (mode, level, op, fork)]
                        require(len(selected) == (args.rounds if mode == "warm" else args.single_cases * 2), "incomplete measurement matrix")
                        forks.append({"fork": fork, "speedup": median(r["speedup"] for r in selected),
                                      "baseline_ns": median(r["baseline"]["ns_per_op"] for r in selected), "candidate_ns": median(r["candidate"]["ns_per_op"] for r in selected),
                                      "startup_inclusive_speedup": median(r["startup_inclusive_speedup"] for r in selected)})
                    ratios = [f["speedup"] for f in forks]
                    item = {"mode": mode, "level": level, "op": op, "speedup": median(ratios), "fork_min": min(ratios), "fork_max": max(ratios), "forks": forks}
                    if mode == "single":
                        item["startup_inclusive_speedup"] = median(f["startup_inclusive_speedup"] for f in forks)
                    summary.append(item)
        report = {"schema": "noble-rowdot-fresh-v1", "started_at": started, "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "statistic": "median of within-fork median paired ratios; fork ranges are descriptive, not confidence intervals",
                  "timing_scope": {"operation": "ordinary one-shot API including new caller input arrays/options on every call",
                                   "single": "first cryptographic operation in a new process; import/fixture loading excluded",
                                   "startup_inclusive": "parent-observed process lifetime including startup, imports, fixture loading, operation, equality checks, serialization and exit"},
                  "provenance": before, "correctness": gate, "corpora": corpus_hashes, "summary": summary, "rows": rows}
        atomic_new(out, report)
        print(f"Saved {out}", file=sys.stderr)
    except BaseException as error:
        atomic_new(evidence / "FAILED.json", {"error": repr(error), "stderr": getattr(error, "stderr", None), "stdout": getattr(error, "stdout", None),
                                                "complete_pairs": len(rows), "started_at": started})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    for command in ["check", "bench"]:
        p = sub.add_parser(command)
        p.add_argument("--node", required=True, type=Path)
        p.add_argument("--version", required=True, choices=VERSIONS)
        if command == "bench":
            p.add_argument("--out", type=Path, required=True)
            p.add_argument("--forks", type=int, default=5)
            p.add_argument("--rounds", type=int, default=4)
            p.add_argument("--start", type=int, default=30)
            p.add_argument("--single-cases", type=int, default=3)
            p.add_argument("--budget-ms", type=float, default=250)
            p.add_argument("--warmup-ms", type=float, default=200)
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    lock = BUILD / ".robustness.lock"; lock.mkdir()
    try:
        if args.command == "prepare": prepare()
        else:
            args.node = args.node.resolve()
            require(args.node.is_file(), "Node executable missing")
            if args.command == "check": check(args.node, args.version)
            else: benchmark(args)
    finally:
        lock.rmdir()


if __name__ == "__main__":
    main()
