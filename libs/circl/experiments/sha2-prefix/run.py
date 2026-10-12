#!/usr/bin/env python3
"""Reproduce the production CIRCL SHA-2 prefix experiment, failing on any mismatch."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BUILD = ROOT / "libs/circl/build/sha2-prefix"
UPSTREAM = "91db3e785ba2635b4f24a023e1ad76d2780e2865"
UPSTREAM_STATE = "9e08f7a7c6f73fc54e89f7afa302e18ff370eb66043588b09d8583964827dd78"
FOCUSED_TESTS = {"TestSHA2PrefixDigests", "TestSHA2PrefixReuse", "TestSHA2PrefixAllocations"}
PARAMS = [f"SLH-DSA-SHA2-{n}{s}" for n in [128, 192, 256] for s in ["f", "s"]] + ["SLH-DSA-SHAKE-128f"]
OPS = ["keygen", "sign", "verify"]
ENV = dict(os.environ, GOMAXPROCS="1", GOTOOLCHAIN="local")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, cwd=None, log=None, env=ENV):
    if log:
        with open(log, "w") as out:
            subprocess.run([str(x) for x in args], cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, check=True)
        return ""
    return subprocess.check_output([str(x) for x in args], cwd=cwd, env=env, text=True)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_digest(path):
    files = {str(p.relative_to(path)): digest(p) for p in sorted(path.rglob("*"))
             if p.is_file() and (p.suffix in {".go", ".s", ".h", ".c"} or p.name in {"go.mod", "go.sum"})}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def patch_env(path):
    # Archive directories live below another Git repository. Never let git apply
    # discover that parent and silently skip paths outside its current prefix.
    return dict(ENV, GIT_CEILING_DIRECTORIES=str(path.parent))


def focused_test(path, args, log, expected_pass):
    result = subprocess.run(["go", "test", "-json", *args, "./sign/slhdsa", "-count=1"],
                            cwd=path, env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(result.stdout)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if expected_pass:
        require(result.returncode == 0, f"focused tests failed: {log}")
        passed = {e.get("Test") for e in events if e.get("Action") == "pass"}
        require(FOCUSED_TESTS <= passed, f"missing expected focused tests: {FOCUSED_TESTS - passed}")
        return sorted(FOCUSED_TESTS)
    failed = {e.get("Test") for e in events if e.get("Action") == "fail"}
    require(result.returncode != 0 and "TestSHA2PrefixReuse" in failed, "baseline resource gate unexpectedly passed or did not run")
    require(sum(name.startswith("TestSHA2PrefixReuse/SLH-DSA-SHA2-") and name.count("/") == 1 for name in failed if name) == 6,
            "baseline did not fail the resource gate for all six parameter sets")
    require(result.stdout.count("without repeated seed blocks") == 18, "baseline resource gate failed for an unexpected reason")
    return sorted(name for name in failed if name)


def inputs():
    paths = [HERE / "run.py", HERE / "main.go", HERE / "production.patch", HERE / "tests.patch", ROOT / "common/validation/validation.json.gz"]
    return {str(p.relative_to(ROOT)): digest(p) for p in paths}


def atomic_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=path.name + ".", delete=False) as f:
        json.dump(data, f, indent=2); f.write("\n")
        temporary = Path(f.name)
    try:
        os.link(temporary, path)  # Refuse to replace existing evidence, including a racing writer.
    finally:
        temporary.unlink()


def layout():
    manifest = json.loads((BUILD / "prepared.json").read_text())
    require(manifest["inputs"] == inputs(), "inputs changed; prepare and check again")
    return {v: BUILD / manifest["snapshot"] / v for v in ["baseline", "candidate"]}


def provenance(dirs):
    sources = {v: digest(dirs[v] / "sign/slhdsa/state.go") for v in dirs}
    binaries = {v: digest(dirs[v] / "prefixbench") for v in dirs}
    require(sources["baseline"] == UPSTREAM_STATE, "baseline source differs from pinned upstream")
    require(sources["baseline"] != sources["candidate"], "candidate source is identical to baseline: patch was not applied")
    require(binaries["baseline"] != binaries["candidate"], "candidate binary is identical to baseline")
    for variant, path in dirs.items():
        require((path / "sign/slhdsa/state_prefix_test.go").is_file(), "focused tests are missing")
        run(["git", "apply", "--reverse", "--check", HERE / "tests.patch"], cwd=path, env=patch_env(path))
        if variant == "candidate":
            run(["git", "apply", "--reverse", "--check", HERE / "production.patch"], cwd=path, env=patch_env(path))
    return {
        "upstream": UPSTREAM, "inputs": inputs(),
        "binaries": binaries, "sources": sources,
        "source_trees": {v: source_digest(path) for v, path in dirs.items()},
        "go": run(["go", "version"]).strip(),
        "go_env": json.loads(run(["go", "env", "-json", "GOOS", "GOARCH", "GOAMD64", "GOARM64", "GOEXPERIMENT"])),
        "platform": platform.platform(), "machine": platform.machine(),
        "GOMAXPROCS": ENV["GOMAXPROCS"], "build_flags": ["-trimpath", "-pgo=off", "-buildvcs=false"],
    }


def prepare(source):
    if source is None:
        source = BUILD / "upstream"
        if not source.exists():
            run(["git", "clone", "--filter=blob:none", "--no-checkout", "https://github.com/cloudflare/circl.git", source])
    require(run(["git", "rev-parse", UPSTREAM + "^{commit}"], cwd=source).strip() == UPSTREAM, "upstream commit unavailable")
    identity = hashlib.sha256(json.dumps(inputs(), sort_keys=True).encode()).hexdigest()[:16]
    snapshot = BUILD / identity
    require(not snapshot.exists(), f"snapshot already exists: {snapshot}; use its check/bench commands")
    for variant in ["baseline", "candidate"]:
        dest = snapshot / variant; dest.mkdir(parents=True)
        proc = subprocess.Popen(["git", "archive", UPSTREAM], cwd=source, stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
            for member in archive:
                target = (dest / member.name).resolve()
                require(dest.resolve() in target.parents or target == dest.resolve(), "unsafe archive path")
                require(member.isfile() or member.isdir(), "unexpected archive entry type")
                archive.extract(member, dest)
        require(proc.wait() == 0, "git archive failed")
        require(digest(dest / "sign/slhdsa/state.go") == UPSTREAM_STATE, "archived source differs from pinned upstream")
        for patch in (["production.patch"] if variant == "candidate" else []) + ["tests.patch"]:
            run(["git", "apply", "--check", HERE / patch], cwd=dest, env=patch_env(dest))
            run(["git", "apply", HERE / patch], cwd=dest, env=patch_env(dest))
            run(["git", "apply", "--reverse", "--check", HERE / patch], cwd=dest, env=patch_env(dest))
        require((dest / "sign/slhdsa/state_prefix_test.go").is_file(), "test patch was not applied")
        require((digest(dest / "sign/slhdsa/state.go") != UPSTREAM_STATE) == (variant == "candidate"), "production patch application failed")
        target = dest / "cmd/prefixbench"; target.mkdir(parents=True)
        (target / "main.go").write_bytes((HERE / "main.go").read_bytes())
        listed = run(["go", "test", "./sign/slhdsa", "-list", "^TestSHA2Prefix"], cwd=dest).splitlines()
        require(FOCUSED_TESTS <= set(listed), "prepared snapshot is missing expected test names")
        run(["go", "build", "-trimpath", "-pgo=off", "-buildvcs=false", "-o", dest / "prefixbench", "./cmd/prefixbench"], cwd=dest)
    provenance({v: snapshot / v for v in ["baseline", "candidate"]})
    (BUILD / "prepared.json").write_text(json.dumps({"snapshot": identity, "inputs": inputs(), "upstream": UPSTREAM}, indent=2) + "\n")
    print(json.dumps({"prepared": str(snapshot), "upstream": UPSTREAM}))


def correctness():
    dirs = layout(); before = provenance(dirs)
    results = {}
    print("Checking baseline failure and candidate pass of the resource regression", file=sys.stderr)
    focused = {
        "baseline_expected_failures": focused_test(dirs["baseline"], ["-run", "^TestSHA2PrefixReuse$"], BUILD / "resource-red.log", False),
        "candidate_passes": focused_test(dirs["candidate"], ["-race", "-run", "^TestSHA2Prefix"], BUILD / "race-tests.log", True),
    }
    suite = ROOT / "common/validation/validation.json.gz"
    for variant, path in dirs.items():
        print(f"Checking {variant} against all shared SLH-DSA vectors", file=sys.stderr)
        results[variant] = json.loads(run([path / "prefixbench", "-mode", "check", "-suite", suite]))
    print("Running the upstream candidate suite", file=sys.stderr)
    run(["go", "test", "-p=2", "./...", "-count=1"], cwd=dirs["candidate"], log=BUILD / "upstream-tests.log")
    run(["go", "vet", "./sign/slhdsa"], cwd=dirs["candidate"], log=BUILD / "vet.log")
    fixture_path = BUILD / "gate-fixture.json"
    fixture_path.write_text(run([dirs["baseline"] / "prefixbench", "-mode", "fixture", "-fork", "0"]))
    varied = {}
    for variant, path in dirs.items():
        varied[variant] = json.loads(run([path / "prefixbench", "-mode", "check-fixture", "-fixture", fixture_path]))
    require(provenance(dirs) == before, "sources or runtime changed during correctness checks")
    gate = {"provenance": before, "vectors": results, "varied": varied, "focused": focused, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "logs": {name: digest(BUILD / name) for name in ["resource-red.log", "upstream-tests.log", "race-tests.log", "vet.log"]}}
    (BUILD / "gate.json").write_text(json.dumps(gate, indent=2) + "\n")
    print(json.dumps(gate, indent=2))


def benchmark(args):
    require(5 <= args.forks <= 30 and 1 <= args.rounds <= 15, "require 5..30 forks and 1..15 rounds")
    require(0 <= args.start < 1000000 and math.isfinite(args.budget_ms) and args.budget_ms > 0, "invalid seed or budget")
    out = args.out.resolve(); require(not out.exists(), "existing evidence must not be overwritten")
    dirs = layout(); before = provenance(dirs)
    gate = json.loads((BUILD / "gate.json").read_text())
    require(gate["provenance"] == before, "no passing correctness gate for these exact sources and runtime")
    for name, expected in gate["logs"].items():
        require(digest(BUILD / name) == expected, "correctness log changed")
    rows = []; fixture_hashes = {}
    began = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for fork in range(args.start, args.start + args.forks):
        print(f"Preparing varied corpus for paired fork {fork}", file=sys.stderr)
        corpus = BUILD / f"fixture-{fork}.json"
        corpus.write_text(run([dirs["baseline"] / "prefixbench", "-mode", "fixture", "-fork", str(fork)]))
        fixture_hashes[str(fork)] = digest(corpus)
        # Both variants must pass complete-operation and ownership checks before timing this corpus.
        for path in dirs.values():
            run([path / "prefixbench", "-mode", "check-fixture", "-fixture", corpus])
        for param in PARAMS:
            for op in OPS:
                for round_number in range(args.rounds):
                    order = ["baseline", "candidate"] if (fork + round_number) % 2 == 0 else ["candidate", "baseline"]
                    pair = {}
                    for variant in order:
                        pair[variant] = json.loads(run([dirs[variant] / "prefixbench", "-mode", "bench", "-fixture", corpus, "-param", param, "-op", op, "-budget", f"{args.budget_ms}ms", "-warmup", "25ms"]))
                        result = pair[variant]
                        require(result["param"] == param and result["op"] == op, "wrong operation")
                        require(result["iterations"] >= 3 and result["iterations"] % 3 == 0, "incomplete corpus cycle")
                        require(math.isfinite(result["ns_per_op"]) and result["ns_per_op"] > 0, "invalid timing")
                    rows.append({"fork": fork, "round": round_number, "param": param, "op": op, "order": order, **pair,
                                 "speedup": pair["baseline"]["ns_per_op"] / pair["candidate"]["ns_per_op"]})
                print(f"Fork {fork}: {param} {op} complete", file=sys.stderr)
        require(digest(corpus) == fixture_hashes[str(fork)], "corpus changed during timing")
        require(provenance(dirs) == before, "sources or runtime changed during timing")
    summary = []
    for param in PARAMS:
        for op in OPS:
            forks = []
            for fork in range(args.start, args.start + args.forks):
                samples = [x for x in rows if x["param"] == param and x["op"] == op and x["fork"] == fork]
                require(len(samples) == args.rounds, "partial result matrix")
                forks.append({"fork": fork, "speedup": statistics.median(x["speedup"] for x in samples),
                              "baseline_ns": statistics.median(x["baseline"]["ns_per_op"] for x in samples),
                              "candidate_ns": statistics.median(x["candidate"]["ns_per_op"] for x in samples)})
            ratios = [x["speedup"] for x in forks]
            summary.append({"param": param, "op": op, "speedup": statistics.median(ratios), "fork_min": min(ratios), "fork_max": max(ratios), "forks": forks})
    report = {"schema": "circl-sha2-prefix-v1", "started_at": began, "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "statistic": "median of within-fork median paired ratios; fork min/max are descriptive ranges, not confidence intervals",
              "provenance": before, "correctness": gate, "corpora": fixture_hashes, "summary": summary, "rows": rows}
    atomic_new(out, report)
    print(f"Saved {out}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    prep = sub.add_parser("prepare"); prep.add_argument("--source", type=Path)
    sub.add_parser("check")
    bench = sub.add_parser("bench")
    bench.add_argument("--out", type=Path, required=True)
    bench.add_argument("--forks", type=int, default=5)
    bench.add_argument("--rounds", type=int, default=3)
    bench.add_argument("--start", type=int, default=10)
    bench.add_argument("--budget-ms", type=float, default=100)
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    lock = BUILD / ".lock"
    lock.mkdir()  # Exclusive across setup, checks, and timing.
    try:
        if args.mode == "prepare": prepare(args.source)
        elif args.mode == "check": correctness()
        else: benchmark(args)
    finally:
        lock.rmdir()


if __name__ == "__main__":
    main()
