#!/usr/bin/env python3
"""Independently recompute the complete CIRCL SHA-2 prefix experiment."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


def audit(path, corpora):
    data = json.loads(path.read_text())
    params = {f"SLH-DSA-SHA2-{bits}{size}" for bits in (128, 192, 256) for size in ("f", "s")}
    params.add("SLH-DSA-SHAKE-128f")
    ops = {"keygen", "sign", "verify"}
    forks = {int(fork) for fork in data["corpora"]}
    assert len(forks) == 5
    assert data["correctness"]["provenance"] == data["provenance"]
    assert len(set(data["provenance"]["sources"].values())) == 2
    assert len(set(data["provenance"]["binaries"].values())) == 2
    for fork, expected in data["corpora"].items():
        raw = (corpora / f"fixture-{fork}.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        cases = json.loads(raw)
        assert len(cases) == 21
        assert {case["Param"] for case in cases} == params
        assert all(sum(case["Param"] == param for case in cases) == 3 for param in params)
    groups, seen = {}, set()
    for row in data["rows"]:
        key = (row["fork"], row["round"], row["param"], row["op"])
        assert key not in seen
        seen.add(key)
        assert row["order"] in (["baseline", "candidate"], ["candidate", "baseline"])
        for variant in ("baseline", "candidate"):
            result = row[variant]
            assert result["param"] == row["param"] and result["op"] == row["op"]
            assert result["iterations"] >= 3 and result["iterations"] % 3 == 0
            assert math.isfinite(result["ns_per_op"]) and result["ns_per_op"] > 0
        assert row["speedup"] == row["baseline"]["ns_per_op"] / row["candidate"]["ns_per_op"]
        groups.setdefault((row["param"], row["op"], row["fork"]), []).append(row)
    assert seen == {(fork, round_number, param, op) for fork in forks for round_number in range(4)
                    for param in params for op in ops}
    checked, summaries = set(), []
    for summary in data["summary"]:
        key = (summary["param"], summary["op"])
        assert key not in checked
        checked.add(key)
        assert {entry["fork"] for entry in summary["forks"]} == forks
        assert len(summary["forks"]) == 5
        ratios = []
        for entry in summary["forks"]:
            rows = groups[(*key, entry["fork"])]
            assert len(rows) == 4
            assert sum(row["order"] == ["baseline", "candidate"] for row in rows) == 2
            ratio = statistics.median(row["speedup"] for row in rows)
            assert entry["speedup"] == ratio
            assert entry["baseline_ns"] == statistics.median(row["baseline"]["ns_per_op"] for row in rows)
            assert entry["candidate_ns"] == statistics.median(row["candidate"]["ns_per_op"] for row in rows)
            ratios.append(ratio)
        assert summary["speedup"] == statistics.median(ratios)
        assert summary["fork_min"] == min(ratios) and summary["fork_max"] == max(ratios)
        summaries.append({"param": key[0], "operation": key[1], "speedup": summary["speedup"],
                          "minimum_fork_speedup": min(ratios)})
    assert checked == {(param, op) for param in params for op in ops}
    return {"schema": "circl-sha2-prefix-independent-check-v1", "report": path.name,
            "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "pairs_checked": len(seen),
            "corpora_checked": len(forks), "balanced_order": True, "summaries": summaries}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: audit-prefix.py REPORT.json CORPORA_DIRECTORY")
    print(json.dumps(audit(Path(sys.argv[1]), Path(sys.argv[2])), indent=2))
