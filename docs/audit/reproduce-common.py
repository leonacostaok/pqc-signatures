"""Reproduce audit findings using disposable fixtures; never changes real results."""
import json
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = pathlib.Path(__file__).resolve().parent / "evidence"
EVIDENCE.mkdir(exist_ok=True)

with tempfile.TemporaryDirectory(prefix="common-fixture-", dir=EVIDENCE) as tmp:
    fixture = pathlib.Path(tmp)
    (fixture / "common").mkdir()
    (fixture / "results").mkdir()
    for name in ["check-match.mjs", "reference.json", "vectors.json", "run-final.sh"]:
        shutil.copy2(ROOT / "common" / name, fixture / "common" / name)

    def check():
        p = subprocess.run(["node", str(fixture / "common/check-match.mjs")], capture_output=True, text=True)
        return {"exit": p.returncode, "last_line": p.stdout.strip().splitlines()[-1]}

    out = {"empty_results": check()}
    (fixture / "results/noble").mkdir()
    (fixture / "results/noble/memory.jsonl").write_text('{"match":false}\n')
    (fixture / "results/noble/validation.json").write_text(json.dumps({"results": [{"id": "invented", "variant": "verify.v0"}], "summary": {}}))
    out["bad_memory_and_malformed_validation"] = check()

    shutil.rmtree(fixture / "results")
    shutil.copytree(ROOT / "results", fixture / "results")
    out["committed_snapshot"] = check()
    match = json.loads((fixture / "results/match.json").read_text())
    out["committed_snapshot"].update({
        "byte_match_libraries": list(match["byte_match"]),
        "stage_pairs": len(match["stages"]["cross_lib"]),
        "stage_disagreements": [k for k, v in match["stages"]["cross_lib"].items() if not v["agree"]],
        "validation_rows": sum(v["cases"] for v in match["validation"].values()),
        "crossverify_failures": {k: v["failures"] for k, v in match["crossverify"].items() if v["failures"]},
    })

    shutil.rmtree(fixture / "results")
    (fixture / "results").mkdir()
    (fixture / "libs/failing").mkdir(parents=True)
    driver = fixture / "libs/failing/run.sh"
    driver.write_text('#!/usr/bin/env bash\nexit 23\n')
    driver.chmod(0o755)
    for name in ["report.mjs", "report-phase2.mjs"]:
        (fixture / "common" / name).write_text('console.log("mock report ran");\n')
    p = subprocess.run(["bash", str(fixture / "common/run-final.sh"), "--libs", "failing"], capture_output=True, text=True)
    out["all_steps_fail"] = {"exit": p.returncode, "log": p.stdout.splitlines(), "stderr": p.stderr}
    (EVIDENCE / "checker-reproduction.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))
