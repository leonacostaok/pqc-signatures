#!/usr/bin/env python3
"""JSON <-> flat-text glue for the liboqs C driver (used by run.sh)."""
import json
import sys

OQS_NAMES = {
    "ML-DSA-44": "ML-DSA-44", "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87",
    "Falcon-512": "Falcon-512", "Falcon-1024": "Falcon-1024",
}


def oqs_name(p):
    if p in OQS_NAMES:
        return OQS_NAMES[p]
    if p.startswith("SLH-DSA-"):
        # SLH-DSA-SHA2-128s -> SLH_DSA_PURE_SHA2_128S
        _, _, h, s = p.split("-")
        return f"SLH_DSA_PURE_{h}_{s.upper()}"
    raise SystemExit(f"unknown param {p}")


def spec(vectors, reference, out):
    v = json.load(open(vectors))
    r = json.load(open(reference))
    with open(out, "w") as f:
        f.write(f"msg {v['message_hex']}\n")
        for p in v["params"]:
            ref = r.get(p["name"])
            f.write("param %s %s %s %s %s %s\n" % (
                p["name"], oqs_name(p["name"]), p["seed_hex"],
                ref["pk_sha256"] if ref else "-", ref["sk_sha256"] if ref else "-",
                ref["sig_sha256"] if ref else "-"))


def vectors_json(lib_version, lines_file, out):
    entries = []
    for line in open(lines_file):
        t = line.split()
        if not t:
            continue
        name, pkhex, sighex, sksha, pksha, sigsha, ok, match = t
        e = {"param": name, "pk_hex": pkhex, "sig_hex": sighex, "sk_sha256": sksha,
             "pk_sha256": pksha, "sig_sha256": sigsha, "self_verify": ok == "1"}
        if match != "-1":
            e["reference_match"] = match == "1"
        entries.append(e)
    json.dump({"lib": "liboqs", "lib_version": lib_version, "entries": entries}, open(out, "w"), indent=1)
    bad = [e["param"] for e in entries if not e["self_verify"] or e.get("reference_match") is False]
    print(f"vectors: {len(entries)} params, mismatches: {bad if bad else 'none'}")
    return 1 if bad else 0


def entries_flat(artifacts, out):
    a = json.load(open(artifacts))
    with open(out, "w") as f:
        for e in a["entries"]:
            f.write(f"{e['param']} {e['pk_hex']} {e['sig_hex']}\n")
    return a.get("lib", "?")


def crossverify_json(source, lines_file, out):
    results = []
    for line in open(lines_file):
        t = line.split()
        if not t:
            continue
        name, ok, tamper, err = t[0], t[1], t[2], " ".join(t[3:])
        results.append({"param": name, "ok": ok == "1", "error": None if err == "-" else err,
                        "tamper_rejected": tamper == "1"})
    json.dump({"lib": "liboqs", "source": source, "results": results}, open(out, "w"), indent=1)
    bad = [r["param"] for r in results if not r["ok"] or not r["tamper_rejected"]]
    print(f"crossverify({source}): {len(results)} params, failures: {bad if bad else 'none'}")
    return 1 if bad else 0


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "spec":
        spec(*sys.argv[2:5])
    elif cmd == "vectors-json":
        sys.exit(vectors_json(*sys.argv[2:5]))
    elif cmd == "entries-flat":
        print(entries_flat(*sys.argv[2:4]))
    elif cmd == "crossverify-json":
        sys.exit(crossverify_json(*sys.argv[2:5]))
    else:
        raise SystemExit("usage: glue.py spec|vectors-json|entries-flat|crossverify-json ...")
