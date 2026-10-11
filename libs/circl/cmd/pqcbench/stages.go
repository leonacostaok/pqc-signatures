package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"pqcbench/vendorcircl/slhdsa"
)

// stageRun is one stage variant bound to prepared inputs.
type stageRun struct {
	run     func() bool   // executes the stage once (timed)
	out     func() []byte // canonical output after run (untimed); nil for total/total_best
	threads int
}

// stageImpl is implemented per family (mlStages44/65/87, slhStages).
type stageImpl interface {
	prepare(pk, msg, ctx, sig []byte) bool
	stage(name, mode string) (stageRun, bool)
	verifyPipeline(best bool, pk, msg, ctx, sig []byte) bool
	stageNames() []string
}

func newStageImpl(a *alg) stageImpl {
	switch a.name {
	case "ML-DSA-44":
		return newMLStages44()
	case "ML-DSA-65":
		return newMLStages65()
	case "ML-DSA-87":
		return newMLStages87()
	}
	id, err := slhdsa.IDByName(a.name)
	if err != nil {
		panic(err)
	}
	return newSLHStages(id)
}

type stageVariant struct {
	family string // ml-dsa | slh-dsa
	stage  string
	id     string
	name   string
	desc   string
	flavor string
	mode   string
}

const (
	dPurego = "Built with -tags purego (no assembly), v0 code path."
	dV3     = "Built with GOAMD64=v3 (compiler may use AVX2/BMI2), v0 code path."
	dPGO    = "Built with -pgo=default.pgo (profile-guided optimisation), v0 code path."
)

var stageVariants = []stageVariant{
	// ---- ML-DSA decode
	{"ml-dsa", "decode", "decode.v0", "circl", "pkDecode (rho, UnpackT1) + sigDecode (c~, z with ||z|| bound, strict hint encoding) with CIRCL's unpack routines.", "default", "circl"},
	{"ml-dsa", "decode", "decode.v1", "cached-pk", "Only sigDecode; the pkDecode result is cached per public key (as circl's PublicKey object does).", "default", "cachedpk"},
	{"ml-dsa", "decode", "decode.v2", "fused-z", "pkDecode + sigDecode where the ||z||inf < gamma1-beta check is fused into the z bit-unpacking loop (single pass, early exit) instead of a second pass.", "default", "fused"},
	{"ml-dsa", "decode", "decode.v3", "amd64v3", dV3, "amd64v3", "circl"},
	{"ml-dsa", "decode", "decode.v4", "pgo", dPGO, "pgo", "circl"},
	// ---- ML-DSA mu
	{"ml-dsa", "mu", "mu.v0", "circl", "tr = SHAKE256(pk, 64); mu = SHAKE256(tr || 0 || len(ctx) || ctx || M, 64) with CIRCL's internal sha3.", "default", "circl"},
	{"ml-dsa", "mu", "mu.v1", "cached-tr", "tr cached per public key (circl PublicKey caches it); only mu is hashed.", "default", "cachedtr"},
	{"ml-dsa", "mu", "mu.v2", "stdlib-sha3", "tr and mu with the Go standard library crypto/sha3 SHAKE256 (amd64 assembly Keccak) instead of CIRCL's pure-Go Keccak.", "default", "stdsha3"},
	{"ml-dsa", "mu", "mu.v3", "midstate", "SHAKE256 state with tr || 0 || len(ctx) || ctx pre-absorbed per (pk, ctx); per message the state is cloned and only M is absorbed.", "default", "midstate"},
	{"ml-dsa", "mu", "mu.v4", "amd64v3", dV3, "amd64v3", "circl"},
	{"ml-dsa", "mu", "mu.v5", "pgo", dPGO, "pgo", "circl"},
	// ---- ML-DSA expandA
	{"ml-dsa", "expandA", "expandA.v0", "circl-x4", "CIRCL Mat.Derive: 4 SHAKE128 streams at a time with the AVX2 4-way Keccak-f1600 (runtime detected).", "default", "circl"},
	{"ml-dsa", "expandA", "expandA.v1", "scalar-1way", "Same binary, one SHAKE128 stream at a time (CIRCL's non-x4 fallback forced): isolates the 4-way Keccak gain.", "default", "scalar"},
	{"ml-dsa", "expandA", "expandA.v2", "purego", "Built with -tags purego: scalar Keccak only, no 4-way permutation.", "purego", "circl"},
	{"ml-dsa", "expandA", "expandA.v3", "parallel-rows", "K rows derived concurrently on goroutines (one per row), each row using the x4 sampler.", "default", "parrows"},
	{"ml-dsa", "expandA", "expandA.v4", "cached-A", "A^ cached per public key (what circl's PublicKey.Unpack stores); the stage degenerates to reusing the cached matrix.", "default", "cachedA"},
	{"ml-dsa", "expandA", "expandA.v5", "amd64v3", dV3, "amd64v3", "circl"},
	// ---- ML-DSA w_approx
	{"ml-dsa", "w_approx", "w_approx.v0", "circl", "NTT(z), A^ o NTT(z) (PolyDotHat), NTT(t1*2^d), SampleInBall(c~), NTT(c), MulHat, Sub, InvNTT, normalise: CIRCL's Verify body (AVX2 NTT).", "default", "circl"},
	{"ml-dsa", "w_approx", "w_approx.v1", "purego", "Built with -tags purego: generic Go NTT/MulHat/InvNTT.", "purego", "circl"},
	{"ml-dsa", "w_approx", "w_approx.v2", "cached-t1hat", "NTT(t1*2^d) precomputed per public key; saves K forward NTTs per verification.", "default", "cachedT1"},
	{"ml-dsa", "w_approx", "w_approx.v3", "parallel-rows", "The K independent rows (dot product, c*t1 term, subtraction, InvNTT) on goroutines; NTT(z) and NTT(c) computed once.", "default", "parrows"},
	{"ml-dsa", "w_approx", "w_approx.v4", "amd64v3", dV3, "amd64v3", "circl"},
	{"ml-dsa", "w_approx", "w_approx.v5", "pgo", dPGO, "pgo", "circl"},
	// ---- ML-DSA hint_check
	{"ml-dsa", "hint_check", "hint_check.v0", "circl", "||z|| check, VecK.UseHint (vector Decompose + hint correction), PackW1, SHAKE256(mu || w1Encode) and compare, CIRCL's code.", "default", "circl"},
	{"ml-dsa", "hint_check", "hint_check.v1", "fused-usehint-pack", "UseHint evaluated per coefficient with the scalar decompose and packed straight into the w1Encode buffer (no intermediate decomposed/w1 vectors).", "default", "fused"},
	{"ml-dsa", "hint_check", "hint_check.v2", "stdlib-sha3", "The challenge hash c~' with the standard library crypto/sha3 (assembly Keccak).", "default", "stdsha3"},
	{"ml-dsa", "hint_check", "hint_check.v3", "amd64v3", dV3, "amd64v3", "circl"},
	{"ml-dsa", "hint_check", "hint_check.v4", "pgo", dPGO, "pgo", "circl"},
	// ---- SLH-DSA hmsg
	{"slh-dsa", "hmsg", "hmsg.v0", "circl", "Full signature parse (R, FORS pairs, hypertree layers) + H_msg (SHA-256/MGF1 or SHAKE256) + md/idx_tree/idx_leaf split, CIRCL's code.", "default", "circl"},
	{"slh-dsa", "hmsg", "hmsg.v1", "purego", "Built with -tags purego: no stdlib SHA-256 assembly (SHA2 sets); SHAKE sets unaffected (CIRCL's Keccak is pure Go).", "purego", "circl"},
	{"slh-dsa", "hmsg", "hmsg.v2", "lazy-parse", "Only length-check the signature and slice R; the FORS/hypertree structure parse (allocations) is deferred to the stages that need it.", "default", "lazy"},
	{"slh-dsa", "hmsg", "hmsg.v3", "stdlib-sha3", "SHAKE sets only: H_msg with the standard library crypto/sha3 SHAKE256 (assembly) instead of CIRCL's internal sha3.", "default", "althash"},
	{"slh-dsa", "hmsg", "hmsg.v4", "amd64v3", dV3, "amd64v3", "circl"},
	{"slh-dsa", "hmsg", "hmsg.v5", "pgo", dPGO, "pgo", "circl"},
	// ---- SLH-DSA fors
	{"slh-dsa", "fors", "fors.v0", "circl", "fors_pkFromSig: k leaf hashes (F), k*a path hashes (H), one T over the roots, CIRCL's hasher state.", "default", "circl"},
	{"slh-dsa", "fors", "fors.v1", "purego", dPurego, "purego", "circl"},
	{"slh-dsa", "fors", "fors.v2", "parallel-trees", "The k independent FORS tree roots on min(k, GOMAXPROCS) goroutines with separate hasher states; T over the roots sequential.", "default", "parallel"},
	{"slh-dsa", "fors", "fors.v3", "alt-hash", "SHA2 sets: SHA-256/512 midstate with PK.seed||pad pre-compressed (one compression less per F/H/T call). SHAKE sets: stdlib crypto/sha3 backend for F/H/T.", "default", "althash"},
	{"slh-dsa", "fors", "fors.v4", "amd64v3", dV3, "amd64v3", "circl"},
	{"slh-dsa", "fors", "fors.v5", "pgo", dPGO, "pgo", "circl"},
	// ---- SLH-DSA ht_wots
	{"slh-dsa", "ht_wots", "ht_wots.v0", "circl", "d WOTS+ pkFromSig computations (len chains of F, one T each), CIRCL's code, sequential.", "default", "circl"},
	{"slh-dsa", "ht_wots", "ht_wots.v1", "purego", dPurego, "purego", "circl"},
	{"slh-dsa", "ht_wots", "ht_wots.v2", "parallel-layers", "The d layers (independent given their input messages) on min(d, GOMAXPROCS) goroutines with separate hasher states.", "default", "parallel"},
	{"slh-dsa", "ht_wots", "ht_wots.v3", "alt-hash", "SHA2 sets: SHA-2 midstate for F and T. SHAKE sets: stdlib crypto/sha3 backend.", "default", "althash"},
	{"slh-dsa", "ht_wots", "ht_wots.v4", "amd64v3", dV3, "amd64v3", "circl"},
	{"slh-dsa", "ht_wots", "ht_wots.v5", "pgo", dPGO, "pgo", "circl"},
	// ---- SLH-DSA ht_auth
	{"slh-dsa", "ht_auth", "ht_auth.v0", "circl", "d XMSS auth-path root computations (h' H calls each) + compare with PK.root, CIRCL's code, sequential.", "default", "circl"},
	{"slh-dsa", "ht_auth", "ht_auth.v1", "purego", dPurego, "purego", "circl"},
	{"slh-dsa", "ht_auth", "ht_auth.v2", "parallel-layers", "The d layers (independent given their WOTS+ pk) on min(d, GOMAXPROCS) goroutines with separate hasher states.", "default", "parallel"},
	{"slh-dsa", "ht_auth", "ht_auth.v3", "alt-hash", "SHA2 sets: SHA-2 midstate for H. SHAKE sets: stdlib crypto/sha3 backend.", "default", "althash"},
	{"slh-dsa", "ht_auth", "ht_auth.v4", "amd64v3", dV3, "amd64v3", "circl"},
	{"slh-dsa", "ht_auth", "ht_auth.v5", "pgo", dPGO, "pgo", "circl"},
}

const (
	mlBestDesc  = "End-to-end verify from the fastest correct alternatives: cached pkDecode/tr/A^/NTT(t1*2^d) per key, mu midstate per (key, ctx), fused z decode (decode.v2), fused UseHint+pack (hint_check.v1)."
	slhBestDesc = "End-to-end verify from the fastest correct alternatives: lazy parse (hmsg.v2); SHA2 sets add the SHA-2 midstate hashers (fors/ht_wots/ht_auth v3); SHAKE sets keep CIRCL hashers (v0: the stdlib SHA-3 backend brought no gain); sequential layers."
)

type stageLine struct {
	Lib          string  `json:"lib"`
	LibVersion   string  `json:"lib_version"`
	Lang         string  `json:"lang"`
	Runtime      string  `json:"runtime"`
	Family       string  `json:"family"`
	Stage        string  `json:"stage"`
	Variant      string  `json:"variant"`
	VariantName  string  `json:"variant_name"`
	VariantDesc  string  `json:"variant_desc"`
	Param        string  `json:"param"`
	Iterations   int     `json:"iterations"`
	WallNsMedian int64   `json:"wall_ns_median"`
	WallNsMean   int64   `json:"wall_ns_mean"`
	WallNsP95    int64   `json:"wall_ns_p95"`
	WallNsMin    int64   `json:"wall_ns_min"`
	CPUNsPerOp   int64   `json:"cpu_ns_per_op"`
	CPUUtil      float64 `json:"cpu_util"`
	OpsPerSec    float64 `json:"ops_per_sec"`
	Threads      int     `json:"threads"`
	OutputSha256 string  `json:"output_sha256"`
	Match        bool    `json:"match"`
}

// prepareStages builds the stage implementation on the reference inputs.
func prepareStages(a *alg, c *common) stageImpl {
	st := getSetup(a, c)
	impl := newStageImpl(a)
	if !impl.prepare(st.pk, c.msg, nil, st.sig) {
		fatalf("%s: stage pipeline does not verify the reference signature", a.name)
	}
	return impl
}

// stageOutput runs a stage variant once (untimed) and returns (ok, canonical digest).
func stageOutput(r stageRun) (bool, string) {
	ok := r.run()
	if r.out == nil {
		if ok {
			return ok, "true"
		}
		return ok, "false"
	}
	return ok, sha256hex(r.out())
}

func cmdStages(args []string) {
	fs := flag.NewFlagSet("stages", flag.ExitOnError)
	commonDir := fs.String("common", "common", "directory with vectors.json/reference.json")
	out := fs.String("out", "", "output .jsonl (appended)")
	budgetMs := fs.Int("budget-ms", 1000, "time budget per (variant, param)")
	params := fs.String("params", "", "comma-separated params")
	stagesF := fs.String("stages", "", "comma-separated stage names (total, total_best included by default)")
	variants := fs.String("variants", "", "comma-separated variant ids")
	fs.Parse(args)
	c := loadCommon(*commonDir)
	w := openOut(*out)
	defer w.Close()
	pset, sset, vset := splitList(*params), splitList(*stagesF), splitList(*variants)
	budget := time.Duration(*budgetMs) * time.Millisecond

	for _, a := range algs {
		if pset != nil && !pset[a.name] || c.seed(a.name) == nil {
			continue
		}
		impl := prepareStages(a, c)
		family := a.family
		// v0 reference digests per stage (computed in every binary from its own v0)
		ref := map[string]string{}
		for _, s := range impl.stageNames() {
			r, _ := impl.stage(s, "circl")
			ok, d := stageOutput(r)
			if !ok {
				fatalf("%s %s.v0 returned false on the reference", a.name, s)
			}
			ref[s] = d
		}
		emit := func(stage, id, name, desc, mode string) {
			r, ok := impl.stage(stage, mode)
			if !ok {
				return
			}
			st := measure(func() { r.run() }, func() {}, 1, budget)
			ok2, d := stageOutput(r)
			match := ok2
			if r.out != nil {
				match = match && d == ref[stage]
			}
			line := stageLine{
				Lib: libName, LibVersion: libVersion(), Lang: "go", Runtime: runtimeString(), Family: family,
				Stage: stage, Variant: id, VariantName: name, VariantDesc: desc, Param: a.name,
				Iterations: st.iterations, WallNsMedian: st.median, WallNsMean: st.mean, WallNsP95: st.p95,
				WallNsMin: st.min, CPUNsPerOp: st.cpuPerOp, CPUUtil: st.cpuUtil, OpsPerSec: st.opsPerSec,
				Threads: r.threads, OutputSha256: d, Match: match,
			}
			b, _ := json.Marshal(line)
			fmt.Fprintln(w, string(b))
			fmt.Fprintf(os.Stderr, "[%s] %-16s %-20s median=%10.2fus cpu/op=%10.2fus thr=%d match=%v\n",
				flavor, id, a.name, float64(st.median)/1e3, float64(st.cpuPerOp)/1e3, r.threads, match)
		}
		for _, v := range stageVariants {
			if v.family != family || v.flavor != flavor || (sset != nil && !sset[v.stage]) || (vset != nil && !vset[v.id]) {
				continue
			}
			emit(v.stage, v.id, v.name, v.desc, v.mode)
		}
		if flavor == "default" && (sset == nil || sset["total"]) && (vset == nil || vset["total"]) {
			emit("total", "total", "v0-pipeline", "End-to-end verify from the v0 stages (pkDecode+sigDecode, tr/mu, ExpandA, w_approx, hint check); same work as circl UnmarshalBinary + Verify.", "")
		}
		if flavor == "default" && (sset == nil || sset["total_best"]) && (vset == nil || vset["total_best"]) {
			desc := mlBestDesc
			if family == "slh-dsa" {
				desc = slhBestDesc
			}
			emit("total_best", "total_best", "best-pipeline", desc, "")
		}
	}
}

func openOut(path string) *os.File {
	if path == "" || path == "-" {
		return os.Stdout
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fatalf("open %s: %v", path, err)
	}
	return f
}
