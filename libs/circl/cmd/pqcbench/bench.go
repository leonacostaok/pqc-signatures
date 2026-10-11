package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// mode selects the code path inside one binary; flavor selects the binary.
type mode int

const (
	modeBaseline    mode = iota // documented API, packed key unpacked on every call
	modePreunpacked             // key unpacked once, output buffer reused
	modeGCOff                   // baseline path with GOGC=off + 1 GiB memory limit
	modeParallel                // worker pool (one op per worker per batch), pre-unpacked keys
)

type variant struct {
	id     string // "<op>.vN"
	op     string
	name   string
	desc   string
	flavor string // which binary runs it
	mode   mode
}

var variantTable = []variant{
	// ---- keygen
	{"keygen.v0", "keygen", "baseline", "Default build; mldsa.NewKeyFromSeed + Pack / slhdsa.GenerateKey(seed reader) + MarshalBinary.", "default", modeBaseline},
	{"keygen.v1", "keygen", "purego", "Built with -tags purego: no assembly (generic NTT, scalar Keccak instead of AVX2 Keccak-x4).", "purego", modeBaseline},
	{"keygen.v2", "keygen", "amd64v3", "Built with GOAMD64=v3 so the Go compiler may emit AVX2/BMI2/FMA for generic Go code.", "amd64v3", modeBaseline},
	{"keygen.v3", "keygen", "pgo", "Profile-guided optimization: -pgo=default.pgo from a CPU profile of this workload.", "pgo", modeBaseline},
	{"keygen.v4", "keygen", "gc-off", "Runtime tuning: GC disabled (GOGC=off) with a 1 GiB soft memory limit during the loop.", "default", modeGCOff},
	{"keygen.v5", "keygen", "parallel", "Batch keygen on a goroutine worker pool (GOMAXPROCS workers); throughput over the batch.", "default", modeParallel},
	// ---- sign
	{"sign.v0", "sign", "baseline", "Default build; sk bytes unpacked per call (UnmarshalBinary), SignTo/SignDeterministic into a fresh buffer.", "default", modeBaseline},
	{"sign.v1", "sign", "preunpacked", "Private key unpacked once (ExpandA + NTTs cached in circl PrivateKey) and reused; signature buffer reused.", "default", modePreunpacked},
	{"sign.v2", "sign", "purego", "Built with -tags purego: no assembly (generic NTT, scalar Keccak instead of AVX2 Keccak-x4).", "purego", modeBaseline},
	{"sign.v3", "sign", "amd64v3", "Built with GOAMD64=v3 so the Go compiler may emit AVX2/BMI2/FMA for generic Go code.", "amd64v3", modeBaseline},
	{"sign.v4", "sign", "pgo", "Profile-guided optimization: -pgo=default.pgo from a CPU profile of this workload.", "pgo", modeBaseline},
	{"sign.v5", "sign", "parallel", "Batch signing on a goroutine worker pool (GOMAXPROCS workers, each with its own pre-unpacked key).", "default", modeParallel},
	// ---- verify
	{"verify.v0", "verify", "baseline", "Default build; pk bytes unpacked per call (UnmarshalBinary), then Verify.", "default", modeBaseline},
	{"verify.v1", "verify", "preunpacked", "Public key unpacked once (ExpandA + tr cached in circl PublicKey) and reused across verifications.", "default", modePreunpacked},
	{"verify.v2", "verify", "purego", "Built with -tags purego: no assembly (generic NTT, scalar Keccak instead of AVX2 Keccak-x4).", "purego", modeBaseline},
	{"verify.v3", "verify", "amd64v3", "Built with GOAMD64=v3 so the Go compiler may emit AVX2/BMI2/FMA for generic Go code.", "amd64v3", modeBaseline},
	{"verify.v4", "verify", "pgo", "Profile-guided optimization: -pgo=default.pgo from a CPU profile of this workload.", "pgo", modeBaseline},
	{"verify.v5", "verify", "parallel", "Batch verification on a goroutine worker pool (GOMAXPROCS workers, each with its own pre-unpacked key).", "default", modeParallel},
}

// runner executes `batch` ops per call and returns the outputs of the first op
// (out2 is only used by keygen: pk, sk). Outputs of the other ops in a batch are
// compared against the first inside run(); any difference sets `bad`.
type runner struct {
	batch   int
	threads int
	run     func() (out1, out2 []byte)
	cleanup func()
	bad     bool
	tamper  bool // verify only: tampered signature was rejected at setup
}

// singleOp builds the per-call closure for one op in a given mode.
func singleOp(a *alg, c *common, op string, m mode, seed, pk, sk, sig []byte) func() ([]byte, []byte) {
	switch op {
	case "keygen":
		return func() ([]byte, []byte) { return a.keygen(seed) }
	case "sign":
		if m == modePreunpacked || m == modeParallel {
			s := a.newSigner(sk)
			buf := make([]byte, a.sigSize)
			return func() ([]byte, []byte) { return s(c.msg, buf), nil }
		}
		return func() ([]byte, []byte) { return a.newSigner(sk)(c.msg, make([]byte, a.sigSize)), nil }
	case "verify":
		if m == modePreunpacked || m == modeParallel {
			v := a.newVerifier(pk)
			return func() ([]byte, []byte) { return boolBytes(v(c.msg, sig)), nil }
		}
		return func() ([]byte, []byte) { return boolBytes(a.newVerifier(pk)(c.msg, sig)), nil }
	}
	panic("bad op " + op)
}

var bTrue, bFalse = []byte{1}, []byte{0}

func boolBytes(b bool) []byte {
	if b {
		return bTrue
	}
	return bFalse
}

// setup holds the untimed inputs of one parameter set (computed once per process:
// SLH-DSA "s" signing takes seconds, so this must not be repeated per variant).
type setup struct {
	seed, pk, sk, sig []byte
	tamperRejected    bool
}

var setups = map[string]*setup{}

func getSetup(a *alg, c *common) *setup {
	if s, ok := setups[a.name]; ok {
		return s
	}
	s := &setup{seed: c.seed(a.name)}
	s.pk, s.sk = a.keygen(s.seed)
	s.sig = a.newSigner(s.sk)(c.msg, make([]byte, a.sigSize))
	// tamper check (untimed): flip one bit of the signature, must be rejected
	t := append([]byte(nil), s.sig...)
	t[len(t)/2] ^= 0x01
	s.tamperRejected = !a.newVerifier(s.pk)(c.msg, t)
	setups[a.name] = s
	return s
}

func newRunner(a *alg, c *common, v *variant) *runner {
	st := getSetup(a, c)
	seed, pk, sk, sig := st.seed, st.pk, st.sk, st.sig
	r := &runner{batch: 1, threads: 1, cleanup: func() {}, tamper: st.tamperRejected}

	switch v.mode {
	case modeBaseline, modePreunpacked:
		r.run = singleOp(a, c, v.op, v.mode, seed, pk, sk, sig)
	case modeGCOff:
		op := singleOp(a, c, v.op, modeBaseline, seed, pk, sk, sig)
		runtime.GC()
		oldPct := debug.SetGCPercent(-1)
		oldLim := debug.SetMemoryLimit(1 << 30)
		r.run = op
		r.cleanup = func() {
			debug.SetGCPercent(oldPct)
			debug.SetMemoryLimit(oldLim)
			runtime.GC()
		}
	case modeParallel:
		w := runtime.GOMAXPROCS(0)
		r.threads, r.batch = w, w
		ops := make([]func() ([]byte, []byte), w)
		for i := range ops {
			ops[i] = singleOp(a, c, v.op, modeParallel, seed, pk, sk, sig)
		}
		out1 := make([][]byte, w)
		out2 := make([][]byte, w)
		start := make([]chan struct{}, w)
		var wg sync.WaitGroup
		quit := make(chan struct{})
		for i := 0; i < w; i++ {
			start[i] = make(chan struct{}, 1)
			go func(i int) {
				for {
					select {
					case <-start[i]:
						out1[i], out2[i] = ops[i]()
						wg.Done()
					case <-quit:
						return
					}
				}
			}(i)
		}
		r.run = func() ([]byte, []byte) {
			wg.Add(w)
			for i := 0; i < w; i++ {
				start[i] <- struct{}{}
			}
			wg.Wait()
			for i := 1; i < w; i++ {
				if !bytes.Equal(out1[i], out1[0]) || !bytes.Equal(out2[i], out2[0]) {
					r.bad = true
				}
			}
			return out1[0], out2[0]
		}
		r.cleanup = func() { close(quit) }
	}
	return r
}

type benchLine struct {
	Lib          string  `json:"lib"`
	LibVersion   string  `json:"lib_version"`
	Lang         string  `json:"lang"`
	Runtime      string  `json:"runtime"`
	Variant      string  `json:"variant"`
	VariantName  string  `json:"variant_name"`
	VariantDesc  string  `json:"variant_desc"`
	Op           string  `json:"op"`
	Param        string  `json:"param"`
	Iterations   int     `json:"iterations"`
	Threads      int     `json:"threads"`
	WallNsMedian int64   `json:"wall_ns_median"`
	WallNsMean   int64   `json:"wall_ns_mean"`
	WallNsP95    int64   `json:"wall_ns_p95"`
	WallNsMin    int64   `json:"wall_ns_min"`
	CPUNsPerOp   int64   `json:"cpu_ns_per_op"`
	CPUUtil      float64 `json:"cpu_util"`
	OpsPerSec    float64 `json:"ops_per_sec"`
	OutputSha256 string  `json:"output_sha256"`
	Match        bool    `json:"match"`
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

const maxCalls = 100000

func benchOne(a *alg, c *common, v *variant, budget time.Duration) benchLine {
	r := newRunner(a, c, v)
	defer r.cleanup()

	// warm-up: at least one op, up to ~100 ms or 10 calls (Go has no JIT)
	first1, first2 := r.run()
	for t0, n := time.Now(), 1; n < 10 && time.Since(t0) < 100*time.Millisecond; n++ {
		r.run()
	}

	samples := make([]float64, 0, 1024)
	cpu0 := cpuTime()
	loopStart := time.Now()
	calls := 0
	for {
		t0 := time.Now()
		o1, o2 := r.run()
		d := time.Since(t0)
		if !bytes.Equal(o1, first1) || !bytes.Equal(o2, first2) {
			r.bad = true
		}
		samples = append(samples, float64(d.Nanoseconds())/float64(r.batch))
		calls++
		minCalls := 3
		if d > 5*time.Second {
			minCalls = 2
		}
		if (time.Since(loopStart) >= budget && calls >= minCalls) || calls >= maxCalls {
			break
		}
	}
	wallTotal := time.Since(loopStart)
	cpuTotal := cpuTime() - cpu0
	ops := calls * r.batch

	sort.Float64s(samples)
	sum := 0.0
	for _, s := range samples {
		sum += s
	}
	pct := func(p float64) int64 {
		i := int(math.Round(p * float64(len(samples)-1)))
		return int64(samples[i])
	}

	// correctness against the shared reference
	ref, hasRef := c.ref[a.name]
	match := hasRef && !r.bad
	outHash := ""
	switch v.op {
	case "keygen":
		outHash = sha256hex(first1)
		match = match && outHash == ref.PkSha256 && sha256hex(first2) == ref.SkSha256
	case "sign":
		outHash = sha256hex(first1)
		match = match && outHash == ref.SigSha256
	case "verify":
		ok := bytes.Equal(first1, bTrue) && r.tamper
		match = match && ok
		outHash = "false"
		if ok {
			outHash = "true"
		}
	}

	return benchLine{
		Lib: libName, LibVersion: libVersion(), Lang: "go", Runtime: runtimeString(),
		Variant: v.id, VariantName: v.name, VariantDesc: v.desc, Op: v.op, Param: a.name,
		Iterations: ops, Threads: r.threads,
		WallNsMedian: pct(0.5), WallNsMean: int64(sum / float64(len(samples))),
		WallNsP95: pct(0.95), WallNsMin: int64(samples[0]),
		CPUNsPerOp: cpuTotal.Nanoseconds() / int64(ops),
		CPUUtil:    float64(cpuTotal) / float64(wallTotal),
		OpsPerSec:  float64(ops) / wallTotal.Seconds(),
		OutputSha256: outHash, Match: match,
	}
}

func splitList(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			m[x] = true
		}
	}
	return m
}

func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	commonDir := fs.String("common", "common", "directory with vectors.json/reference.json")
	out := fs.String("out", "", "output .jsonl (appended)")
	budgetMs := fs.Int("budget-ms", 1000, "time budget per (variant, param)")
	params := fs.String("params", "", "comma-separated params")
	ops := fs.String("ops", "", "comma-separated ops")
	variants := fs.String("variants", "", "comma-separated variant ids")
	allFlavors := fs.Bool("all-flavors", false, "run variants of every flavor in this binary (debug)")
	fs.Parse(args)
	c := loadCommon(*commonDir)

	w := os.Stdout
	if *out != "" && *out != "-" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fatalf("open %s: %v", *out, err)
		}
		defer f.Close()
		w = f
	}
	pset, oset, vset := splitList(*params), splitList(*ops), splitList(*variants)
	budget := time.Duration(*budgetMs) * time.Millisecond

	mismatches := 0
	for i := range variantTable {
		v := &variantTable[i]
		if (!*allFlavors && v.flavor != flavor) || (oset != nil && !oset[v.op]) || (vset != nil && !vset[v.id]) {
			continue
		}
		for _, a := range algs {
			if pset != nil && !pset[a.name] {
				continue
			}
			if c.seed(a.name) == nil {
				continue
			}
			line := benchOne(a, c, v, budget)
			b, _ := json.Marshal(line)
			fmt.Fprintln(w, string(b))
			if !line.Match {
				mismatches++
			}
			fmt.Fprintf(os.Stderr, "[%s] %-10s %-20s median=%9.1fus cpu/op=%9.1fus util=%.2f ops/s=%10.1f match=%v\n",
				flavor, v.id, a.name, float64(line.WallNsMedian)/1e3, float64(line.CPUNsPerOp)/1e3, line.CPUUtil, line.OpsPerSec, line.Match)
		}
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "pqcbench: WARNING %d bench results did not match the reference\n", mismatches)
	}
}

// cmdProfile runs the baseline path of every op/param under the CPU profiler
// to produce a default.pgo for the PGO build.
func cmdProfile(args []string) {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	commonDir := fs.String("common", "common", "directory with vectors.json/reference.json")
	out := fs.String("out", "", "output profile")
	ms := fs.Int("ms", 150, "milliseconds per (op, param)")
	fs.Parse(args)
	c := loadCommon(*commonDir)

	f, err := os.Create(*out)
	if err != nil {
		fatalf("create %s: %v", *out, err)
	}
	defer f.Close()
	if err := pprof.StartCPUProfile(f); err != nil {
		fatalf("profile: %v", err)
	}
	defer pprof.StopCPUProfile()
	for _, a := range algs {
		if c.seed(a.name) == nil {
			continue
		}
		for _, op := range []string{"keygen", "sign", "verify"} {
			for _, m := range []mode{modeBaseline, modePreunpacked} {
				if op == "keygen" && m == modePreunpacked {
					continue
				}
				v := &variant{id: "profile", op: op, mode: m, flavor: flavor}
				r := newRunner(a, c, v)
				for t0 := time.Now(); time.Since(t0) < time.Duration(*ms)*time.Millisecond; {
					r.run()
				}
				r.cleanup()
			}
		}
	}
}
