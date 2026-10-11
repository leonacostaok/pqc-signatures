package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------- stack painting
//
// Go goroutine stacks are growable (copied on overflow). To measure the peak
// stack of one operation we run it on a dedicated goroutine whose stack was
// pre-grown by a deep recursion (so the op never triggers a copy), paint the
// now-free region below the measuring frame with 0xA5 through unsafe, run the
// op, and scan for the lowest address that was overwritten. GC is disabled
// (no stack shrinking) and run.sh sets GODEBUG=asyncpreemptoff=1 so no
// asyncPreempt frame is pushed onto the painted region.

const paintByte = 0xA5

// growStack recurses `n` levels with a 1 KiB frame and returns the address of
// a local in the deepest frame (computed after the final stack growth, so it
// is valid for the final stack).
//
//go:noinline
func growStack(n int) uintptr {
	var pad [1024]byte
	pad[n&1023] = byte(n)
	if n > 0 {
		lo := growStack(n - 1)
		runtime.KeepAlive(&pad)
		return lo
	}
	runtime.KeepAlive(&pad)
	return uintptr(unsafe.Pointer(&pad[0]))
}

// spNow returns an address inside the frame of this (tiny) function, i.e. just
// below the caller's stack pointer.
//
//go:noinline
func spNow() uintptr {
	var x [16]byte
	x[0] = 1
	runtime.KeepAlive(&x)
	return uintptr(unsafe.Pointer(&x[0]))
}

type stackResult struct {
	used  int
	moved bool // the stack was copied during the op: measurement invalid
}

// measureStack runs op on a fresh goroutine with a ~4 MiB pre-grown stack.
func measureStack(op func()) stackResult {
	ch := make(chan stackResult, 1)
	go func() {
		lo := growStack(4000)
		hi := spNow()
		region := unsafe.Slice((*byte)(unsafe.Pointer(lo)), hi-lo)
		for i := range region {
			region[i] = paintByte
		}
		op()
		moved := spNow() != hi
		low := len(region)
		for i := range region {
			if region[i] != paintByte {
				low = i
				break
			}
		}
		ch <- stackResult{used: len(region) - low, moved: moved}
	}()
	return <-ch
}

// ---------------------------------------------------------------- heap

type heapResult struct {
	allocPerOp int64 // TotalAlloc delta / n
	peak       int64 // HeapAlloc growth over one op with GC off (upper bound of peak live heap)
}

func measureHeap(op func(), n int) heapResult {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	op()
	runtime.ReadMemStats(&m1)
	peak := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	runtime.ReadMemStats(&m0)
	for i := 0; i < n; i++ {
		op()
	}
	runtime.ReadMemStats(&m1)
	return heapResult{allocPerOp: int64(m1.TotalAlloc-m0.TotalAlloc) / int64(n), peak: peak}
}

type memLine struct {
	Lib             string `json:"lib"`
	Variant         string `json:"variant"`
	Op              string `json:"op"`
	Stage           string `json:"stage,omitempty"`
	Param           string `json:"param"`
	StackBytes      *int64 `json:"stack_bytes"`
	StackMethod     string `json:"stack_method"`
	StackResolution int64  `json:"stack_resolution_bytes"`
	HeapAllocPerOp  *int64 `json:"heap_alloc_bytes_per_op"`
	HeapPeak        *int64 `json:"heap_peak_bytes"`
	HeapMethod      string `json:"heap_method"`
	Threads         int    `json:"threads"`
	Match           bool   `json:"match"`
}

const (
	stackMethod = "pre-grown goroutine stack (~4 MiB) painted with 0xA5 via unsafe below the measuring frame, GC off, asyncpreempt off; high-water mark = lowest overwritten byte; harness call overhead (empty op) subtracted"
	heapMethod  = "runtime.ReadMemStats: TotalAlloc delta / n ops (GC off); heap_peak_bytes = HeapAlloc growth over one op with GC off (upper bound of peak live heap)"
)

func cmdMemory(args []string) {
	fs := flag.NewFlagSet("memory", flag.ExitOnError)
	commonDir := fs.String("common", "common", "directory with vectors.json/reference.json")
	out := fs.String("out", "", "output .jsonl (appended)")
	params := fs.String("params", "", "comma-separated params")
	heapOps := fs.Int("heap-ops", 5, "ops for the heap allocation average")
	fs.Parse(args)
	c := loadCommon(*commonDir)
	w := openOut(*out)
	defer w.Close()
	pset := splitList(*params)

	debug.SetGCPercent(-1)
	defer debug.SetGCPercent(100)

	// harness overhead: the measuring goroutine's own frames for an empty op
	base := measureStack(func() {}).used
	fmt.Fprintf(os.Stderr, "[%s] memory: empty-op stack baseline %d bytes\n", flavor, base)

	emit := func(l memLine, op func(), ok func() bool) {
		var sr stackResult
		// take the minimum of three runs (preemption or runtime noise can only add)
		for i := 0; i < 3; i++ {
			r := measureStack(op)
			if i == 0 || (!r.moved && r.used < sr.used) {
				sr = r
			}
		}
		if !sr.moved {
			v := int64(sr.used - base)
			l.StackBytes = &v
		}
		l.StackMethod = stackMethod
		l.StackResolution = 8
		n := *heapOps
		if l.Op == "sign" && l.Param[len(l.Param)-1] == 's' && a0(l.Param) { // SLH-DSA "s": seconds per op
			n = 1
		}
		h := measureHeap(op, n)
		l.HeapAllocPerOp, l.HeapPeak = &h.allocPerOp, &h.peak
		l.HeapMethod = heapMethod
		l.Match = ok()
		runtime.GC()
		b, _ := json.Marshal(l)
		fmt.Fprintln(w, string(b))
		fmt.Fprintf(os.Stderr, "[%s] %-14s %-20s stack=%v heap/op=%d peak=%d match=%v\n", flavor, l.Variant, l.Param, derefOr(l.StackBytes), h.allocPerOp, h.peak, l.Match)
	}

	for _, a := range algs {
		if pset != nil && !pset[a.name] || c.seed(a.name) == nil {
			continue
		}
		st := getSetup(a, c)
		ref := c.ref[a.name]
		for i := range variantTable {
			v := &variantTable[i]
			if v.flavor != flavor {
				continue
			}
			m := v.mode
			threads := 1
			if m == modeParallel { // per-worker stack: the worker's own op closure
				threads = runtime.GOMAXPROCS(0)
			}
			if m == modeGCOff {
				m = modeBaseline // GC is off for the whole memory run anyway
			}
			op := singleOp(a, st.inputs(c), v.op, m)
			var o1, o2 []byte
			emit(memLine{Lib: libName, Variant: v.id, Op: v.op, Param: a.name, Threads: threads},
				func() { o1, o2 = op() },
				func() bool {
					o1, o2 = op()
					switch v.op {
					case "keygen":
						return sha256hex(o1) == ref.PkSha256 && sha256hex(o2) == ref.SkSha256
					case "sign":
						return sha256hex(o1) == ref.SigSha256
					default:
						return bytes.Equal(o1, bTrue) && st.tamperRejected
					}
				})
		}
		if flavor != "default" {
			continue
		}
		impl := prepareStages(a, c)
		for _, s := range impl.stageNames() {
			r, _ := impl.stage(s, "circl")
			_, refDigest := stageOutput(r)
			emit(memLine{Lib: libName, Variant: s + ".v0", Op: "verify-stage", Stage: s, Param: a.name, Threads: 1},
				func() { r.run() },
				func() bool { ok, d := stageOutput(r); return ok && d == refDigest })
		}
		r, _ := impl.stage("total_best", "")
		emit(memLine{Lib: libName, Variant: "total_best", Op: "verify-stage", Stage: "total_best", Param: a.name, Threads: 1},
			func() { r.run() },
			func() bool {
				t := append([]byte(nil), st.sig...)
				t[len(t)/2] ^= 1
				return r.run() && !impl.verifyPipeline(true, st.pk, c.msg, nil, t)
			})
	}
	_ = time.Now
}

func a0(p string) bool { return len(p) > 7 && p[:7] == "SLH-DSA" }

func derefOr(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
