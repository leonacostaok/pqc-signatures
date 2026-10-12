package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"runtime"
	"runtime/metrics"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	"github.com/cloudflare/circl/sign/slhdsa"
)

type encoded struct {
	Group                                                            string
	Index                                                            int
	Seed, Message, Context, Entropy, PublicKey, SecretKey, Signature string
}
type fixture struct {
	Parameter string
	Rows      []encoded
}
type caseData struct {
	index                       int
	seed, msg, ctx, pk, sk, sig []byte
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func check(ok bool, s string) {
	if !ok {
		panic(s)
	}
}
func unhex(s string) []byte { x, e := hex.DecodeString(s); must(e); return x }
func decode(r encoded) caseData {
	return caseData{r.Index, unhex(r.Seed), unhex(r.Message), unhex(r.Context), unhex(r.PublicKey), unhex(r.SecretKey), unhex(r.Signature)}
}

type adapter struct {
	scheme sign.Scheme
	slh    bool
	id     slhdsa.ID
}

func newAdapter(param string) adapter {
	a := adapter{scheme: schemes.ByName(param), slh: strings.HasPrefix(param, "SLH-")}
	check(a.scheme != nil, "unknown parameter")
	if a.slh {
		var err error
		a.id, err = slhdsa.IDByName(param)
		must(err)
	}
	return a
}

type prepared struct {
	call     func()
	validate func() [][]byte
}

func (a adapter) prepare(c caseData, op string) prepared {
	seed, msg, ctx, pkb, skb, sigb := bytes.Clone(c.seed), bytes.Clone(c.msg), bytes.Clone(c.ctx), bytes.Clone(c.pk), bytes.Clone(c.sk), bytes.Clone(c.sig)
	var pk sign.PublicKey
	var sk sign.PrivateKey
	var sig []byte
	var valid bool
	var err error
	opts := &sign.SignatureOpts{Context: string(ctx)}
	reader := bytes.NewReader(seed)
	if op == "sign" {
		sk, err = a.scheme.UnmarshalBinaryPrivateKey(skb)
		must(err)
	}
	if op == "verify" {
		pk, err = a.scheme.UnmarshalBinaryPublicKey(pkb)
		must(err)
	}
	var slhMsg *slhdsa.Message
	if a.slh && op != "keygen" {
		slhMsg = slhdsa.NewMessage(msg)
	}
	call := func() {
		switch op {
		case "keygen":
			if a.slh {
				p, s, e := slhdsa.GenerateKey(reader, a.id)
				pk, sk, err = p, s, e
			} else {
				pk, sk = a.scheme.DeriveKey(seed)
			}
		case "sign":
			if a.slh {
				s := sk.(slhdsa.PrivateKey)
				sig, err = slhdsa.SignDeterministic(&s, slhMsg, ctx)
			} else {
				sig = a.scheme.Sign(sk, msg, opts)
			}
		case "verify":
			if a.slh {
				p := pk.(slhdsa.PublicKey)
				valid = slhdsa.Verify(&p, slhMsg, sigb, ctx)
			} else {
				valid = a.scheme.Verify(pk, msg, sigb, opts)
			}
		}
	}
	validate := func() [][]byte {
		must(err)
		var out [][]byte
		switch op {
		case "keygen":
			p, e := pk.MarshalBinary()
			must(e)
			s, e := sk.MarshalBinary()
			must(e)
			check(bytes.Equal(p, c.pk) && bytes.Equal(s, c.sk), "key mismatch")
			if a.slh {
				check(reader.Len() == 0, "seed consumption")
			}
			out = [][]byte{p, s}
		case "sign":
			check(bytes.Equal(sig, c.sig), "signature mismatch")
			s, e := sk.MarshalBinary()
			must(e)
			check(bytes.Equal(s, c.sk), "secret key changed")
			out = [][]byte{sig}
		case "verify":
			check(valid, "signature rejected")
			p, e := pk.MarshalBinary()
			must(e)
			check(bytes.Equal(p, c.pk), "public key changed")
			out = [][]byte{{1}}
		}
		for _, pair := range [][2][]byte{{seed, c.seed}, {msg, c.msg}, {ctx, c.ctx}, {pkb, c.pk}, {skb, c.sk}, {sigb, c.sig}} {
			check(bytes.Equal(pair[0], pair[1]), "caller input changed")
		}
		return out
	}
	return prepared{call, validate}
}

type memory struct {
	HeapAlloc   uint64  `json:"heap_alloc_bytes"`
	HeapInuse   uint64  `json:"heap_inuse_bytes"`
	HeapObjects uint64  `json:"heap_objects"`
	StackInuse  uint64  `json:"runtime_reserved_stack_bytes"`
	TotalAlloc  uint64  `json:"total_allocated_bytes"`
	Mallocs     uint64  `json:"allocated_objects"`
	NumGC       uint32  `json:"gc_cycles"`
	PauseTotal  uint64  `json:"gc_pause_total_ns"`
	GCCPU       float64 `json:"gc_cpu_seconds"`
	HeapLive    uint64  `json:"last_gc_live_heap_bytes"`
}

func snapshot() memory {
	var s runtime.MemStats
	runtime.ReadMemStats(&s)
	samples := []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/gc/heap/live:bytes"}}
	metrics.Read(samples)
	return memory{s.HeapAlloc, s.HeapInuse, s.HeapObjects, s.StackInuse, s.TotalAlloc, s.Mallocs, s.NumGC, s.PauseTotalNs, samples[0].Value.Float64(), samples[1].Value.Uint64()}
}
func usage() syscall.Rusage {
	var r syscall.Rusage
	must(syscall.Getrusage(syscall.RUSAGE_SELF, &r))
	return r
}
func cpu(r syscall.Rusage) int64 { return r.Utime.Nano() + r.Stime.Nano() }
func calls(param, op string) int {
	slow := strings.HasSuffix(param, "s")
	if op == "sign" {
		if slow {
			return 3
		}
		if strings.Contains(param, "128") {
			return 60
		}
		if strings.Contains(param, "192") {
			return 36
		}
		return 18
	}
	if op == "keygen" {
		if slow {
			return 24
		}
		if strings.Contains(param, "128") {
			return 1536
		}
		if strings.Contains(param, "192") {
			return 768
		}
		return 384
	}
	if slow {
		return 3072
	}
	return 1536
}
func main() {
	path := flag.String("fixture", "", "corpus")
	param := flag.String("param", "", "parameter")
	mode := flag.String("mode", "check", "check, latency, resource")
	op := flag.String("op", "", "operation")
	setting := flag.String("settings", "default", "setting")
	flag.Parse()
	check(flag.NArg() == 0, "unexpected args")
	check(*mode == "check" || *mode == "latency" || *mode == "resource", "unknown mode")
	check(*setting == "default" || *setting == "constrained", "unknown setting")
	check(*op == "" || *op == "keygen" || *op == "sign" || *op == "verify", "unknown operation")
	raw, e := os.ReadFile(*path)
	must(e)
	var f fixture
	must(json.Unmarshal(raw, &f))
	check(f.Parameter == *param, "fixture parameter")
	a := newAdapter(*param)
	warm, measured := []caseData{}, []caseData{}
	for _, r := range f.Rows {
		if r.Group == "warmup" {
			warm = append(warm, decode(r))
		} else if r.Group == "measured" {
			measured = append(measured, decode(r))
		} else {
			panic("unknown corpus group")
		}
	}
	check(len(warm) == 2 && len(measured) == 3, "corpus size")
	ops := []string{"keygen", "sign", "verify"}
	if *op != "" {
		ops = []string{*op}
	}
	results := []any{}
	for _, operation := range ops {
		for _, c := range warm {
			p := a.prepare(c, operation)
			p.call()
			p.validate()
		}
		count := 3
		if *mode == "resource" {
			count = calls(*param, operation)
		}
		var before, after, max memory
		samples := []any{}
		api := make([]int64, 0, count)
		digest := sha256.New()
		if *mode == "resource" {
			before = snapshot()
			max = before
		}
		u0 := usage()
		start := time.Now()
		for i := 0; i < count; i++ {
			p := a.prepare(measured[i%3], operation)
			t := time.Now()
			p.call()
			api = append(api, time.Since(t).Nanoseconds())
			if *mode == "resource" {
				s := snapshot()
				if s.HeapAlloc > max.HeapAlloc {
					max.HeapAlloc = s.HeapAlloc
				}
				if s.HeapInuse > max.HeapInuse {
					max.HeapInuse = s.HeapInuse
				}
				if s.StackInuse > max.StackInuse {
					max.StackInuse = s.StackInuse
				}
				if s.HeapObjects > max.HeapObjects {
					max.HeapObjects = s.HeapObjects
				}
				if i%128 == 0 {
					samples = append(samples, map[string]any{"index": i, "memory": s})
				}
			}
			for _, b := range p.validate() {
				_, _ = digest.Write(b)
			}
		}
		elapsed := time.Since(start).Nanoseconds()
		u1 := usage()
		if *mode == "resource" {
			after = snapshot()
			if after.HeapAlloc > max.HeapAlloc {
				max.HeapAlloc = after.HeapAlloc
			}
			if after.HeapInuse > max.HeapInuse {
				max.HeapInuse = after.HeapInuse
			}
			if after.HeapObjects > max.HeapObjects {
				max.HeapObjects = after.HeapObjects
			}
			if after.StackInuse > max.StackInuse {
				max.StackInuse = after.StackInuse
			}
		}
		rss := u1.Maxrss
		if runtime.GOOS != "darwin" {
			rss *= 1024
		}
		results = append(results, map[string]any{"operation": operation, "count": count, "warmup_calls": 2, "api_ns": api, "checked_workload_ns": elapsed, "checked_workload_cpu_ns": cpu(u1) - cpu(u0), "output_sha256": hex.EncodeToString(digest.Sum(nil)), "memory": map[string]any{"initial": before, "end": after, "sampled_max": map[string]uint64{"heap_alloc_bytes": max.HeapAlloc, "heap_inuse_bytes": max.HeapInuse, "heap_objects": max.HeapObjects, "runtime_reserved_stack_bytes": max.StackInuse}, "samples": samples}, "process_maxrss_bytes": rss, "scope": "API clocks exclude fresh caller copying/key import/checks; resource interval includes them and sampling; sampled reserved stack is not consumed stack"})
	}
	for _, c := range measured {
		bad := bytes.Clone(c.sig)
		bad[len(bad)/2] ^= 1
		pk, e := a.scheme.UnmarshalBinaryPublicKey(bytes.Clone(c.pk))
		must(e)
		check(!a.scheme.Verify(pk, bytes.Clone(c.msg), bad, &sign.SignatureOpts{Context: string(c.ctx)}), "tamper accepted")
	}
	out := map[string]any{"schema": "circl-resource-followup-v1", "parameter": *param, "mode": *mode, "settings": *setting, "go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "environment": map[string]string{"GOGC": os.Getenv("GOGC"), "GOMEMLIMIT": os.Getenv("GOMEMLIMIT"), "GOMAXPROCS": os.Getenv("GOMAXPROCS")}, "checks": map[string]any{"exact_outputs": true, "inputs_preserved": true, "tamper_rejections": 3}, "rows": results}
	must(json.NewEncoder(os.Stdout).Encode(out))
}
