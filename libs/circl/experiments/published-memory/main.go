// Audit heap allocation counters around complete public operations; no latency measurements.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"runtime"

	"github.com/cloudflare/circl/sign/slhdsa"
)

type input struct {
	Index                  int `json:"index"`
	Seed, Message, Context string
}
type cases struct{ Warmup, Measured []input }
type corpus struct {
	ID         string           `json:"id"`
	Parameters map[string]cases `json:"parameters"`
}
type allocation struct {
	Bytes             uint64 `json:"allocated_bytes"`
	Objects           uint64 `json:"allocated_objects"`
	HeapBytesChange   int64  `json:"heap_alloc_change"`
	HeapObjectsChange int64  `json:"heap_objects_change"`
	Collections       uint32 `json:"collections_during_call"`
}
type row struct {
	Index      int                   `json:"index"`
	Seed       string                `json:"seed"`
	PK         string                `json:"public_key"`
	SK         string                `json:"secret_key"`
	Signature  string                `json:"signature"`
	Valid      bool                  `json:"valid"`
	Tamper     bool                  `json:"tamper_rejected"`
	Preserved  bool                  `json:"inputs_preserved"`
	Allocation map[string]allocation `json:"allocation"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func check(ok bool, msg string) {
	if !ok {
		panic(msg)
	}
}
func decode(s string) []byte { out, err := hex.DecodeString(s); must(err); return out }
func measure(enabled bool, fn func()) allocation {
	if !enabled {
		fn()
		return allocation{}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return allocation{after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs,
		int64(after.HeapAlloc) - int64(before.HeapAlloc), int64(after.HeapObjects) - int64(before.HeapObjects), after.NumGC - before.NumGC}
}
func one(id slhdsa.ID, c input, measured bool) row {
	seed := decode(c.Seed)
	savedSeed := bytes.Clone(seed)
	reader := bytes.NewReader(seed)
	var pub slhdsa.PublicKey
	var priv slhdsa.PrivateKey
	var err error
	kg := measure(measured, func() { pub, priv, err = slhdsa.GenerateKey(reader, id) })
	must(err)
	check(reader.Len() == 0, "keygen did not consume the complete seed")
	check(bytes.Equal(seed, savedSeed), "keygen mutated seed")
	pk, err := pub.MarshalBinary()
	must(err)
	sk, err := priv.MarshalBinary()
	must(err)
	msg, ctx := decode(c.Message), decode(c.Context)
	signSK, signMsg, signCtx := bytes.Clone(sk), bytes.Clone(msg), bytes.Clone(ctx)
	signKey := slhdsa.PrivateKey{ID: id}
	must(signKey.UnmarshalBinary(signSK))
	signMessage := slhdsa.NewMessage(signMsg)
	var sig []byte
	sg := measure(measured, func() { sig, err = slhdsa.SignDeterministic(&signKey, signMessage, signCtx) })
	must(err)
	afterSK, err := signKey.MarshalBinary()
	must(err)
	check(bytes.Equal(afterSK, sk) && bytes.Equal(signSK, sk) && bytes.Equal(signMsg, msg) && bytes.Equal(signCtx, ctx), "sign mutated input")
	verifyPK, verifyMsg, verifyCtx, verifySig := bytes.Clone(pk), bytes.Clone(msg), bytes.Clone(ctx), bytes.Clone(sig)
	verifyKey := slhdsa.PublicKey{ID: id}
	must(verifyKey.UnmarshalBinary(verifyPK))
	verifyMessage := slhdsa.NewMessage(verifyMsg)
	valid := false
	vr := measure(measured, func() { valid = slhdsa.Verify(&verifyKey, verifyMessage, verifySig, verifyCtx) })
	check(valid, "valid signature rejected")
	afterPK, err := verifyKey.MarshalBinary()
	must(err)
	check(bytes.Equal(afterPK, pk) && bytes.Equal(verifyPK, pk) && bytes.Equal(verifyMsg, msg) && bytes.Equal(verifyCtx, ctx) && bytes.Equal(verifySig, sig), "verify mutated input")
	bad := bytes.Clone(sig)
	bad[len(bad)/2] ^= 1
	badKey := slhdsa.PublicKey{ID: id}
	must(badKey.UnmarshalBinary(bytes.Clone(pk)))
	check(!slhdsa.Verify(&badKey, slhdsa.NewMessage(bytes.Clone(msg)), bad, bytes.Clone(ctx)), "tampered signature accepted")
	return row{c.Index, c.Seed, hex.EncodeToString(pk), hex.EncodeToString(sk), hex.EncodeToString(sig), true, true, true, map[string]allocation{"keygen": kg, "sign": sg, "verify": vr}}
}
func main() {
	path := flag.String("corpus", "", "input corpus")
	param := flag.String("param", "", "parameter set")
	warmup := flag.Int("warmup-cycles", 1, "disjoint warmup cycles")
	flag.Parse()
	check(flag.NArg() == 0 && *warmup > 0, "invalid arguments")
	raw, err := os.ReadFile(*path)
	must(err)
	var data corpus
	must(json.Unmarshal(raw, &data))
	c, ok := data.Parameters[*param]
	check(ok && len(c.Measured) == 10 && len(c.Warmup) == 4, "require exactly ten measured and four warmup keys")
	seeds := map[string]bool{}
	for _, group := range [][]input{c.Warmup, c.Measured} {
		for _, v := range group {
			check(!seeds[v.Seed], "duplicate or overlapping seed")
			seeds[v.Seed] = true
		}
	}
	id, err := slhdsa.IDByName(*param)
	must(err)
	for cycle := 0; cycle < *warmup; cycle++ {
		for _, v := range c.Warmup[:1] {
			one(id, v, false)
		}
	}
	rows := make([]row, 0, 3)
	for _, v := range c.Measured[:3] {
		rows = append(rows, one(id, v, true))
	}
	output := map[string]any{"schema": "circl-published-allocation-v1", "param": *param, "corpus_id": data.ID, "runtime": runtime.Version(), "arch": runtime.GOARCH, "measured_calls": map[string]int{"keygen": 3, "sign": 3, "verify": 3}, "warmup_keys": 1, "warmup_cycles": *warmup, "allocation_scope": "public API only; fresh caller copies and key decoding outside counters; GC before each call; no cross-call cryptographic cache", "metric": "runtime.MemStats TotalAlloc/Mallocs deltas; heap deltas are not peak memory", "rows": rows}
	must(json.NewEncoder(os.Stdout).Encode(output))
}
