// Command prefixbench checks and measures the production SLH-DSA API.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
)

type vector struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Param   string `json:"param"`
	Seed    string `json:"seed_hex"`
	PK      string `json:"pk_hex"`
	SK      string `json:"sk_hex"`
	Msg     string `json:"msg_hex"`
	Ctx     string `json:"ctx_hex"`
	Sig     string `json:"sig_hex"`
	WantPK  string `json:"expect_pk_hex"`
	WantSK  string `json:"expect_sk_hex"`
	WantSig string `json:"expect_sig_hex"`
	Expect  *bool  `json:"expect"`
}

type fixture struct {
	Param                       string
	Seed, PK, SK, Msg, Ctx, Sig []byte
}

type loaded struct {
	fixture
	pub  slhdsa.PublicKey
	priv slhdsa.PrivateKey
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
func unhex(s string) []byte { v, err := hex.DecodeString(s); must(err); return v }
func emit(v any)            { must(json.NewEncoder(os.Stdout).Encode(v)) }

func load(c fixture) loaded {
	id, err := slhdsa.IDByName(c.Param)
	must(err)
	x := loaded{fixture: c, pub: slhdsa.PublicKey{ID: id}, priv: slhdsa.PrivateKey{ID: id}}
	must(x.pub.UnmarshalBinary(c.PK))
	must(x.priv.UnmarshalBinary(c.SK))
	return x
}

func keys(seed []byte, id slhdsa.ID) ([]byte, []byte) {
	pub, priv, err := slhdsa.GenerateKey(bytes.NewReader(seed), id)
	must(err)
	pk, err := pub.MarshalBinary()
	must(err)
	sk, err := priv.MarshalBinary()
	must(err)
	return pk, sk
}

func verify(pk, msg, ctx, sig []byte, id slhdsa.ID) bool {
	pub := slhdsa.PublicKey{ID: id}
	if err := pub.UnmarshalBinary(pk); err != nil {
		return false
	}
	return slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig, ctx)
}

func checkSuite(path string) {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	z, err := gzip.NewReader(f)
	must(err)
	defer z.Close()
	var suite struct {
		Cases []vector `json:"cases"`
	}
	must(json.NewDecoder(z).Decode(&suite))
	counts := map[string]int{}
	checked := 0
	for _, c := range suite.Cases {
		if !strings.HasPrefix(c.Param, "SLH-DSA-") {
			continue
		}
		id, err := slhdsa.IDByName(c.Param)
		must(err)
		switch c.Kind {
		case "keygen":
			pk, sk := keys(unhex(c.Seed), id)
			check(bytes.Equal(pk, unhex(c.WantPK)) && bytes.Equal(sk, unhex(c.WantSK)), c.ID+": keygen mismatch")
		case "siggen":
			priv := slhdsa.PrivateKey{ID: id}
			must(priv.UnmarshalBinary(unhex(c.SK)))
			sig, err := slhdsa.SignDeterministic(&priv, slhdsa.NewMessage(unhex(c.Msg)), unhex(c.Ctx))
			must(err)
			check(bytes.Equal(sig, unhex(c.WantSig)), c.ID+": signature mismatch")
		case "sigver":
			check(c.Expect != nil, c.ID+": missing expectation")
			check(verify(unhex(c.PK), unhex(c.Msg), unhex(c.Ctx), unhex(c.Sig), id) == *c.Expect, c.ID+": verify mismatch")
		default:
			panic("unsupported vector kind: " + c.Kind)
		}
		counts[c.Param+"/"+c.Kind]++
		checked++
	}
	check(checked == 432, fmt.Sprintf("partial suite: %d, want 432", checked))
	emit(map[string]any{"checked": checked, "counts": counts})
}

func derive(label string, n int) []byte {
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("circl-prefix-v1/%s/%d", label, i)))
		out = append(out, h[:]...)
	}
	return out[:n]
}

func makeFixture(fork int) {
	var cases []fixture
	for _, id := range []slhdsa.ID{slhdsa.SHA2_128f, slhdsa.SHA2_128s, slhdsa.SHA2_192f, slhdsa.SHA2_192s, slhdsa.SHA2_256f, slhdsa.SHA2_256s, slhdsa.SHAKE_128f} {
		for i := 0; i < 3; i++ {
			label := fmt.Sprintf("%d/%s/%d", fork, id, i)
			c := fixture{Param: id.String(), Seed: derive(label+"/seed", id.Scheme().SeedSize()), Msg: derive(label+"/msg", []int{0, 64, 4096}[i]), Ctx: derive(label+"/ctx", []int{0, 31, 255}[i])}
			c.PK, c.SK = keys(c.Seed, id)
			x := load(c)
			var err error
			c.Sig, err = slhdsa.SignDeterministic(&x.priv, slhdsa.NewMessage(c.Msg), c.Ctx)
			must(err)
			check(slhdsa.Verify(&x.pub, slhdsa.NewMessage(c.Msg), c.Sig, c.Ctx), "fixture verify failed")
			cases = append(cases, c)
		}
	}
	emit(cases)
}

func checkFixture(cases []fixture) {
	check(len(cases) == 21, "partial fixture")
	for _, c := range cases {
		x := load(c)
		owned := [][]byte{c.Seed, c.PK, c.SK, c.Msg, c.Ctx, c.Sig}
		saved := make([][]byte, len(owned))
		for i := range owned {
			saved[i] = bytes.Clone(owned[i])
		}
		pk, sk := keys(c.Seed, x.pub.ID)
		check(bytes.Equal(pk, c.PK) && bytes.Equal(sk, c.SK), "varied keygen mismatch")
		sig, err := slhdsa.SignDeterministic(&x.priv, slhdsa.NewMessage(c.Msg), c.Ctx)
		must(err)
		check(bytes.Equal(sig, c.Sig), "varied sign mismatch")
		check(slhdsa.Verify(&x.pub, slhdsa.NewMessage(c.Msg), c.Sig, c.Ctx), "varied verify mismatch")
		bad := bytes.Clone(c.Sig)
		bad[len(bad)/2] ^= 1
		for _, s := range [][]byte{bad, c.Sig[1:], append(bytes.Clone(c.Sig), 0)} {
			check(!slhdsa.Verify(&x.pub, slhdsa.NewMessage(c.Msg), s, c.Ctx), "accepted malformed signature")
		}
		check(!slhdsa.Verify(&x.pub, slhdsa.NewMessage(append(bytes.Clone(c.Msg), 1)), c.Sig, c.Ctx), "accepted different message")
		ctx := bytes.Clone(c.Ctx)
		if len(ctx) == 0 {
			ctx = []byte{1}
		} else {
			ctx[0] ^= 1
		}
		check(!slhdsa.Verify(&x.pub, slhdsa.NewMessage(c.Msg), c.Sig, ctx), "accepted different context")
		pk[0] ^= 1
		check(!verify(pk, c.Msg, c.Ctx, c.Sig, x.pub.ID), "accepted different public key")
		check(!verify(c.PK[1:], c.Msg, c.Ctx, c.Sig, x.pub.ID), "accepted truncated public key")
		check(slhdsa.Verify(&x.pub, slhdsa.NewMessage(c.Msg), c.Sig, c.Ctx), "failed valid request after negatives")
		_, err = slhdsa.SignDeterministic(&x.priv, slhdsa.NewMessage(c.Msg), make([]byte, 256))
		check(err != nil, "accepted long context")
		for i := range owned {
			check(bytes.Equal(owned[i], saved[i]), "mutated caller input")
		}
	}
	emit(map[string]any{"checked": len(cases), "negative_checks_per_case": 7, "caller_inputs_preserved": true})
}

func bench(cases []fixture, param, op string, budget, warmup time.Duration) {
	var corpus []loaded
	for _, c := range cases {
		if c.Param == param {
			corpus = append(corpus, load(c))
		}
	}
	check(len(corpus) == 3, "benchmark requires a complete varied corpus")
	check(op == "keygen" || op == "sign" || op == "verify", "unknown operation")
	measure := func(duration time.Duration) map[string]any {
		var lastSig []byte
		var lastPK slhdsa.PublicKey
		var lastSK slhdsa.PrivateKey
		allValid := true
		iterations := 0
		start := time.Now()
		var elapsed time.Duration
		for {
			for _, c := range corpus {
				var err error
				switch op {
				case "keygen":
					lastPK, lastSK, err = slhdsa.GenerateKey(bytes.NewReader(c.Seed), c.pub.ID)
				case "sign":
					lastSig, err = slhdsa.SignDeterministic(&c.priv, slhdsa.NewMessage(c.Msg), c.Ctx)
				case "verify":
					allValid = slhdsa.Verify(&c.pub, slhdsa.NewMessage(c.Msg), c.Sig, c.Ctx) && allValid
				}
				must(err)
				iterations++
			}
			elapsed = time.Since(start)
			if elapsed >= duration {
				break
			}
		}
		last := corpus[len(corpus)-1]
		if op == "keygen" {
			pk, err := lastPK.MarshalBinary()
			must(err)
			sk, err := lastSK.MarshalBinary()
			must(err)
			check(bytes.Equal(pk, last.PK) && bytes.Equal(sk, last.SK), "timed keygen mismatch")
		} else if op == "sign" {
			check(bytes.Equal(lastSig, last.Sig), "timed sign mismatch")
		} else {
			check(allValid, "timed verify rejected")
		}
		return map[string]any{"iterations": iterations, "ns_per_op": float64(elapsed.Nanoseconds()) / float64(iterations)}
	}
	measure(warmup)
	result := measure(budget)
	result["param"], result["op"] = param, op
	result["go"], result["os"], result["arch"] = runtime.Version(), runtime.GOOS, runtime.GOARCH
	emit(result)
}

func main() {
	mode := flag.String("mode", "", "check, fixture, check-fixture, bench")
	suite := flag.String("suite", "", "validation gzip")
	path := flag.String("fixture", "", "fixture JSON")
	fork := flag.Int("fork", 0, "corpus seed")
	param := flag.String("param", "", "parameter set")
	op := flag.String("op", "", "operation")
	budget := flag.Duration("budget", 100*time.Millisecond, "measurement duration")
	warmup := flag.Duration("warmup", 50*time.Millisecond, "warmup duration")
	flag.Parse()
	check(flag.NArg() == 0 && *fork >= 0 && *budget > 0 && *warmup > 0, "invalid arguments")
	if *mode == "check" {
		checkSuite(*suite)
		return
	}
	if *mode == "fixture" {
		makeFixture(*fork)
		return
	}
	f, err := os.Open(*path)
	must(err)
	defer f.Close()
	data, err := io.ReadAll(f)
	must(err)
	var cases []fixture
	must(json.Unmarshal(data, &cases))
	if *mode == "check-fixture" {
		checkFixture(cases)
	} else if *mode == "bench" {
		bench(cases, *param, *op, *budget, *warmup)
	} else {
		panic("unknown mode")
	}
}
