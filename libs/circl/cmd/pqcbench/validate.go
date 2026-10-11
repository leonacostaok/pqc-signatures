package main

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type vcase struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Kind        string `json:"kind"`
	Param       string `json:"param"`
	SeedHex     string `json:"seed_hex"`
	ExpectPkHex string `json:"expect_pk_hex"`
	ExpectSkHex string `json:"expect_sk_hex"`
	SkHex       string `json:"sk_hex"`
	PkHex       string `json:"pk_hex"`
	MsgHex      string `json:"msg_hex"`
	CtxHex      string `json:"ctx_hex"`
	SigHex      string `json:"sig_hex"`
	ExpectSig   string `json:"expect_sig_hex"`
	Expect      *bool  `json:"expect"`
	Reason      string `json:"reason"`
}

type vresult struct {
	ID      string  `json:"id"`
	Variant string  `json:"variant"`
	Pass    bool    `json:"pass"`
	Got     *bool   `json:"got"`
	Error   *string `json:"error"`
	Skipped bool    `json:"skipped,omitempty"`
}

type vsummary struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Skipped int `json:"skipped"`
}

type voutput struct {
	Lib        string               `json:"lib"`
	LibVersion string               `json:"lib_version"`
	Results    []vresult            `json:"results"`
	Summary    map[string]*vsummary `json:"summary"`
}

func loadSuite(path string) []vcase {
	f, err := os.Open(path)
	if err != nil {
		fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			fatalf("gunzip %s: %v", path, err)
		}
		defer gz.Close()
		r = gz
	}
	var suite struct {
		Cases []vcase `json:"cases"`
	}
	if err := json.NewDecoder(r).Decode(&suite); err != nil {
		fatalf("parse %s: %v", path, err)
	}
	return suite.Cases
}

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fatalf("bad hex in suite: %v", err)
	}
	return b
}

// runCase executes one case through one variant; panics become error strings.
func runCase(a *alg, cs *vcase, v *variant, impl stageImpl, pipeline string) (res vresult) {
	res = vresult{ID: cs.ID}
	if v != nil {
		res.Variant = v.id
	} else {
		res.Variant = pipeline
	}
	defer func() {
		if p := recover(); p != nil {
			s := fmt.Sprint(p)
			res.Error = &s
			f := false
			res.Got = &f
			// an exception counts as "false": that is a pass only for sigver cases expecting false
			res.Pass = cs.Kind == "sigver" && cs.Expect != nil && !*cs.Expect
		}
	}()
	switch cs.Kind {
	case "keygen":
		in := &inputs{seed: hx(cs.SeedHex)}
		r := newRunner(a, in, v)
		pk, sk := r.run()
		r.cleanup()
		ok := !r.bad && bytes.Equal(pk, hx(cs.ExpectPkHex)) && bytes.Equal(sk, hx(cs.ExpectSkHex))
		res.Got, res.Pass = &ok, ok
		if !ok {
			s := "pk/sk differ from expected"
			res.Error = &s
		}
	case "siggen":
		in := &inputs{sk: hx(cs.SkHex), msg: hx(cs.MsgHex), ctx: hx(cs.CtxHex)}
		r := newRunner(a, in, v)
		sig, _ := r.run()
		r.cleanup()
		ok := !r.bad && bytes.Equal(sig, hx(cs.ExpectSig))
		res.Got, res.Pass = &ok, ok
		if !ok {
			s := "signature differs from expected"
			res.Error = &s
		}
	case "sigver":
		in := &inputs{pk: hx(cs.PkHex), msg: hx(cs.MsgHex), ctx: hx(cs.CtxHex), sig: hx(cs.SigHex)}
		var got bool
		if v != nil {
			r := newRunner(a, in, v)
			o, _ := r.run()
			r.cleanup()
			got = !r.bad && bytes.Equal(o, bTrue)
		} else {
			got = impl.verifyPipeline(pipeline == "verify.total_best", in.pk, in.msg, in.ctx, in.sig)
		}
		res.Got = &got
		res.Pass = cs.Expect != nil && got == *cs.Expect
		if !res.Pass {
			s := fmt.Sprintf("expected %v, got %v (%s)", *cs.Expect, got, cs.Reason)
			res.Error = &s
		}
	}
	return res
}

var flavors = []string{"default", "purego", "amd64v3", "pgo"}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	suite := fs.String("suite", "", "validation.json(.gz)")
	out := fs.String("out", "", "output json")
	onlyOwn := fs.Bool("only-own", false, "run only this binary's variants (used for sub-processes)")
	bindir := fs.String("bindir", "", "directory with the pqcbench-<flavor> binaries (default: this binary's dir)")
	params := fs.String("params", "", "comma-separated params filter (dev)")
	fs.Parse(args)
	cases := loadSuite(*suite)
	pset := splitList(*params)

	res := voutput{Lib: libName, LibVersion: libVersion(), Results: []vresult{}, Summary: map[string]*vsummary{}}
	kindOp := map[string]string{"keygen": "keygen", "siggen": "sign", "sigver": "verify"}
	impls := map[string]stageImpl{}
	for i := range cases {
		cs := &cases[i]
		a := algByName(cs.Param)
		if a == nil || (pset != nil && !pset[cs.Param]) {
			continue
		}
		op := kindOp[cs.Kind]
		for j := range variantTable {
			v := &variantTable[j]
			if v.op != op || v.flavor != flavor {
				continue
			}
			res.Results = append(res.Results, runCase(a, cs, v, nil, ""))
		}
		if cs.Kind == "sigver" && flavor == "default" {
			impl, ok := impls[cs.Param]
			if !ok {
				impl = newStageImpl(a)
				impls[cs.Param] = impl
			}
			for _, p := range []string{"verify.total", "verify.total_best"} {
				res.Results = append(res.Results, runCase(a, cs, nil, impl, p))
			}
		}
		if i%50 == 0 {
			fmt.Fprintf(os.Stderr, "[%s] validate: %d/%d cases\n", flavor, i, len(cases))
		}
	}

	// Orchestrate the other build flavors as sub-processes and merge.
	if !*onlyOwn && flavor == "default" {
		dir := *bindir
		if dir == "" {
			exe, _ := os.Executable()
			dir = filepath.Dir(exe)
		}
		for _, f := range flavors {
			if f == "default" {
				continue
			}
			tmp := filepath.Join(os.TempDir(), fmt.Sprintf("pqcbench-validate-%s-%d.json", f, os.Getpid()))
			cmd := exec.Command(filepath.Join(dir, "pqcbench-"+f), "validate", "--suite", *suite, "--out", tmp, "--only-own", "--params", *params)
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fatalf("sub-process %s: %v", f, err)
			}
			var part voutput
			mustReadJSON(tmp, &part)
			os.Remove(tmp)
			res.Results = append(res.Results, part.Results...)
		}
	}
	for _, r := range res.Results {
		s := res.Summary[r.Variant]
		if s == nil {
			s = &vsummary{}
			res.Summary[r.Variant] = s
		}
		switch {
		case r.Skipped:
			s.Skipped++
		case r.Pass:
			s.Pass++
		default:
			s.Fail++
		}
	}
	writeJSON(*out, res)
	fails := 0
	for k, s := range res.Summary {
		fails += s.Fail
		fmt.Fprintf(os.Stderr, "[%s] %-20s pass=%d fail=%d skipped=%d\n", flavor, k, s.Pass, s.Fail, s.Skipped)
	}
	if fails > 0 {
		fmt.Fprintf(os.Stderr, "pqcbench: WARNING %d validation failures (see %s)\n", fails, *out)
	}
}
