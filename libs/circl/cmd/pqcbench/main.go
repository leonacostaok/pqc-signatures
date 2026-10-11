// pqcbench: CIRCL harness for the pqc-signatures benchmark (see common/CONTRACT.md).
//
// Subcommands:
//
//	vectors     --common DIR --out FILE
//	crossverify --common DIR --in ARTIFACTS --out FILE
//	bench       --common DIR --out FILE [--budget-ms N] [--params a,b] [--ops k,s,v] [--variants id,id]
//	profile     --common DIR --out FILE.pgo [--ms N]   (CPU profile of the workload, for PGO)
//	variants                                             (prints variant table, one per line)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

// flavor is set with -ldflags "-X main.flavor=..." at build time:
// default | purego | amd64v3 | pgo
var flavor = "default"

const libName = "circl"

type vectors struct {
	MessageHex string `json:"message_hex"`
	ContextHex string `json:"context_hex"`
	Params     []struct {
		Name              string `json:"name"`
		Family            string `json:"family"`
		SeedHex           string `json:"seed_hex"`
		ByteMatchExpected bool   `json:"byte_match_expected"`
	} `json:"params"`
}

type refEntry struct {
	PkLen     int    `json:"pk_len"`
	SkLen     int    `json:"sk_len"`
	SigLen    int    `json:"sig_len"`
	PkSha256  string `json:"pk_sha256"`
	SkSha256  string `json:"sk_sha256"`
	SigSha256 string `json:"sig_sha256"`
}

type common struct {
	vec vectors
	ref map[string]refEntry
	msg []byte
	ctx []byte
}

func loadCommon(dir string) *common {
	c := &common{}
	mustReadJSON(dir+"/vectors.json", &c.vec)
	mustReadJSON(dir+"/reference.json", &c.ref)
	c.msg = mustHex(c.vec.MessageHex)
	c.ctx = mustHex(c.vec.ContextHex)
	if len(c.ctx) != 0 {
		fatalf("this harness only supports the empty context")
	}
	return c
}

func (c *common) seed(name string) []byte {
	for _, p := range c.vec.Params {
		if p.Name == name {
			return mustHex(p.SeedHex)
		}
	}
	return nil
}

func mustReadJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		fatalf("parse %s: %v", path, err)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fatalf("bad hex: %v", err)
	}
	return b
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pqcbench: "+format+"\n", args...)
	os.Exit(1)
}

func libVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/cloudflare/circl" {
				return strings.TrimPrefix(d.Version, "v")
			}
		}
	}
	return "unknown"
}

func runtimeString() string {
	return fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// ---------------------------------------------------------------- vectors

type artifactEntry struct {
	Param      string `json:"param"`
	PkHex      string `json:"pk_hex"`
	SigHex     string `json:"sig_hex"`
	SkSha256   string `json:"sk_sha256"`
	PkSha256   string `json:"pk_sha256"`
	SigSha256  string `json:"sig_sha256"`
	SelfVerify bool   `json:"self_verify"`
}

type artifacts struct {
	Lib        string          `json:"lib"`
	LibVersion string          `json:"lib_version"`
	Entries    []artifactEntry `json:"entries"`
}

func cmdVectors(args []string) {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	commonDir := fs.String("common", "common", "directory with vectors.json/reference.json")
	out := fs.String("out", "", "output artifacts file")
	fs.Parse(args)
	c := loadCommon(*commonDir)

	art := artifacts{Lib: libName, LibVersion: libVersion()}
	bad := 0
	for _, a := range algs {
		seed := c.seed(a.name)
		if seed == nil {
			continue
		}
		pk, sk := a.keygen(seed)
		sig := a.newSigner(sk)(c.msg, make([]byte, a.sigSize))
		ok := a.newVerifier(pk)(c.msg, sig)
		e := artifactEntry{
			Param: a.name, PkHex: hex.EncodeToString(pk), SigHex: hex.EncodeToString(sig),
			SkSha256: sha256hex(sk), PkSha256: sha256hex(pk), SigSha256: sha256hex(sig), SelfVerify: ok,
		}
		art.Entries = append(art.Entries, e)
		status := "OK"
		if r, has := c.ref[a.name]; has {
			if r.PkSha256 != e.PkSha256 || r.SkSha256 != e.SkSha256 || r.SigSha256 != e.SigSha256 || !ok {
				status = "MISMATCH"
				bad++
			}
		} else {
			status = "no-reference"
		}
		fmt.Fprintf(os.Stderr, "%-20s pk=%d sk=%d sig=%d self_verify=%v %s\n", a.name, len(pk), len(sk), len(sig), ok, status)
	}
	writeJSON(*out, art)
	if bad > 0 {
		fatalf("%d parameter sets do not match common/reference.json", bad)
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if path == "" || path == "-" {
		os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

// ---------------------------------------------------------------- crossverify

type crossResult struct {
	Param          string  `json:"param"`
	OK             bool    `json:"ok"`
	Error          *string `json:"error"`
	TamperRejected bool    `json:"tamper_rejected"`
}

func cmdCrossverify(args []string) {
	fs := flag.NewFlagSet("crossverify", flag.ExitOnError)
	commonDir := fs.String("common", "common", "directory with vectors.json/reference.json")
	in := fs.String("in", "", "artifacts file produced by another library")
	out := fs.String("out", "", "output file")
	fs.Parse(args)
	c := loadCommon(*commonDir)

	var src artifacts
	mustReadJSON(*in, &src)
	res := struct {
		Lib     string        `json:"lib"`
		Source  string        `json:"source"`
		Results []crossResult `json:"results"`
	}{Lib: libName, Source: src.Lib, Results: []crossResult{}}

	failures := 0
	for _, e := range src.Entries {
		a := algByName(e.Param)
		if a == nil {
			continue // unsupported here: skipped
		}
		r := crossResult{Param: e.Param}
		func() {
			defer func() {
				if p := recover(); p != nil {
					s := fmt.Sprint(p)
					r.Error = &s
					r.OK = false
				}
			}()
			pk, err1 := hex.DecodeString(e.PkHex)
			sig, err2 := hex.DecodeString(e.SigHex)
			if err1 != nil || err2 != nil {
				s := "bad hex"
				r.Error = &s
				return
			}
			if len(pk) != a.pkSize {
				s := fmt.Sprintf("pk length %d, expected %d", len(pk), a.pkSize)
				r.Error = &s
				return
			}
			if len(sig) != a.sigSize {
				s := fmt.Sprintf("sig length %d, expected %d", len(sig), a.sigSize)
				r.Error = &s
				return
			}
			v := a.newVerifier(pk)
			r.OK = v(c.msg, sig)
			if !r.OK {
				s := "signature rejected"
				r.Error = &s
			}
			t := append([]byte(nil), sig...)
			t[len(t)/2] ^= 0x01
			r.TamperRejected = !v(c.msg, t)
		}()
		if !r.OK || !r.TamperRejected {
			failures++
		}
		fmt.Fprintf(os.Stderr, "%-20s ok=%v tamper_rejected=%v\n", r.Param, r.OK, r.TamperRejected)
		res.Results = append(res.Results, r)
	}
	writeJSON(*out, res)
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "pqcbench: WARNING %d cross-verification failures (see %s)\n", failures, *out)
	}
}

// ---------------------------------------------------------------- main

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: pqcbench <vectors|crossverify|bench|profile|variants> ...")
	}
	switch os.Args[1] {
	case "vectors":
		cmdVectors(os.Args[2:])
	case "crossverify":
		cmdCrossverify(os.Args[2:])
	case "bench":
		cmdBench(os.Args[2:])
	case "profile":
		cmdProfile(os.Args[2:])
	case "variants":
		for _, v := range variantTable {
			fmt.Printf("%s\t%s\t%s\t%s\n", v.id, v.flavor, v.name, v.desc)
		}
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
}
