// Code template: generated from stages_ml44.go (do not edit); stages_ml65.go and
// stages_ml87.go are generated from it by run.sh (sed on "44").

package main

import (
	"bytes"

	mi "pqcbench/vendorcircl/mldsa65i"
)

type mlStages65 struct {
	pk, msg, ctx, sig []byte
	// v0 intermediates on the prepared inputs
	dpk      mi.DecodedPk
	dsig     mi.DecodedSig
	tr       [mi.TRSize]byte
	mu       [64]byte
	A        mi.Mat
	t1h      mi.VecK
	w        mi.VecK
	w1Packed []byte
	mid      *mi.MuMidstate
	// scratch written by timed runs
	sdpk  mi.DecodedPk
	sdsig mi.DecodedSig
	str   [mi.TRSize]byte
	smu   [64]byte
	sA    *mi.Mat
	sw    mi.VecK
	sw1   []byte
	// best-pipeline cache (pk, ctx)
	cpk, cctx []byte
}

func newMLStages65() stageImpl { return &mlStages65{} }

func (m *mlStages65) stageNames() []string {
	return []string{"decode", "mu", "expandA", "w_approx", "hint_check"}
}

func (m *mlStages65) prepare(pk, msg, ctx, sig []byte) bool {
	m.pk, m.msg, m.ctx, m.sig = pk, msg, ctx, sig
	if len(ctx) > 255 || !mi.DecodePk(&m.dpk, pk) || !mi.DecodeSig(&m.dsig, sig) {
		return false
	}
	mi.Tr(pk, &m.tr)
	mi.Mu(&m.tr, ctx, msg, &m.mu)
	mi.ExpandA(&m.A, &m.dpk.Rho)
	mi.T1Hat(&m.t1h, &m.dpk.T1)
	mi.WApprox(&m.w, &m.A, &m.dpk.T1, &m.dsig.Z, &m.dsig.C)
	m.w1Packed = make([]byte, mi.PolyW1Size*mi.K)
	ok := mi.HintCheck(&m.w, &m.dsig.Hint, &m.dsig.Z, &m.mu, &m.dsig.C, m.w1Packed)
	m.mid = mi.NewMuMidstate(&m.tr, ctx)
	m.sA = new(mi.Mat)
	m.sw1 = make([]byte, mi.PolyW1Size*mi.K)
	m.cpk, m.cctx = pk, ctx
	return ok
}

func (m *mlStages65) stage(name, mode string) (stageRun, bool) {
	r := stageRun{threads: 1}
	switch name {
	case "decode":
		r.out = func() []byte { return m.sdsig.C[:] }
		switch mode {
		case "circl":
			r.run = func() bool { return mi.DecodePk(&m.sdpk, m.pk) && mi.DecodeSig(&m.sdsig, m.sig) }
		case "cachedpk":
			r.run = func() bool { return mi.DecodeSig(&m.sdsig, m.sig) }
		case "fused":
			r.run = func() bool { return mi.DecodePk(&m.sdpk, m.pk) && mi.DecodeSigFused(&m.sdsig, m.sig) }
		default:
			return r, false
		}
	case "mu":
		r.out = func() []byte { return m.smu[:] }
		switch mode {
		case "circl":
			r.run = func() bool { mi.Tr(m.pk, &m.str); mi.Mu(&m.str, m.ctx, m.msg, &m.smu); return true }
		case "cachedtr":
			r.run = func() bool { mi.Mu(&m.tr, m.ctx, m.msg, &m.smu); return true }
		case "stdsha3":
			r.run = func() bool { mi.TrStd(m.pk, &m.str); mi.MuStd(&m.str, m.ctx, m.msg, &m.smu); return true }
		case "midstate":
			r.run = func() bool { m.mid.Mu(m.msg, &m.smu); return true }
		default:
			return r, false
		}
	case "expandA":
		r.out = func() []byte { return mi.MatCanonical(m.sA) }
		switch mode {
		case "circl":
			r.run = func() bool { mi.ExpandA(m.sA, &m.dpk.Rho); return true }
		case "scalar":
			r.run = func() bool { mi.ExpandAScalar(m.sA, &m.dpk.Rho); return true }
		case "parrows":
			r.threads = mi.ExpandAThreads()
			r.run = func() bool { mi.ExpandAParallelRows(m.sA, &m.dpk.Rho); return true }
		case "cachedA":
			r.run = func() bool { m.sA = &m.A; return true }
		default:
			return r, false
		}
	case "w_approx":
		r.out = func() []byte { return mi.VecKCanonical(&m.sw) }
		switch mode {
		case "circl":
			r.run = func() bool { mi.WApprox(&m.sw, &m.A, &m.dpk.T1, &m.dsig.Z, &m.dsig.C); return true }
		case "cachedT1":
			r.run = func() bool { mi.WApproxCachedT1(&m.sw, &m.A, &m.t1h, &m.dsig.Z, &m.dsig.C); return true }
		case "parrows":
			r.threads = mi.WThreads()
			r.run = func() bool { mi.WApproxParallelRows(&m.sw, &m.A, &m.dpk.T1, &m.dsig.Z, &m.dsig.C); return true }
		default:
			return r, false
		}
	case "hint_check":
		r.out = func() []byte { return m.sw1 }
		switch mode {
		case "circl":
			r.run = func() bool { return mi.HintCheck(&m.w, &m.dsig.Hint, &m.dsig.Z, &m.mu, &m.dsig.C, m.sw1) }
		case "fused":
			r.run = func() bool { return mi.HintCheckFused(&m.w, &m.dsig.Hint, &m.dsig.Z, &m.mu, &m.dsig.C, m.sw1) }
		case "stdsha3":
			r.run = func() bool { return mi.HintCheckStd(&m.w, &m.dsig.Hint, &m.dsig.Z, &m.mu, &m.dsig.C, m.sw1) }
		default:
			return r, false
		}
	case "total":
		r.run = func() bool { return m.verifyPipeline(false, m.pk, m.msg, m.ctx, m.sig) }
		r.out = nil
	case "total_best":
		r.run = func() bool { return m.verifyPipeline(true, m.pk, m.msg, m.ctx, m.sig) }
		r.out = nil
	default:
		return r, false
	}
	return r, true
}

// verifyPipeline is the end-to-end verify assembled from stages.
// best=false: v0 of every stage (= what mldsa.PublicKey.UnmarshalBinary + Verify do).
// best=true: per-(pk,ctx) cache of pkDecode, tr, A^, NTT(t1*2^d) and the mu
// midstate (built untimed when the key changes), fused z decode, fused hint/pack.
func (m *mlStages65) verifyPipeline(best bool, pk, msg, ctx, sig []byte) bool {
	if len(ctx) > 255 {
		return false
	}
	if !best {
		var dpk mi.DecodedPk
		var dsig mi.DecodedSig
		if !mi.DecodePk(&dpk, pk) || !mi.DecodeSig(&dsig, sig) {
			return false
		}
		var tr [mi.TRSize]byte
		var mu [64]byte
		mi.Tr(pk, &tr)
		mi.Mu(&tr, ctx, msg, &mu)
		A := new(mi.Mat)
		mi.ExpandA(A, &dpk.Rho)
		var w mi.VecK
		mi.WApprox(&w, A, &dpk.T1, &dsig.Z, &dsig.C)
		var w1 [mi.PolyW1Size * mi.K]byte
		return mi.HintCheck(&w, &dsig.Hint, &dsig.Z, &mu, &dsig.C, w1[:])
	}
	if !bytes.Equal(pk, m.cpk) || !bytes.Equal(ctx, m.cctx) || m.mid == nil {
		// (re)build the per-key cache, untimed in the stages benchmark
		if !mi.DecodePk(&m.dpk, pk) {
			return false
		}
		mi.Tr(pk, &m.tr)
		mi.ExpandA(&m.A, &m.dpk.Rho)
		mi.T1Hat(&m.t1h, &m.dpk.T1)
		m.mid = mi.NewMuMidstate(&m.tr, ctx)
		m.cpk, m.cctx = append([]byte(nil), pk...), append([]byte(nil), ctx...)
	}
	var dsig mi.DecodedSig
	if !mi.DecodeSigFused(&dsig, sig) {
		return false
	}
	var mu [64]byte
	m.mid.Mu(msg, &mu)
	var w mi.VecK
	mi.WApproxCachedT1(&w, &m.A, &m.t1h, &dsig.Z, &dsig.C)
	var w1 [mi.PolyW1Size * mi.K]byte
	return mi.HintCheckFused(&w, &dsig.Hint, &dsig.Z, &mu, &dsig.C, w1[:])
}
