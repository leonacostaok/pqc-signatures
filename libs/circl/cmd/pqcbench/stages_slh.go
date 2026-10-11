package main

import (
	"bytes"
	"sync"

	"pqcbench/vendorcircl/slhdsa"
)

// slhStages implements the SLH-DSA verify stages (hmsg, fors, ht_wots, ht_auth)
// on top of the vendored CIRCL slhdsa package.
type slhStages struct {
	id  slhdsa.ID
	pub slhdsa.PublicKey
	v   *slhdsa.Verifier
	st  *slhdsa.State // CIRCL hashers
	alt *slhdsa.State // SHA-2 midstate (SHA2 sets) or stdlib SHA-3 (SHAKE sets)
	pool []*slhdsa.State

	pk, msg, ctx, sig, msgPrime []byte
	ps                          *slhdsa.ParsedSig
	h                           slhdsa.HMsgOut
	pkFors                      []byte
	idxLeaf                     []uint32
	idxTree                     [][3]uint32
	msgs, wots, roots           [][]byte
	// scratch
	sh       slhdsa.HMsgOut
	spk      []byte
	sw, sr   [][]byte
	swFlat   []byte
	srFlat   []byte
	cpk, cctx []byte
}

func newSLHStages(id slhdsa.ID) stageImpl { return &slhStages{id: id} }

func (m *slhStages) stageNames() []string { return []string{"hmsg", "fors", "ht_wots", "ht_auth"} }

func (m *slhStages) setKey(pk []byte) bool {
	m.pub = slhdsa.PublicKey{ID: m.id}
	if err := m.pub.UnmarshalBinary(pk); err != nil {
		return false
	}
	m.v = slhdsa.NewVerifier(&m.pub)
	m.st = m.v.NewState()
	if m.v.IsSHA2() {
		m.alt = m.v.NewStateMidstate()
	} else {
		m.alt = m.v.NewStateStdSHA3()
	}
	m.pool = m.v.NewStatePool(slhdsa.Threads(max(m.v.K(), m.v.D())))
	m.cpk = append([]byte(nil), pk...)
	return true
}

func (m *slhStages) prepare(pk, msg, ctx, sig []byte) bool {
	m.pk, m.msg, m.ctx, m.sig = pk, msg, ctx, sig
	if !m.setKey(pk) {
		return false
	}
	mp, ok := slhdsa.MsgPrime(msg, ctx)
	if !ok {
		return false
	}
	m.msgPrime = mp
	m.ps, ok = m.v.ParseSig(sig)
	if !ok {
		return false
	}
	m.v.HMsg(m.ps.R, m.msgPrime, &m.h)
	m.pkFors = append([]byte(nil), m.v.Fors(m.st, m.ps, &m.h)...)
	m.idxLeaf, m.idxTree = m.v.HTLayout(&m.h)
	d, n := m.v.D(), m.v.N()
	m.msgs, m.wots, m.roots = make([][]byte, d), make([][]byte, d), make([][]byte, d)
	m.sw, m.sr = make([][]byte, d), make([][]byte, d)
	m.swFlat, m.srFlat = make([]byte, d*n), make([]byte, d*n)
	in := m.pkFors
	for j := 0; j < d; j++ {
		m.msgs[j] = in
		m.wots[j] = make([]byte, n)
		m.roots[j] = make([]byte, n)
		m.v.WotsLayer(m.st, m.ps, j, in, m.idxLeaf[j], m.idxTree[j], m.wots[j])
		m.v.AuthLayer(m.st, m.ps, j, m.wots[j], m.idxLeaf[j], m.idxTree[j], m.roots[j])
		in = m.roots[j]
		m.sw[j] = m.swFlat[j*n : (j+1)*n]
		m.sr[j] = m.srFlat[j*n : (j+1)*n]
	}
	m.spk = make([]byte, n)
	m.sh = slhdsa.HMsgOut{}
	return m.v.RootOK(m.roots[d-1])
}

func (m *slhStages) stage(name, mode string) (stageRun, bool) {
	r := stageRun{threads: 1}
	d := m.v.D()
	wotsAll := func(s *slhdsa.State) bool {
		for j := 0; j < d; j++ {
			m.v.WotsLayer(s, m.ps, j, m.msgs[j], m.idxLeaf[j], m.idxTree[j], m.sw[j])
		}
		return true
	}
	authAll := func(s *slhdsa.State) bool {
		for j := 0; j < d; j++ {
			m.v.AuthLayer(s, m.ps, j, m.wots[j], m.idxLeaf[j], m.idxTree[j], m.sr[j])
		}
		return m.v.RootOK(m.sr[d-1])
	}
	parLayers := func(f func(s *slhdsa.State, j int)) bool {
		w := len(m.pool)
		var wg sync.WaitGroup
		wg.Add(w)
		for g := 0; g < w; g++ {
			go func(g int) {
				defer wg.Done()
				for j := g; j < d; j += w {
					f(m.pool[g], j)
				}
			}(g)
		}
		wg.Wait()
		return true
	}
	switch name {
	case "hmsg":
		r.out = func() []byte { return m.sh.Digest }
		switch mode {
		case "circl":
			r.run = func() bool {
				ps, ok := m.v.ParseSig(m.sig)
				if !ok {
					return false
				}
				m.v.HMsg(ps.R, m.msgPrime, &m.sh)
				return true
			}
		case "lazy":
			r.run = func() bool {
				rnd, ok := m.v.ParseR(m.sig)
				if !ok {
					return false
				}
				m.v.HMsg(rnd, m.msgPrime, &m.sh)
				return true
			}
		case "althash":
			if m.v.IsSHA2() {
				return r, false // no alternative H_msg backend for SHA-2 sets
			}
			r.run = func() bool {
				ps, ok := m.v.ParseSig(m.sig)
				if !ok {
					return false
				}
				m.v.HMsgStd(ps.R, m.msgPrime, &m.sh)
				return true
			}
		default:
			return r, false
		}
	case "fors":
		r.out = func() []byte { return m.spk }
		switch mode {
		case "circl":
			r.run = func() bool { copy(m.spk, m.v.Fors(m.st, m.ps, &m.h)); return true }
		case "parallel":
			r.threads = len(m.pool)
			r.run = func() bool { copy(m.spk, m.v.ForsParallel(m.st, m.pool, m.ps, &m.h)); return true }
		case "althash":
			r.run = func() bool { copy(m.spk, m.v.Fors(m.alt, m.ps, &m.h)); return true }
		default:
			return r, false
		}
	case "ht_wots":
		r.out = func() []byte { return m.swFlat }
		switch mode {
		case "circl":
			r.run = func() bool { return wotsAll(m.st) }
		case "parallel":
			r.threads = len(m.pool)
			r.run = func() bool {
				return parLayers(func(s *slhdsa.State, j int) {
					m.v.WotsLayer(s, m.ps, j, m.msgs[j], m.idxLeaf[j], m.idxTree[j], m.sw[j])
				})
			}
		case "althash":
			r.run = func() bool { return wotsAll(m.alt) }
		default:
			return r, false
		}
	case "ht_auth":
		r.out = func() []byte { return m.srFlat }
		switch mode {
		case "circl":
			r.run = func() bool { return authAll(m.st) }
		case "parallel":
			r.threads = len(m.pool)
			r.run = func() bool {
				parLayers(func(s *slhdsa.State, j int) {
					m.v.AuthLayer(s, m.ps, j, m.wots[j], m.idxLeaf[j], m.idxTree[j], m.sr[j])
				})
				return m.v.RootOK(m.sr[d-1])
			}
		case "althash":
			r.run = func() bool { return authAll(m.alt) }
		default:
			return r, false
		}
	case "total":
		r.run = func() bool { return m.verifyPipeline(false, m.pk, m.msg, m.ctx, m.sig) }
	case "total_best":
		r.run = func() bool { return m.verifyPipeline(true, m.pk, m.msg, m.ctx, m.sig) }
	default:
		return r, false
	}
	return r, true
}

// bestUsesAltHash: total_best uses the SHA-2 midstate state for SHA2 sets and
// the stdlib SHA-3 state for SHAKE sets (see docs/circl/verify-stages.md).
var slhBestAltHash = map[bool]bool{true: true, false: false}

// verifyPipeline: best=false is hmsg.v0 -> fors.v0 -> ht_wots.v0 -> ht_auth.v0
// (identical work to slhdsa.Verify); best=true is lazy parse + alternative
// hash backend, sequential layers.
func (m *slhStages) verifyPipeline(best bool, pk, msg, ctx, sig []byte) bool {
	if m.v == nil || !bytes.Equal(pk, m.cpk) {
		if !m.setKey(pk) {
			return false
		}
	}
	mp, ok := slhdsa.MsgPrime(msg, ctx)
	if !ok {
		return false
	}
	var h slhdsa.HMsgOut
	var ps *slhdsa.ParsedSig
	s := m.st
	if best && slhBestAltHash[m.v.IsSHA2()] {
		s = m.alt
	}
	if best {
		rnd, ok := m.v.ParseR(sig)
		if !ok {
			return false
		}
		m.v.HMsg(rnd, mp, &h)
		if ps, ok = m.v.ParseSig(sig); !ok {
			return false
		}
	} else {
		if ps, ok = m.v.ParseSig(sig); !ok {
			return false
		}
		m.v.HMsg(ps.R, mp, &h)
	}
	in := append([]byte(nil), m.v.Fors(s, ps, &h)...) // Fors returns the state's T output buffer
	idxLeaf, idxTree := m.v.HTLayout(&h)
	n := m.v.N()
	wpk := make([]byte, n)
	root := make([]byte, n)
	for j := 0; j < m.v.D(); j++ {
		m.v.WotsLayer(s, ps, j, in, idxLeaf[j], idxTree[j], wpk)
		m.v.AuthLayer(s, ps, j, wpk, idxLeaf[j], idxTree[j], root)
		in = root
	}
	return m.v.RootOK(root)
}
