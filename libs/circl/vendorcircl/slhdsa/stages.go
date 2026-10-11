// stages.go -- pqc-signatures harness addition (NOT part of upstream CIRCL).
//
// Entry points exposing the canonical SLH-DSA verify stages of FIPS 205
// (hmsg, fors, ht_wots, ht_auth) built from CIRCL's own internal functions,
// plus algorithmic alternatives (lazy signature parse, parallel FORS trees /
// hypertree layers, SHA-2 midstate caching of PK.seed, stdlib SHA-3 backend).

package slhdsa

import (
	"bytes"
	"crypto/sha256"
	stdsha3 "crypto/sha3"
	"crypto/sha512"
	"encoding"
	"hash"
	"runtime"
	"sync"
)

// State is CIRCL's (unexported) hasher state, exported for the harness.
type State = state

// Verifier is the per-public-key context: parameters and CIRCL's hasher state.
type Verifier struct {
	p   *params
	pub *PublicKey
	st  state
}

func NewVerifier(pub *PublicKey) *Verifier {
	p := pub.ID.params()
	return &Verifier{p: p, pub: pub, st: p.NewStatePub(pub.seed)}
}

func (v *Verifier) N() int       { return int(v.p.n) }
func (v *Verifier) K() int       { return int(v.p.k) }
func (v *Verifier) D() int       { return int(v.p.d) }
func (v *Verifier) IsSHA2() bool { return v.p.isSHA2 }
func (v *Verifier) Root() []byte { return v.pub.root }

// MsgPrime is M' = 0 || len(ctx) || ctx || M (pure mode); false if ctx > 255.
func MsgPrime(msg, ctx []byte) ([]byte, bool) {
	mp, err := NewMessage(msg).getMsgPrime(ctx)
	return mp, err == nil
}

// ParsedSig wraps CIRCL's parsed signature structure.
type ParsedSig struct {
	sig signature
	R   []byte
}

// ParseSig parses the whole signature (R, FORS pairs, hypertree layers).
func (v *Verifier) ParseSig(b []byte) (*ParsedSig, bool) {
	if len(b) != v.p.SignatureSize() {
		return nil, false
	}
	ps := &ParsedSig{}
	c := cursor(b)
	if !ps.sig.fromBytes(v.p, &c) {
		return nil, false
	}
	ps.R = ps.sig.rnd
	return ps, true
}

// ParseR only length-checks the signature and slices out R (lazy parse).
func (v *Verifier) ParseR(b []byte) ([]byte, bool) {
	if len(b) != v.p.SignatureSize() {
		return nil, false
	}
	return b[:v.p.n], true
}

// ---------------------------------------------------------------- hmsg

type HMsgOut struct {
	Digest  []byte
	Md      []byte
	IdxTree [3]uint32
	IdxLeaf uint32
}

// HMsg: digest = H_msg(R, PK.seed, PK.root, M'), split into md/idx_tree/idx_leaf (CIRCL).
func (v *Verifier) HMsg(r, msgPrime []byte, out *HMsgOut) {
	if out.Digest == nil {
		out.Digest = make([]byte, v.p.m)
	}
	v.p.HashMsg(out.Digest, r, msgPrime, v.pub)
	out.Md, out.IdxTree, out.IdxLeaf = v.p.parseMsg(out.Digest)
}

// HMsgStd is HMsg for the SHAKE parameter sets using the standard library's
// crypto/sha3 SHAKE256 instead of CIRCL's internal sha3.
func (v *Verifier) HMsgStd(r, msgPrime []byte, out *HMsgOut) {
	if out.Digest == nil {
		out.Digest = make([]byte, v.p.m)
	}
	if v.p.isSHA2 {
		v.p.HashMsg(out.Digest, r, msgPrime, v.pub)
	} else {
		h := stdsha3.NewSHAKE256()
		_, _ = h.Write(r)
		_, _ = h.Write(v.pub.seed)
		_, _ = h.Write(v.pub.root)
		_, _ = h.Write(msgPrime)
		_, _ = h.Read(out.Digest)
	}
	out.Md, out.IdxTree, out.IdxLeaf = v.p.parseMsg(out.Digest)
}

// ---------------------------------------------------------------- fors

// forsIndices is base_2^a(md) for the k trees.
func (v *Verifier) forsIndices(md []byte) []uint32 {
	idx := make([]uint32, v.p.k)
	in, bits, total := 0, uint32(0), uint32(0)
	maskA := (uint32(1) << v.p.a) - 1
	for i := range v.p.k {
		for bits < v.p.a {
			total = (total << 8) + uint32(md[in])
			in++
			bits += 8
		}
		bits -= v.p.a
		idx[i] = (total >> bits) & maskA
	}
	return idx
}

func (v *Verifier) forsAddr(h *HMsgOut) address {
	addr := v.p.NewAddress()
	addr.SetTreeAddress(h.IdxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(h.IdxLeaf)
	return addr
}

// Fors is CIRCL's forsPkFromSig on the given state.
func (v *Verifier) Fors(s *state, ps *ParsedSig, h *HMsgOut) []byte {
	return s.forsPkFromSig(ps.sig.forsSig, h.Md, v.forsAddr(h))
}

// forsTreeRoot computes the root of FORS tree i from its secret leaf and auth path.
func forsTreeRoot(s *state, pair forsPair, i, indicesI, a uint32, addr address) []byte {
	s.F.address.Set(addr)
	s.F.address.SetTreeHeight(0)
	s.H.address.Set(addr)
	treeIdx := (i << a) + indicesI
	s.F.address.SetTreeIndex(treeIdx)
	s.F.SetMessage(pair.sk)
	node := append([]byte(nil), s.F.Final()...)
	for j := range a {
		if (indicesI>>j)&0x1 == 0 {
			treeIdx = treeIdx >> 1
			s.H.SetMsgs(node, pair.auth[j])
		} else {
			treeIdx = (treeIdx - 1) >> 1
			s.H.SetMsgs(pair.auth[j], node)
		}
		s.H.address.SetTreeHeight(j + 1)
		s.H.address.SetTreeIndex(treeIdx)
		copy(node, s.H.Final())
	}
	return node
}

// ForsParallel computes the k tree roots on len(pool) goroutines (each with
// its own hasher state) and then T-hashes the roots in order on s.
func (v *Verifier) ForsParallel(s *state, pool []*state, ps *ParsedSig, h *HMsgOut) []byte {
	addr := v.forsAddr(h)
	idx := v.forsIndices(h.Md)
	roots := make([][]byte, v.p.k)
	var wg sync.WaitGroup
	w := len(pool)
	wg.Add(w)
	for g := 0; g < w; g++ {
		go func(g int) {
			defer wg.Done()
			for i := uint32(g); i < v.p.k; i += uint32(w) {
				roots[i] = forsTreeRoot(pool[g], ps.sig.forsSig[i], i, idx[i], v.p.a, addr)
			}
		}(g)
	}
	wg.Wait()
	s.T.address.Set(addr)
	s.T.address.SetTypeAndClear(addressForsRoots)
	s.T.address.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.T.Reset()
	for i := range roots {
		s.T.WriteMessage(roots[i])
	}
	return append([]byte(nil), s.T.Final()...)
}

// ---------------------------------------------------------------- hypertree

// HTLayout returns, per layer j, the idx_leaf and idx_tree used by htVerify.
func (v *Verifier) HTLayout(h *HMsgOut) (idxLeaf []uint32, idxTree [][3]uint32) {
	it, il := h.IdxTree, h.IdxLeaf
	for j := uint32(0); j < v.p.d; j++ {
		if j > 0 {
			il = nextIndex(&it, v.p.hPrime)
		}
		idxLeaf = append(idxLeaf, il)
		idxTree = append(idxTree, it)
	}
	return
}

func (v *Verifier) layerAddr(j int, idxTree [3]uint32) address {
	addr := v.p.NewAddress()
	addr.SetLayerAddress(addrType(j))
	addr.SetTreeAddress(idxTree)
	return addr
}

// WotsLayer: WOTS+ pkFromSig for layer j (first half of xmssPkFromSig).
func (v *Verifier) WotsLayer(s *state, ps *ParsedSig, j int, msg []byte, idxLeaf uint32, idxTree [3]uint32, out []byte) {
	addr := v.layerAddr(j, idxTree)
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idxLeaf)
	copy(out, s.wotsPkFromSig(ps.sig.htSig[j].wotsSig, msg, addr))
}

// AuthLayer: XMSS root from the WOTS+ pk and the auth path of layer j
// (second half of xmssPkFromSig).
func (v *Verifier) AuthLayer(s *state, ps *ParsedSig, j int, wotsPk []byte, idxLeaf uint32, idxTree [3]uint32, out []byte) {
	addr := v.layerAddr(j, idxTree)
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idxLeaf)
	s.H.address.Set(addr)
	s.H.address.SetTypeAndClear(addressTree)
	pk := wotsPk
	treeIdx := idxLeaf
	authPath := cursor(ps.sig.htSig[j].authPath)
	for k := range v.p.hPrime {
		if (idxLeaf>>k)&0x1 == 0 {
			treeIdx = treeIdx >> 1
			s.H.SetMsgs(pk, authPath.Next(v.p.n))
		} else {
			treeIdx = (treeIdx - 1) >> 1
			s.H.SetMsgs(authPath.Next(v.p.n), pk)
		}
		s.H.address.SetTreeHeight(k + 1)
		s.H.address.SetTreeIndex(treeIdx)
		pk = s.H.Final()
	}
	copy(out, pk)
}

// RootOK is the final comparison with PK.root.
func (v *Verifier) RootOK(root []byte) bool { return bytes.Equal(root, v.pub.root) }

// Threads is min(n, GOMAXPROCS).
func Threads(n int) int { return min(n, runtime.GOMAXPROCS(0)) }

// ---------------------------------------------------------------- states

// NewState returns a fresh CIRCL hasher state for this public key.
func (v *Verifier) NewState() *state {
	s := v.p.NewStatePub(v.pub.seed)
	return &s
}

// NewStatePool returns n independent states (for goroutine workers).
func (v *Verifier) NewStatePool(n int) []*state {
	pool := make([]*state, n)
	for i := range pool {
		pool[i] = v.NewState()
	}
	return pool
}

// NewStateMidstate (SHA-2 sets only) returns a state whose F, H and T hash
// functions start from a saved SHA-256/SHA-512 state in which the first
// block PK.seed || toByte(0, 64-n or 128-n) is already compressed, so every
// call does one compression less. The states are restored with
// encoding.BinaryUnmarshaler (no allocation per call).
func (v *Verifier) NewStateMidstate() *state {
	if !v.p.isSHA2 {
		panic("midstate variant is for SHA-2 parameter sets")
	}
	s := v.p.NewStatePub(v.pub.seed)
	s.F.hash = midstateFn(sha256.New(), s.F.input[:64])
	if v.p.n == 16 {
		s.H.hash = midstateFn(sha256.New(), s.H.input[:64])
		s.T.hash = &midT{base: newMid(sha256.New(), s.T.input[:64]), skip: 64}
	} else {
		s.H.hash = midstateFn(sha512.New(), s.H.input[:128])
		s.T.hash = &midT{base: newMid(sha512.New(), s.T.input[:128]), skip: 128}
	}
	return &s
}

type mid struct {
	h     hash.Hash
	saved []byte
	plen  int
}

func newMid(h hash.Hash, prefix []byte) *mid {
	_, _ = h.Write(prefix)
	saved, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return &mid{h: h, saved: saved, plen: len(prefix)}
}

func (m *mid) restore() {
	if err := m.h.(encoding.BinaryUnmarshaler).UnmarshalBinary(m.saved); err != nil {
		panic(err)
	}
}

// midstateFn returns a hash(out, in) function that skips the first len(prefix)
// bytes of in (which always equal prefix) by restoring the saved state.
func midstateFn(h hash.Hash, prefix []byte) func(out, in []byte) {
	m := newMid(h, prefix)
	return func(out, in []byte) {
		m.restore()
		_, _ = m.h.Write(in[m.plen:])
		m.h.Sum(out[:0])
	}
}

// midT implements stateT's hash interface: Reset restores the midstate and
// the next `skip` written bytes (the prefix stateT.Reset always writes) are dropped.
type midT struct {
	base *mid
	skip int
	todo int
}

func (t *midT) Reset() { t.base.restore(); t.todo = t.skip }
func (t *midT) Write(p []byte) (int, error) {
	n := len(p)
	if t.todo > 0 {
		k := min(t.todo, len(p))
		t.todo -= k
		p = p[k:]
	}
	_, _ = t.base.h.Write(p)
	return n, nil
}
func (t *midT) Final(out []byte) { t.base.h.Sum(out[:0]) }

// NewStateStdSHA3 (SHAKE sets only) returns a state whose F, H and T use the
// Go standard library's crypto/sha3 SHAKE256 (amd64 assembly) instead of
// CIRCL's internal sha3.
func (v *Verifier) NewStateStdSHA3() *state {
	if v.p.isSHA2 {
		panic("stdlib sha3 variant is for SHAKE parameter sets")
	}
	s := v.p.NewStatePub(v.pub.seed)
	s.F.hash = func(out, in []byte) { stdShake(out, in) }
	s.H.hash = func(out, in []byte) { stdShake(out, in) }
	s.T.hash = &stdT{h: stdsha3.NewSHAKE256()}
	return &s
}

func stdShake(out, in []byte) {
	h := stdsha3.NewSHAKE256()
	_, _ = h.Write(in)
	_, _ = h.Read(out)
}

type stdT struct{ h *stdsha3.SHAKE }

func (t *stdT) Reset()                      { t.h.Reset() }
func (t *stdT) Write(p []byte) (int, error) { return t.h.Write(p) }
func (t *stdT) Final(out []byte)            { _, _ = t.h.Read(out) }
