// stages.go -- pqc-signatures harness addition (NOT part of upstream CIRCL).
//
// Entry points that expose the canonical ML-DSA verify stages of FIPS 204
// (decode, mu, expandA, w_approx, hint_check) built from CIRCL's own internal
// functions, plus a few algorithmic alternatives per stage. Every alternative
// is checked by the harness against the stage's v0 output.

package mldsa87i

import (
	stdsha3 "crypto/sha3"
	"encoding/binary"
	"runtime"
	"sync"

	common "pqcbench/vendorcircl/dilithium"
	"pqcbench/vendorcircl/sha3"
)

// DecodedPk is pkDecode output: rho and t1 (plus the packed t1 for tr).
type DecodedPk struct {
	Rho [32]byte
	T1  VecK
}

// DecodedSig is sigDecode output: c~, z, h.
type DecodedSig struct {
	C    [CTildeSize]byte
	Z    VecL
	Hint VecK
}

// ---------------------------------------------------------------- decode

// DecodePk is pkDecode (FIPS 204 Alg 23): rho || t1.
func DecodePk(dst *DecodedPk, pk []byte) bool {
	if len(pk) != PublicKeySize {
		return false
	}
	copy(dst.Rho[:], pk[:32])
	dst.T1.UnpackT1(pk[32:])
	return true
}

// DecodeSig is sigDecode (Alg 27) as CIRCL does it: c~, z (with the
// ||z||inf < gamma1-beta check) and the strictly validated hint encoding.
func DecodeSig(dst *DecodedSig, sig []byte) bool {
	var s unpackedSignature
	if !s.Unpack(sig) {
		return false
	}
	dst.C, dst.Z, dst.Hint = s.c, s.z, s.hint
	return true
}

// DecodeSigFused unpacks z with the infinity-norm check fused into the
// bit-unpacking loop (CIRCL unpacks all of z first and then runs a second
// pass, Exceeds). Raw w in [0, 2*gamma1) encodes gamma1 - w, so
// |z_i| >= gamma1 - beta  <=>  w <= beta || w >= 2*gamma1 - beta.
func DecodeSigFused(dst *DecodedSig, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	copy(dst.C[:], sig[:CTildeSize])
	buf := sig[CTildeSize:]
	const lo, hi = Beta, 2*Gamma1 - Beta
	for l := 0; l < L; l++ {
		p := &dst.Z[l]
		b := buf[l*PolyLeGamma1Size : (l+1)*PolyLeGamma1Size]
		if Gamma1Bits == 17 {
			j := 0
			for i := 0; i < PolyLeGamma1Size; i += 9 {
				w0 := uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2]&0x3)<<16
				w1 := uint32(b[i+2]>>2) | uint32(b[i+3])<<6 | uint32(b[i+4]&0xf)<<14
				w2 := uint32(b[i+4]>>4) | uint32(b[i+5])<<4 | uint32(b[i+6]&0x3f)<<12
				w3 := uint32(b[i+6]>>6) | uint32(b[i+7])<<2 | uint32(b[i+8])<<10
				if w0 <= lo || w0 >= hi || w1 <= lo || w1 >= hi || w2 <= lo || w2 >= hi || w3 <= lo || w3 >= hi {
					return false
				}
				p[j], p[j+1], p[j+2], p[j+3] = centered(w0), centered(w1), centered(w2), centered(w3)
				j += 4
			}
		} else {
			j := 0
			for i := 0; i < PolyLeGamma1Size; i += 5 {
				w0 := uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2]&0xf)<<16
				w1 := uint32(b[i+2]>>4) | uint32(b[i+3])<<4 | uint32(b[i+4])<<12
				if w0 <= lo || w0 >= hi || w1 <= lo || w1 >= hi {
					return false
				}
				p[j], p[j+1] = centered(w0), centered(w1)
				j += 2
			}
		}
	}
	return dst.Hint.UnpackHint(buf[L*PolyLeGamma1Size:])
}

// centered maps raw w to gamma1 - w normalized into [0, q).
func centered(w uint32) uint32 {
	v := Gamma1 - w
	return v + (uint32(int32(v)>>31) & common.Q)
}

// ---------------------------------------------------------------- mu

// Tr computes tr = SHAKE256(pk, 64) with CIRCL's sha3.
func Tr(pk []byte, out *[TRSize]byte) {
	h := sha3.NewShake256()
	_, _ = h.Write(pk)
	_, _ = h.Read(out[:])
}

// Mu computes mu = SHAKE256(tr || 0 || len(ctx) || ctx || M, 64) (pure mode)
// with CIRCL's sha3, exactly as mldsa.Verify's message closure does.
func Mu(tr *[TRSize]byte, ctx, msg []byte, out *[64]byte) {
	h := sha3.NewShake256()
	_, _ = h.Write(tr[:])
	_, _ = h.Write([]byte{0, byte(len(ctx))})
	_, _ = h.Write(ctx)
	_, _ = h.Write(msg)
	_, _ = h.Read(out[:])
}

// MuStd is Mu with the Go standard library's crypto/sha3 (different Keccak
// implementation, assembly on amd64).
func MuStd(tr *[TRSize]byte, ctx, msg []byte, out *[64]byte) {
	h := stdsha3.NewSHAKE256()
	_, _ = h.Write(tr[:])
	_, _ = h.Write([]byte{0, byte(len(ctx))})
	_, _ = h.Write(ctx)
	_, _ = h.Write(msg)
	_, _ = h.Read(out[:])
}

// TrStd is Tr with crypto/sha3.
func TrStd(pk []byte, out *[TRSize]byte) {
	h := stdsha3.NewSHAKE256()
	_, _ = h.Write(pk)
	_, _ = h.Read(out[:])
}

// MuMidstate keeps a SHAKE256 state with tr || 0 || len(ctx) || ctx already
// absorbed; each message clones it and absorbs only M.
type MuMidstate struct{ st sha3.State }

func NewMuMidstate(tr *[TRSize]byte, ctx []byte) *MuMidstate {
	m := &MuMidstate{st: sha3.NewShake256()}
	_, _ = m.st.Write(tr[:])
	_, _ = m.st.Write([]byte{0, byte(len(ctx))})
	_, _ = m.st.Write(ctx)
	return m
}

func (m *MuMidstate) Mu(msg []byte, out *[64]byte) {
	h := m.st.Clone()
	_, _ = h.Write(msg)
	_, _ = h.Read(out[:])
}

// ---------------------------------------------------------------- expandA

// ExpandA is CIRCL's Mat.Derive (4-way AVX2 Keccak when available).
func ExpandA(m *Mat, rho *[32]byte) { m.Derive(rho) }

// ExpandAScalar derives the K*L polynomials one SHAKE128 stream at a time
// (CIRCL's non-x4 path, forced even when the x4 Keccak is available).
func ExpandAScalar(m *Mat, rho *[32]byte) {
	for i := uint16(0); i < K; i++ {
		for j := uint16(0); j < L; j++ {
			PolyDeriveUniform(&m[i][j], rho, (i<<8)+j)
		}
	}
}

// ExpandAParallelRows derives the K rows concurrently, one goroutine per row,
// each row using the x4 sampler for its L polynomials.
func ExpandAParallelRows(m *Mat, rho *[32]byte) {
	var wg sync.WaitGroup
	wg.Add(K)
	for i := 0; i < K; i++ {
		go func(i int) {
			defer wg.Done()
			deriveRow(&m[i], rho, uint16(i))
		}(i)
	}
	wg.Wait()
}

func deriveRow(row *VecL, rho *[32]byte, i uint16) {
	if !DeriveX4Available {
		for j := uint16(0); j < L; j++ {
			PolyDeriveUniform(&row[j], rho, (i<<8)+j)
		}
		return
	}
	for j := 0; j < L; j += 4 {
		var ps [4]*common.Poly
		var nonces [4]uint16
		for k := 0; k < 4; k++ {
			if j+k < L {
				ps[k] = &row[j+k]
				nonces[k] = (i << 8) + uint16(j+k)
			}
		}
		PolyDeriveUniformX4(ps, rho, nonces)
	}
}

// ExpandAThreads is the number of goroutines ExpandAParallelRows uses.
func ExpandAThreads() int { return min(K, runtime.GOMAXPROCS(0)) }

// MatCanonical serialises A^ as u32 LE coefficients in [0,q), row-major.
func MatCanonical(m *Mat) []byte {
	out := make([]byte, 0, K*L*common.N*4)
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			for _, c := range m[i][j] {
				out = binary.LittleEndian.AppendUint32(out, c%common.Q)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- w_approx

// T1Hat precomputes NTT(t1 * 2^d), the per-public-key part of w_approx.
func T1Hat(dst *VecK, t1 *VecK) {
	dst.MulBy2toD(t1)
	dst.NTT()
}

// WApprox computes w' = InvNTT(A^ o NTT(z) - NTT(c) o NTT(t1*2^d)) exactly as
// CIRCL's Verify does; the result is normalised to [0, q).
func WApprox(w *VecK, A *Mat, t1 *VecK, z *VecL, c *[CTildeSize]byte) {
	var t1h VecK
	T1Hat(&t1h, t1)
	WApproxCachedT1(w, A, &t1h, z, c)
}

// WApproxCachedT1 is WApprox with NTT(t1*2^d) supplied (cached per pk).
func WApproxCachedT1(w *VecK, A *Mat, t1h *VecK, z *VecL, c *[CTildeSize]byte) {
	var zh VecL
	var Az VecK
	var ch common.Poly
	zh = *z
	zh.NTT()
	for i := 0; i < K; i++ {
		PolyDotHat(&Az[i], &A[i], &zh)
	}
	PolyDeriveUniformBall(&ch, c[:])
	ch.NTT()
	for i := 0; i < K; i++ {
		w[i].MulHat(&t1h[i], &ch)
	}
	w.Sub(&Az, w)
	w.ReduceLe2Q()
	w.InvNTT()
	w.NormalizeAssumingLe2Q()
}

// WApproxParallelRows splits the K independent rows (dot product, c*t1 term,
// subtraction, inverse NTT) over goroutines; NTT(z) and NTT(c) are shared.
func WApproxParallelRows(w *VecK, A *Mat, t1 *VecK, z *VecL, c *[CTildeSize]byte) {
	var zh VecL
	var ch common.Poly
	zh = *z
	zh.NTT()
	PolyDeriveUniformBall(&ch, c[:])
	ch.NTT()
	var wg sync.WaitGroup
	wg.Add(K)
	for i := 0; i < K; i++ {
		go func(i int) {
			defer wg.Done()
			var az, t common.Poly
			PolyDotHat(&az, &A[i], &zh)
			t.MulBy2toD(&t1[i])
			t.NTT()
			t.MulHat(&t, &ch)
			w[i].Sub(&az, &t)
			w[i].ReduceLe2Q()
			w[i].InvNTT()
			w[i].NormalizeAssumingLe2Q()
		}(i)
	}
	wg.Wait()
}

// WThreads is the number of goroutines WApproxParallelRows uses.
func WThreads() int { return min(K, runtime.GOMAXPROCS(0)) }

// VecKCanonical serialises a VecK as u32 LE coefficients in [0,q).
func VecKCanonical(v *VecK) []byte {
	out := make([]byte, 0, K*common.N*4)
	for i := 0; i < K; i++ {
		for _, c := range v[i] {
			out = binary.LittleEndian.AppendUint32(out, c%common.Q)
		}
	}
	return out
}

// ---------------------------------------------------------------- hint_check

// HintCheck: ||z||inf < gamma1-beta, w1' = UseHint(h, w'), c~' = H(mu || w1Encode(w1'))
// and compare, CIRCL's way. w1Packed receives w1Encode(w1') (PolyW1Size*K bytes).
func HintCheck(w, hint *VecK, z *VecL, mu *[64]byte, c *[CTildeSize]byte, w1Packed []byte) bool {
	if z.Exceeds(Gamma1 - Beta) {
		return false
	}
	var w1 VecK
	w1.UseHint(w, hint)
	w1.PackW1(w1Packed)
	var cp [CTildeSize]byte
	h := sha3.NewShake256()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(w1Packed)
	_, _ = h.Read(cp[:])
	return *c == cp
}

// HintCheckStd is HintCheck hashing with the standard library's crypto/sha3.
func HintCheckStd(w, hint *VecK, z *VecL, mu *[64]byte, c *[CTildeSize]byte, w1Packed []byte) bool {
	if z.Exceeds(Gamma1 - Beta) {
		return false
	}
	var w1 VecK
	w1.UseHint(w, hint)
	w1.PackW1(w1Packed)
	var cp [CTildeSize]byte
	h := stdsha3.NewSHAKE256()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(w1Packed)
	_, _ = h.Read(cp[:])
	return *c == cp
}

// useHintScalar mirrors PolyUseHint for one coefficient (CIRCL's own scalar
// useHint() only handles gamma2 = (q-1)/32 and is unused for ML-DSA-44).
func useHintScalar(rp, hint uint32) uint32 {
	r0plusQ, r1 := decompose(rp)
	if hint == 0 {
		return r1
	}
	if Gamma2 == 261888 {
		if r0plusQ > common.Q {
			return (r1 + 1) & 15
		}
		return (r1 - 1) & 15
	}
	if r0plusQ > common.Q {
		if r1 == 43 {
			return 0
		}
		return r1 + 1
	}
	if r1 == 0 {
		return 43
	}
	return r1 - 1
}

// HintCheckFused computes UseHint coefficient by coefficient with the
// scalar decompose and packs w1 directly into the output buffer, without the
// intermediate decomposed vectors and w1 polynomials CIRCL materialises.
func HintCheckFused(w, hint *VecK, z *VecL, mu *[64]byte, c *[CTildeSize]byte, w1Packed []byte) bool {
	if z.Exceeds(Gamma1 - Beta) {
		return false
	}
	for i := 0; i < K; i++ {
		buf := w1Packed[i*PolyW1Size : (i+1)*PolyW1Size]
		if Gamma1Bits == 19 { // gamma2 = (q-1)/32: 4-bit w1 coefficients
			for j := 0; j < common.N; j += 2 {
				buf[j/2] = byte(useHintScalar(w[i][j], hint[i][j])) | byte(useHintScalar(w[i][j+1], hint[i][j+1]))<<4
			}
		} else { // gamma2 = (q-1)/88: 6-bit w1 coefficients
			k := 0
			for j := 0; j < common.N; j += 4 {
				a := byte(useHintScalar(w[i][j], hint[i][j]))
				b := byte(useHintScalar(w[i][j+1], hint[i][j+1]))
				cc := byte(useHintScalar(w[i][j+2], hint[i][j+2]))
				d := byte(useHintScalar(w[i][j+3], hint[i][j+3]))
				buf[k] = a | b<<6
				buf[k+1] = b>>2 | cc<<4
				buf[k+2] = cc>>4 | d<<2
				k += 3
			}
		}
	}
	var cp [CTildeSize]byte
	h := sha3.NewShake256()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(w1Packed)
	_, _ = h.Read(cp[:])
	return *c == cp
}
