package main

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// signer is a sign function bound to an already-unpacked private key.
// It writes the signature into sig (len >= sigSize) and returns the slice.
type signer func(msg, ctx, sig []byte) []byte

// verifier is a verify function bound to an already-unpacked public key.
type verifier func(msg, ctx, sig []byte) bool

// alg abstracts one parameter set over the two CIRCL packages (mldsa*, slhdsa).
type alg struct {
	name    string
	family  string
	seedLen int
	pkSize  int
	skSize  int
	sigSize int

	// keygen derives (pk, sk) packed bytes from the contract seed.
	keygen func(seed []byte) (pk, sk []byte)
	// newSigner unpacks sk once and returns a bound signer (this is the
	// "expensive" step for ML-DSA: ExpandA + NTTs of s1, s2, t0).
	newSigner func(sk []byte) signer
	// newVerifier unpacks pk once and returns a bound verifier.
	newVerifier func(pk []byte) verifier
}

var algs = buildAlgs()

func algByName(name string) *alg {
	for _, a := range algs {
		if a.name == name {
			return a
		}
	}
	return nil
}

func buildAlgs() []*alg {
	out := []*alg{
		{
			name: "ML-DSA-44", family: "ml-dsa", seedLen: mldsa44.SeedSize,
			pkSize: mldsa44.PublicKeySize, skSize: mldsa44.PrivateKeySize, sigSize: mldsa44.SignatureSize,
			keygen: func(seed []byte) ([]byte, []byte) {
				var s [mldsa44.SeedSize]byte
				copy(s[:], seed)
				pk, sk := mldsa44.NewKeyFromSeed(&s)
				var pkb [mldsa44.PublicKeySize]byte
				var skb [mldsa44.PrivateKeySize]byte
				pk.Pack(&pkb)
				sk.Pack(&skb)
				return pkb[:], skb[:]
			},
			newSigner: func(skb []byte) signer {
				var sk mldsa44.PrivateKey
				if err := sk.UnmarshalBinary(skb); err != nil {
					panic(err)
				}
				return func(msg, ctx, sig []byte) []byte {
					if err := mldsa44.SignTo(&sk, msg, ctx, false, sig); err != nil {
						panic(err)
					}
					return sig[:mldsa44.SignatureSize]
				}
			},
			newVerifier: func(pkb []byte) verifier {
				var pk mldsa44.PublicKey
				if err := pk.UnmarshalBinary(pkb); err != nil {
					panic(err)
				}
				return func(msg, ctx, sig []byte) bool { return mldsa44.Verify(&pk, msg, ctx, sig) }
			},
		},
		{
			name: "ML-DSA-65", family: "ml-dsa", seedLen: mldsa65.SeedSize,
			pkSize: mldsa65.PublicKeySize, skSize: mldsa65.PrivateKeySize, sigSize: mldsa65.SignatureSize,
			keygen: func(seed []byte) ([]byte, []byte) {
				var s [mldsa65.SeedSize]byte
				copy(s[:], seed)
				pk, sk := mldsa65.NewKeyFromSeed(&s)
				var pkb [mldsa65.PublicKeySize]byte
				var skb [mldsa65.PrivateKeySize]byte
				pk.Pack(&pkb)
				sk.Pack(&skb)
				return pkb[:], skb[:]
			},
			newSigner: func(skb []byte) signer {
				var sk mldsa65.PrivateKey
				if err := sk.UnmarshalBinary(skb); err != nil {
					panic(err)
				}
				return func(msg, ctx, sig []byte) []byte {
					if err := mldsa65.SignTo(&sk, msg, ctx, false, sig); err != nil {
						panic(err)
					}
					return sig[:mldsa65.SignatureSize]
				}
			},
			newVerifier: func(pkb []byte) verifier {
				var pk mldsa65.PublicKey
				if err := pk.UnmarshalBinary(pkb); err != nil {
					panic(err)
				}
				return func(msg, ctx, sig []byte) bool { return mldsa65.Verify(&pk, msg, ctx, sig) }
			},
		},
		{
			name: "ML-DSA-87", family: "ml-dsa", seedLen: mldsa87.SeedSize,
			pkSize: mldsa87.PublicKeySize, skSize: mldsa87.PrivateKeySize, sigSize: mldsa87.SignatureSize,
			keygen: func(seed []byte) ([]byte, []byte) {
				var s [mldsa87.SeedSize]byte
				copy(s[:], seed)
				pk, sk := mldsa87.NewKeyFromSeed(&s)
				var pkb [mldsa87.PublicKeySize]byte
				var skb [mldsa87.PrivateKeySize]byte
				pk.Pack(&pkb)
				sk.Pack(&skb)
				return pkb[:], skb[:]
			},
			newSigner: func(skb []byte) signer {
				var sk mldsa87.PrivateKey
				if err := sk.UnmarshalBinary(skb); err != nil {
					panic(err)
				}
				return func(msg, ctx, sig []byte) []byte {
					if err := mldsa87.SignTo(&sk, msg, ctx, false, sig); err != nil {
						panic(err)
					}
					return sig[:mldsa87.SignatureSize]
				}
			},
			newVerifier: func(pkb []byte) verifier {
				var pk mldsa87.PublicKey
				if err := pk.UnmarshalBinary(pkb); err != nil {
					panic(err)
				}
				return func(msg, ctx, sig []byte) bool { return mldsa87.Verify(&pk, msg, ctx, sig) }
			},
		},
	}

	for _, h := range []string{"SHA2", "SHAKE"} {
		for _, n := range []int{128, 192, 256} {
			for _, v := range []string{"s", "f"} {
				name := fmt.Sprintf("SLH-DSA-%s-%d%s", h, n, v)
				id, err := slhdsa.IDByName(name)
				if err != nil {
					panic(err)
				}
				out = append(out, slhAlg(name, id, n/8))
			}
		}
	}
	return out
}

func slhAlg(name string, id slhdsa.ID, n int) *alg {
	sch := id.Scheme()
	return &alg{
		name: name, family: "slh-dsa", seedLen: 3 * n,
		pkSize: sch.PublicKeySize(), skSize: sch.PrivateKeySize(), sigSize: sch.SignatureSize(),
		keygen: func(seed []byte) ([]byte, []byte) {
			// GenerateKey reads SK.seed, SK.prf, PK.seed (n bytes each) in that
			// order from the reader, which is exactly the contract seed layout.
			pub, priv, err := slhdsa.GenerateKey(bytes.NewReader(seed), id)
			if err != nil {
				panic(err)
			}
			pkb, err := pub.MarshalBinary()
			if err != nil {
				panic(err)
			}
			skb, err := priv.MarshalBinary()
			if err != nil {
				panic(err)
			}
			return pkb, skb
		},
		newSigner: func(skb []byte) signer {
			priv := slhdsa.PrivateKey{ID: id}
			if err := priv.UnmarshalBinary(skb); err != nil {
				panic(err)
			}
			return func(msg, ctx, sig []byte) []byte {
				s, err := slhdsa.SignDeterministic(&priv, slhdsa.NewMessage(msg), ctx)
				if err != nil {
					panic(err)
				}
				return s
			}
		},
		newVerifier: func(pkb []byte) verifier {
			pub := slhdsa.PublicKey{ID: id}
			if err := pub.UnmarshalBinary(pkb); err != nil {
				panic(err)
			}
			return func(msg, ctx, sig []byte) bool { return slhdsa.Verify(&pub, slhdsa.NewMessage(msg), sig, ctx) }
		},
	}
}
