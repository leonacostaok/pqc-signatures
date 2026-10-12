package slhdsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"hash"
	"testing"
)

func TestMemoryAuditPrefixCleanup(t *testing.T) {
	for _, h := range []hash.Hash{sha256.New(), sha512.New()} {
		prefix := bytes.Repeat([]byte{0x23}, h.BlockSize())
		cached := newSHA2Prefix(h, prefix)
		publicState := bytes.Clone(cached.saved)
		saved, sum := cached.saved, cached.sum[:]
		_, _ = cached.Write(bytes.Repeat([]byte{0xa5}, h.BlockSize()+17))
		cached.Final(make([]byte, h.Size()))
		cached.Clear()
		got, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil || !bytes.Equal(got, publicState) {
			t.Fatal("digest did not return to public-only state")
		}
		if !bytes.Equal(saved, make([]byte, len(saved))) || !bytes.Equal(sum, make([]byte, len(sum))) {
			t.Fatal("saved state or digest scratch was not cleared")
		}
	}
}

func TestMemoryAuditBaseCleanup(t *testing.T) {
	for _, h := range []hash.Hash{sha256.New(), sha512.New()} {
		input := bytes.Repeat([]byte{0x72}, h.BlockSize()+29)
		output := make([]byte, 32)
		b := baseHasher{input: input, output: output}
		b.initSHA2(h)
		publicState, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		b.Final()
		b.Clear()
		b.Clear()
		got, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil || !bytes.Equal(got, publicState) {
			t.Fatal("base digest retained message state")
		}
		if !bytes.Equal(input, make([]byte, len(input))) || !bytes.Equal(output, make([]byte, len(output))) {
			t.Fatal("base input, prefix or output remained")
		}
		if b.hash != nil || b.clearHash != nil || b.input != nil || b.output != nil {
			t.Fatal("base retained references")
		}
	}
}

func TestMemoryAuditTCleanup(t *testing.T) {
	for _, id := range []ID{SHA2_128f, SHA2_192f, SHA2_256f} {
		p := id.params()
		var s stateT
		arena := make([]byte, s.Size(p))
		cur := cursor(arena)
		s.Init(p, &cur, bytes.Repeat([]byte{0x43}, int(p.n)))
		cached := s.hash.(*sha2Prefix)
		publicState := bytes.Clone(cached.saved)
		s.Reset()
		s.WriteMessage(bytes.Repeat([]byte{0xa5}, 193))
		s.Final()
		s.Clear()
		s.Clear()
		got, err := cached.Hash.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil || !bytes.Equal(got, publicState) {
			t.Fatal("T digest retained message state")
		}
		if !bytes.Equal(arena, make([]byte, len(arena))) {
			t.Fatal("T arena retained input, prefix or output")
		}
		if s.hash != nil || s.clearHash != nil || s.input != nil || s.output != nil {
			t.Fatal("T retained references")
		}
	}
}
