package slhdsa

import (
	"encoding/json"
	"testing"
	"unsafe"
)

// Sizes include fields only, not pointed-to objects or runtime stack frames.
func TestMemoryAuditLayout(t *testing.T) {
	data := map[string]uintptr{
		"base_hasher_bytes":   unsafe.Sizeof(baseHasher{}),
		"public_state_bytes":  unsafe.Sizeof(state{}),
		"private_state_bytes": unsafe.Sizeof(statePriv{}),
		"state_t_bytes":       unsafe.Sizeof(stateT{}),
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("MEMORY_AUDIT_LAYOUT " + string(b))
}

func TestMemoryAuditSetup(t *testing.T) {
	for _, id := range []ID{SHA2_128f, SHA2_128s, SHA2_192f, SHA2_192s, SHA2_256f, SHA2_256s, SHAKE_128f} {
		p := id.params()
		seed := make([]byte, p.n)
		pub := testing.AllocsPerRun(20, func() { s := p.NewStatePub(seed); s.Clear() })
		priv := testing.AllocsPerRun(20, func() { s := p.NewStatePriv(seed, seed); s.Clear() })
		b, err := json.Marshal(map[string]any{"parameter": id.String(), "public_setup_allocs": pub, "private_setup_allocs": priv})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("MEMORY_AUDIT_SETUP " + string(b))
	}
}
