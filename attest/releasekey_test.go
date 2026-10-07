package attest

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestReleaseKeyPolicyExtendsTheSlotPolicy(t *testing.T) {
	slot := bytes.Repeat([]byte{7}, 32)
	h := sha256.New()
	h.Write(slot)
	h.Write([]byte{0, 0, 0x01, 0x6c, 0, 0, 0x01, 0x47})
	if got := ReleaseKeyPolicy(slot); !bytes.Equal(got, h.Sum(nil)) {
		t.Fatalf("%x", got)
	}
	if bytes.Equal(ReleaseKeyPolicy(slot), ReleaseKeyPolicy(bytes.Repeat([]byte{8}, 32))) {
		t.Fatal("different slot policies give the same release policy")
	}
	tmpl := ReleaseKeyTemplate(ReleaseKeyPolicy(slot))
	a := tmpl.ObjectAttributes
	if !a.AdminWithPolicy || a.UserWithAuth || a.Decrypt || a.Restricted || !a.FixedTPM || !a.FixedParent {
		t.Fatalf("attributes %+v", a)
	}
}
