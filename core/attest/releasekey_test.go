package attest

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestReleaseKeyPolicyExtendsTheSlotPolicy(t *testing.T) {
	name := append([]byte{0, 0x0b}, bytes.Repeat([]byte{7}, 32)...)
	ref := bytes.Repeat([]byte{9}, 16)
	slot, err := SlotPolicyDigest(name, ref, tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(slot)
	h.Write([]byte{0, 0, 0x01, 0x6c, 0, 0, 0x01, 0x47})
	got, err := ReleaseKeyPolicy(name, ref, tpm2.TPMAlgSHA256)
	if err != nil || !bytes.Equal(got, h.Sum(nil)) {
		t.Fatalf("%x %v", got, err)
	}
	if other, _ := ReleaseKeyPolicy(name, bytes.Repeat([]byte{8}, 16), tpm2.TPMAlgSHA256); bytes.Equal(got, other) {
		t.Fatal("different slot policies give the same release policy")
	}
	tmpl := ReleaseKeyTemplate(got)
	a := tmpl.ObjectAttributes
	if !a.AdminWithPolicy || a.UserWithAuth || a.Decrypt || a.Restricted || !a.FixedTPM || !a.FixedParent {
		t.Fatalf("attributes %+v", a)
	}
}
