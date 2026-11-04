//go:build integration

package admin

import (
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"

	"github.com/google/go-tpm/tpm2"
)

// The boot settings: written with the signing key, read by anyone, all off
// without the index; switching debug off removes the index, and only the
// signing key's holder can write it.
func TestBootSettingsOnSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	tpmDev, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := nvslot.ReadBootSettings(tpmDev); err != nil || s.Debug {
		t.Fatalf("no index is all off: %+v %v", s, err)
	}
	key := newKey(t)
	if err := nvslot.WriteBootSettings(tpmDev, nvslot.BootSettings{Debug: true}, key); err != nil {
		t.Fatal(err)
	}
	if s, err := nvslot.ReadBootSettings(tpmDev); err != nil || !s.Debug {
		t.Fatalf("debug on: %+v %v", s, err)
	}
	tpmDev.Close()
	if !nvslot.BootDebug(sock) {
		t.Fatal("BootDebug does not see the switch")
	}

	// Another key cannot write it: the index's write policy names the key
	// that wrote it (PolicySigned).
	tpmDev, _ = tpmdev.Open(sock)
	defer tpmDev.Close()
	data, _ := tpmdev.ReadFromNVRAM(tpmDev, nvslot.BootSettingsIndex)
	pub, _ := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(nvslot.BootSettingsIndex)}.Execute(tpmDev)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(nvslot.BootSettingsIndex), Name: pub.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: []byte{1, 0}},
	}).Execute(tpmDev); err == nil {
		t.Fatal("the owner wrote the boot settings without the signing key")
	}
	if again, _ := tpmdev.ReadFromNVRAM(tpmDev, nvslot.BootSettingsIndex); string(again) != string(data) {
		t.Fatal("the boot settings changed")
	}
	if role := kiraIndexRole(nvslot.BootSettingsIndex); role == "" {
		t.Fatal("slot list does not know the index")
	}

	// Off removes it.
	if err := nvslot.WriteBootSettings(tpmDev, nvslot.BootSettings{}, key); err != nil {
		t.Fatal(err)
	}
	if tpmdev.NVRAMIndexExists(tpmDev, nvslot.BootSettingsIndex) {
		t.Fatal("debug off left the index")
	}

	// 'slot delete' without an index removes it with everything else.
	if err := nvslot.WriteBootSettings(tpmDev, nvslot.BootSettings{Debug: true}, key); err != nil {
		t.Fatal(err)
	}
	if got := kiraLeftovers(tpmDev, false); len(got) != 1 || got[0] != nvslot.BootSettingsIndex {
		t.Fatalf("leftovers: %x", got)
	}
}

func TestParseBootSettings(t *testing.T) {
	for in, ok := range map[string]bool{"\x01\x00": true, "\x01\x01": true, "\x02\x01": false, "\x01\x03": false, "\x01": false} {
		if _, err := nvslot.ParseBootSettings([]byte(in)); (err == nil) != ok {
			t.Errorf("%x: %v", in, err)
		}
	}
	if b := (nvslot.BootSettings{Debug: true}).Marshal(); string(b) != "\x01\x01" {
		t.Fatalf("%x", b)
	}
}
