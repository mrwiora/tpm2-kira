//go:build integration

package cmd

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// The boot settings: written with the signing key, read by anyone, all off
// without the index; switching debug off removes the index, and only the
// signing key's holder can write it.
func TestBootSettingsOnSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	tpmDev, err := OpenTPM(sock)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := ReadBootSettings(tpmDev); err != nil || s.Debug {
		t.Fatalf("no index is all off: %+v %v", s, err)
	}
	key := newKey(t)
	if err := WriteBootSettings(tpmDev, BootSettings{Debug: true}, key); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadBootSettings(tpmDev); err != nil || !s.Debug {
		t.Fatalf("debug on: %+v %v", s, err)
	}
	tpmDev.Close()
	if !BootDebug(sock) {
		t.Fatal("BootDebug does not see the switch")
	}

	// Another key cannot write it: the index's write policy names the key
	// that wrote it (PolicySigned).
	tpmDev, _ = OpenTPM(sock)
	defer tpmDev.Close()
	data, _ := ReadFromNVRAM(tpmDev, BootSettingsIndex)
	pub, _ := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(BootSettingsIndex)}.Execute(tpmDev)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(BootSettingsIndex), Name: pub.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: []byte{1, 0}},
	}).Execute(tpmDev); err == nil {
		t.Fatal("the owner wrote the boot settings without the signing key")
	}
	if again, _ := ReadFromNVRAM(tpmDev, BootSettingsIndex); string(again) != string(data) {
		t.Fatal("the boot settings changed")
	}
	if role := kiraIndexRole(BootSettingsIndex); role == "" {
		t.Fatal("nvram list does not know the index")
	}

	// Off removes it.
	if err := WriteBootSettings(tpmDev, BootSettings{}, key); err != nil {
		t.Fatal(err)
	}
	if NVRAMIndexExists(tpmDev, BootSettingsIndex) {
		t.Fatal("debug off left the index")
	}

	// 'nvram delete' without an index removes it with everything else.
	if err := WriteBootSettings(tpmDev, BootSettings{Debug: true}, key); err != nil {
		t.Fatal(err)
	}
	if got := kiraLeftovers(tpmDev, false); len(got) != 1 || got[0] != BootSettingsIndex {
		t.Fatalf("leftovers: %x", got)
	}
}

func TestParseBootSettings(t *testing.T) {
	for in, ok := range map[string]bool{"\x01\x00": true, "\x01\x01": true, "\x02\x01": false, "\x01\x03": false, "\x01": false} {
		if _, err := parseBootSettings([]byte(in)); (err == nil) != ok {
			t.Errorf("%x: %v", in, err)
		}
	}
	if b := (BootSettings{Debug: true}).marshal(); string(b) != "\x01\x01" {
		t.Fatalf("%x", b)
	}
}
