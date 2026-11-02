package phonegate

import (
	"crypto/sha256"
	"testing"

	"github.com/mrwiora/tpm2-kira/core/attest"
)

func replay(chain []byte) []byte {
	cur := make([]byte, sha256.Size)
	for off := 0; off < len(chain); off += sha256.Size {
		d := sha256.New()
		d.Write(cur)
		d.Write(chain[off : off+sha256.Size])
		cur = d.Sum(nil)
	}
	return cur
}

// Real firmware's logs: the digests come out in the log's order, they replay, and the
// verifier reads the state from them with no other word of the machine's. Taken on
// OVMF: one with Secure Boot on (signed UKI), one in Setup Mode.
func TestPCR7ChainOfRealLogs(t *testing.T) {
	for path, want := range map[string]string{
		"../admin/testdata/arch-uki-eventlog.bin":      attest.SecureBootOn,
		"../admin/testdata/debian13-grub-eventlog.bin": attest.SecureBootSetupMode,
	} {
		chain := PCR7Chain(path, attest.AlgSHA256)
		if len(chain) == 0 || len(chain)%sha256.Size != 0 {
			t.Fatalf("%s: chain of %d bytes", path, len(chain))
		}
		got := attest.EstablishSecureBoot(attest.AlgSHA256, replay(chain), chain)
		t.Logf("%s: %d events, %+v", path, len(chain)/sha256.Size, got)
		if got.State != want {
			t.Errorf("%s: %+v, want %s", path, got, want)
		}
	}
	if chain := PCR7Chain("no such file", attest.AlgSHA256); chain != nil {
		t.Errorf("no log: %x", chain)
	}
}
