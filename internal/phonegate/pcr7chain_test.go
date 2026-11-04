package phonegate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// The real logs' initrd events: a UKI's section in PCR 11, GRUB's command in PCR 8, each
// established from digests the phone makes itself, against the registers they replay to.
func TestInitrdEventsOfRealLogs(t *testing.T) {
	for _, c := range []struct {
		file string
		pcrs []int
		want []int
	}{
		{"arch-uki-eventlog.bin", []int{0, 2, 4, 7, 11}, []int{11, 4}},
		{"debian13-grub-eventlog.bin", []int{0, 2, 4, 7, 8, 9}, []int{9}},
	} {
		path := filepath.Join("..", "admin", "testdata", c.file)
		ev := InitrdEventsOf(path, attest.AlgSHA256)
		sel, err := attest.NewPCRSelection(attest.AlgSHA256, c.pcrs)
		if err != nil {
			t.Fatal(err)
		}
		var vals []attest.PCRValue
		for _, p := range c.pcrs {
			v := make([]byte, 32)
			switch p {
			case 8:
				v = replay(ev.PCR8Chain)
			case 11:
				v = replay(ev.PCR11Chain)
			}
			vals = append(vals, attest.PCRValue{Index: uint8(p), Digest: v})
		}
		got := attest.EstablishInitrd(sel, vals, ev)
		if got.State != attest.InitrdCovered || fmt.Sprint(got.PCRs) != fmt.Sprint(c.want) {
			t.Errorf("%s: %+v, command %q", c.file, got, ev.Command)
		}
	}
	if ev := InitrdEventsOf("no such file", attest.AlgSHA256); ev.PCR8Chain != nil || ev.PCR11Chain != nil || ev.Command != "" {
		t.Errorf("no log: %+v", ev)
	}
}

// A real machine's log, kept off the repository because it names the machine's firmware:
// KIRA_LOCAL_EVENTLOG is the absolute path of a directory with its "eventlog" and "pcr7-sha1", the register on the
// running system in hex (tpm2-trust's .local/eventlogs/). Skipped without it.
func TestLocalMachineLogPastTheOSSeparator(t *testing.T) {
	dir := os.Getenv("KIRA_LOCAL_EVENTLOG")
	if dir == "" {
		t.Skip("KIRA_LOCAL_EVENTLOG is not set")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pcr7-sha1"))
	if err != nil {
		t.Fatal(err)
	}
	pcr7, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got := attest.EstablishSecureBoot(attest.AlgSHA1, pcr7, PCR7Chain(filepath.Join(dir, "eventlog"), attest.AlgSHA1)); got.State != attest.SecureBootOn {
		t.Fatalf("%+v", got)
	}
}
