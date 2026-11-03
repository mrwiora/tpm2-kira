package measure_test

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	evlog "github.com/google/go-attestation/attest"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
)

// core's parsers against other firmware than ours: go-attestation's own test logs, real
// machines' and clouds', read from the module go.mod requires (attest/testdata, Apache
// 2.0, not copied: go.sum vouches for them, and any build that can build this package has
// them). core itself imports none of it (TestCoreHasNoDeviceDeps).
//
// For each log and bank: the digests the machine would send, from the machine's own code;
// the registers replayed from them, as there is no quote; core's reading, and
// go-attestation's of the same events.

// goAttestationLogs is the module's test logs, by name. No module: a failure, never a skip.
func goAttestationLogs(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/google/go-attestation").Output()
	if err != nil {
		t.Fatalf("the module with the logs: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "attest", "testdata")
}

const (
	goAttOn  = "on"
	goAttOff = "off"
)

// corpusRow is what is known of a log in a bank. goAtt: goAttOn, goAttOff, or a part of the
// error it gives. Where the two differ, why says why.
type corpusRow struct {
	file, bank string
	core       string
	goAtt      string
	initrd     string
	why        string
}

var corpus = []corpusRow{
	{"coreos_36_shielded_vm_no_secure_boot_eventlog", "sha256", attest.SecureBootOff, goAttOff, attest.InitrdCovered, ""},
	{"coreos_36_shielded_vm_no_secure_boot_eventlog", "sha1", attest.SecureBootOff, goAttOff, attest.InitrdCovered, ""},
	{"crypto_agile_eventlog", "sha256", attest.SecureBootOff, "SecureBoot data len is 0", attest.InitrdNotEstablished,
		"the variable absent, length 0: core reads off, go-attestation will not say. Neither says on"},
	{"crypto_agile_eventlog", "sha1", attest.SecureBootNotEstablished, "no digests present", attest.InitrdNotEstablished, "no such bank in the log"},
	{"ebs_event_missing_eventlog", "sha256", attest.SecureBootNotEstablished, "no digests present", attest.InitrdNotEstablished, "a SHA-1 log"},
	{"ebs_event_missing_eventlog", "sha1", attest.SecureBootOff, goAttOff, attest.InitrdNotEstablished, ""},
	{"option_rom_eventlog", "sha256", attest.SecureBootNotEstablished, "no digests present", attest.InitrdNotEstablished, "a SHA-1 log"},
	{"option_rom_eventlog", "sha1", attest.SecureBootOn, goAttOn, attest.InitrdNotEstablished, ""},
	{"sb_cert_eventlog", "sha256", attest.SecureBootOn, goAttOn, attest.InitrdNotEstablished, ""},
	{"sb_cert_eventlog", "sha1", attest.SecureBootOn, goAttOn, attest.InitrdNotEstablished, ""},
	{"short_no_action_eventlog", "sha256", attest.SecureBootNotEstablished, goAttOff, attest.InitrdNotEstablished,
		"nothing in PCR 7: go-attestation says disabled, with no error, though it says an error comes when the state cannot be determined"},
	{"short_no_action_eventlog", "sha1", attest.SecureBootNotEstablished, goAttOff, attest.InitrdNotEstablished, "as above"},
	{"ubuntu_2104_shielded_vm_no_secure_boot_eventlog", "sha256", attest.SecureBootOff, goAttOff, attest.InitrdNotEstablished, ""},
	{"ubuntu_2104_shielded_vm_no_secure_boot_eventlog", "sha1", attest.SecureBootOff, goAttOff, attest.InitrdNotEstablished, ""},
	{"windows_gcp_shielded_vm.json", "sha256", attest.SecureBootNotEstablished, "no digests present", attest.InitrdNotEstablished, "a SHA-1 log"},
	{"windows_gcp_shielded_vm.json", "sha1", attest.SecureBootOn, goAttOn, attest.InitrdNotEstablished, ""},
}

// The real PCR 7 of two logs, from go-attestation's secureboot_test.go (SHA-1), and the
// windows dump's own: the replay of the machine's chain must come to what the TPM held.
var quotedPCR7 = map[string]string{
	"sb_cert_eventlog":    "RahiHTSlffKy5/FMkrmayN59WAU=",
	"option_rom_eventlog": "IN59+6a838ytrX4+sJnJHU2Xxa0=",
}

type bank struct {
	alg  uint16
	h    evlog.HashAlg
	c    crypto.Hash
	make func() hash.Hash
}

var banks = map[string]bank{
	"sha256": {attest.AlgSHA256, evlog.HashSHA256, crypto.SHA256, sha256.New},
	"sha1":   {attest.AlgSHA1, evlog.HashSHA1, crypto.SHA1, sha1.New},
}

func (b bank) sum(data []byte) []byte {
	h := b.make()
	h.Write(data)
	return h.Sum(nil)
}

// logFile is the raw log of a test file, on disk as the machine's code wants it.
func logFile(t *testing.T, dir, name string) (path string, raw []byte, dump []evlog.PCR) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(name) != ".json" {
		return filepath.Join(dir, name), raw, nil
	}
	var d struct {
		Log struct {
			PCRs []evlog.PCR
			Raw  []byte
		}
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, d.Log.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, d.Log.Raw, d.Log.PCRs
}

// goAttSays is go-attestation's reading in the corpus's words.
func goAttSays(events []evlog.Event) string {
	sb, err := evlog.ParseSecurebootState(events)
	switch {
	case err != nil:
		return err.Error()
	case sb.Enabled:
		return goAttOn
	}
	return goAttOff
}

func replayedPCR(events []evlog.Event, b bank, pcr int) []byte {
	var chain []byte
	for _, e := range events {
		if e.Index == pcr && uint32(e.Type) != 3 && len(e.Digest) > 0 {
			chain = append(chain, e.Digest...)
		}
	}
	return attesttest.ReplayChain(b.alg, chain)
}

func TestCoreAgainstGoAttestationLogs(t *testing.T) {
	dir := goAttestationLogs(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Every file has its rows: a log the module adds, or takes away, is seen here.
	var want, got []string
	for _, r := range corpus {
		if !slices.Contains(want, r.file) {
			want = append(want, r.file)
		}
	}
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Fatalf("the module's logs: %v; the table's: %v", got, want)
	}
	enabled := 0
	for _, r := range corpus {
		t.Run(r.file+"/"+r.bank, func(t *testing.T) {
			b := banks[r.bank]
			path, raw, dump := logFile(t, dir, r.file)
			log, err := evlog.ParseEventLog(raw)
			if err != nil {
				t.Fatal(err)
			}
			events := log.Events(b.h)
			chain := phonegate.PCR7Chain(path, b.alg)
			pcr7 := attesttest.ReplayChain(b.alg, chain)
			core := attest.EstablishSecureBoot(b.alg, pcr7, chain)
			if len(chain) == 0 { // no such bank: nothing to replay
				core = attest.EstablishSecureBoot(b.alg, make([]byte, b.c.Size()), nil)
			}
			goAtt := goAttSays(events)
			values := []attest.PCRValue{}
			for _, i := range []uint8{7, 8, 9, 11} {
				values = append(values, attest.PCRValue{Index: i, Digest: replayedPCR(events, b, int(i))})
			}
			initrd := attest.EstablishInitrd(attest.PCRSelection{Alg: b.alg, Indices: []uint8{7, 8, 9, 11}}, values, phonegate.InitrdEventsOf(path, b.alg))
			t.Logf("core: %s; go-attestation: %s; initrd: %s %s; %s", core, goAtt, initrd.State, initrd.Detail, r.why)

			if core.State != r.core {
				t.Errorf("core: %s, want %s", core, r.core)
			}
			if r.goAtt == goAttOn || r.goAtt == goAttOff {
				if goAtt != r.goAtt {
					t.Errorf("go-attestation: %s, want %s", goAtt, r.goAtt)
				}
			} else if !strings.Contains(goAtt, r.goAtt) {
				t.Errorf("go-attestation: %s, want an error with %q", goAtt, r.goAtt)
			}
			if initrd.State != r.initrd {
				t.Errorf("initrd: %+v, want %s", initrd, r.initrd)
			}
			// What must agree: neither says on where the other does not.
			if (core.State == attest.SecureBootOn) != (goAtt == goAttOn) {
				t.Errorf("Secure Boot: core %s, go-attestation %s", core, goAtt)
			}
			if core.State == attest.SecureBootOn {
				enabled++
			}
			if len(chain) == 0 {
				return
			}
			// The same reading from the events go-attestation verified itself, and the
			// register's replay is what its own replay takes. A wrong register is refused
			// by both.
			pcr := evlog.PCR{Index: 7, Digest: pcr7, DigestAlg: b.c}
			verified, err := log.Verify([]evlog.PCR{pcr})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			// An error's words name an event by number, which only the verified have.
			if v := goAttSays(verified); (v == goAttOn) != (goAtt == goAttOn) || (v == goAttOff) != (goAtt == goAttOff) {
				t.Errorf("go-attestation, verified events: %s; unverified: %s", v, goAtt)
			}
			wrong := bytes.Clone(pcr7)
			wrong[0] ^= 1
			if _, err := log.Verify([]evlog.PCR{{Index: 7, Digest: wrong, DigestAlg: b.c}}); err == nil {
				t.Error("Verify took a wrong register")
			}
			if f := attest.EstablishSecureBoot(b.alg, wrong, chain); f.State != attest.SecureBootNotEstablished {
				t.Errorf("core took a wrong register: %s", f)
			}
			// Where the TPM's own value is known, the replay comes to it.
			if r.bank == "sha1" {
				if s, ok := quotedPCR7[r.file]; ok {
					real, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(pcr7, real) {
						t.Errorf("the replay: %x, the TPM held %x", pcr7, real)
					}
				}
				for _, p := range dump {
					if p.Index == 7 && p.DigestAlg == b.c && !bytes.Equal(pcr7, p.Digest) {
						t.Errorf("the replay: %x, the dump's register %x", pcr7, p.Digest)
					}
				}
			}
		})
	}
	// How much this corpus can say: the on of three logs, of two banks in one.
	if enabled != 4 {
		t.Errorf("%d rows with Secure Boot on, want 4", enabled)
	}
}

// The firmware behaviour go-attestation handles or refuses, each done to the real logs
// that say on, as a firmware would have done it: the register is that chain's own, as a
// TPM would hold. None may read on in core. Where go-attestation differs, it is said in
// the log of the test, not held: that is its behaviour, not ours.
func TestFirmwareOddityIsNotOn(t *testing.T) {
	dir := goAttestationLogs(t)
	const (
		evSeparator = 0x00000004
		evVariable  = 0x80000001
		evAction    = 0x80000007
	)
	// isSecureBoot finds the event: its variable name, in UTF-16, after the UEFI header.
	isSecureBoot := func(e evlog.Event) bool {
		name := attest.UEFIVariableData("SecureBoot", nil)
		return uint32(e.Type) == evVariable && bytes.HasPrefix(e.Data, name[:16]) && bytes.Contains(e.Data, name[32:])
	}
	index := func(events []evlog.Event, f func(evlog.Event) bool) int {
		return slices.IndexFunc(events, func(e evlog.Event) bool { return e.Index == 7 && f(e) })
	}
	separator := func(e evlog.Event) bool { return uint32(e.Type) == evSeparator }

	cases := []struct {
		name string
		do   func(events []evlog.Event, b bank) []evlog.Event
	}{
		{"UEFI Debug Mode first", func(ev []evlog.Event, b bank) []evlog.Event {
			data := []byte("UEFI Debug Mode")
			return slices.Insert(ev, index(ev, isSecureBoot), evlog.Event{Index: 7, Type: evlog.EventType(evAction), Data: data, Digest: b.sum(data)})
		}},
		{"the error separator", func(ev []evlog.Event, b bank) []evlog.Event {
			i := index(ev, separator)
			ev[i].Data, ev[i].Digest = []byte{0xff, 0xff, 0xff, 0xff}, b.sum([]byte{0xff, 0xff, 0xff, 0xff})
			return ev
		}},
		{"no separator", func(ev []evlog.Event, b bank) []evlog.Event {
			return slices.Delete(ev, index(ev, separator), index(ev, separator)+1)
		}},
		{"SecureBoot twice", func(ev []evlog.Event, b bank) []evlog.Event {
			i := index(ev, isSecureBoot)
			return slices.Insert(ev, i, ev[i])
		}},
		{"a digest over the variable's data alone", func(ev []evlog.Event, b bank) []evlog.Event {
			ev[index(ev, isSecureBoot)].Digest = b.sum([]byte{1})
			return ev
		}},
		{"SecureBoot after the separator", func(ev []evlog.Event, b bank) []evlog.Event {
			i, s := index(ev, isSecureBoot), index(ev, separator)
			e := ev[i]
			ev = slices.Delete(ev, i, i+1)
			return slices.Insert(ev, s, e)
		}},
		{"SecureBoot = 2", func(ev []evlog.Event, b bank) []evlog.Event {
			i := index(ev, isSecureBoot)
			data := attest.UEFIVariableData("SecureBoot", []byte{2})
			ev[i].Data, ev[i].Digest = data, b.sum(data)
			return ev
		}},
		{"SecureBoot = 1 and 0", func(ev []evlog.Event, b bank) []evlog.Event {
			i := index(ev, isSecureBoot)
			data := attest.UEFIVariableData("SecureBoot", []byte{0})
			return slices.Insert(ev, i+1, evlog.Event{Index: 7, Type: evlog.EventType(evVariable), Data: data, Digest: b.sum(data)})
		}},
	}
	for _, r := range corpus {
		if r.core != attest.SecureBootOn {
			continue
		}
		b := banks[r.bank]
		_, raw, _ := logFile(t, dir, r.file)
		log, err := evlog.ParseEventLog(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			t.Run(r.file+"/"+r.bank+"/"+c.name, func(t *testing.T) {
				events := c.do(slices.Clone(log.Events(b.h)), b)
				var chain []byte
				for _, e := range events {
					if e.Index == 7 {
						chain = append(chain, e.Digest...)
					}
				}
				f := attest.EstablishSecureBoot(b.alg, attesttest.ReplayChain(b.alg, chain), chain)
				t.Logf("core: %s; go-attestation: %s", f, goAttSays(events))
				if f.State != attest.SecureBootNotEstablished {
					t.Errorf("core: %s", f)
				}
			})
		}
		// A key not used shows in no digest: core reads on, go-attestation refuses. Held,
		// so that it is known: core's doc says why it does not look.
		t.Run(r.file+"/"+r.bank+"/no authority event", func(t *testing.T) {
			var events []evlog.Event
			for _, e := range log.Events(b.h) {
				if uint32(e.Type) != 0x800000e0 {
					events = append(events, e)
				}
			}
			var chain []byte
			for _, e := range events {
				if e.Index == 7 {
					chain = append(chain, e.Digest...)
				}
			}
			f := attest.EstablishSecureBoot(b.alg, attesttest.ReplayChain(b.alg, chain), chain)
			g := goAttSays(events)
			t.Logf("core: %s; go-attestation: %s", f, g)
			if f.State != attest.SecureBootOn || !strings.Contains(g, "no key was used") {
				t.Errorf("core: %s; go-attestation: %s", f, g)
			}
		})
	}
}

// The boot of our own VM's log, beside the others'. core's Setup Mode is go-attestation's
// off: it has no such state.
func TestCoreAgainstOurOwnLog(t *testing.T) {
	path := "testdata/debian13-grub-eventlog.bin"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	log, err := evlog.ParseEventLog(raw)
	if err != nil {
		t.Fatal(err)
	}
	b := banks["sha256"]
	chain := phonegate.PCR7Chain(path, b.alg)
	f := attest.EstablishSecureBoot(b.alg, attesttest.ReplayChain(b.alg, chain), chain)
	g := goAttSays(log.Events(b.h))
	t.Logf("core: %s; go-attestation: %s", f, g)
	if (f.State == attest.SecureBootOn) != (g == goAttOn) {
		t.Errorf("core %s, go-attestation %s", f, g)
	}
}
