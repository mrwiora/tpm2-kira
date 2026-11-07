//go:build integration

package admin

import (
	"bufio"
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"

	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/prompt"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// A generation index of another shape, read_stclear and without no_da.
var oldGeneration = tpm2.TPMANV{OwnerRead: true, AuthRead: true, PolicyWrite: true, ReadSTClear: true, NT: tpm2.TPMNTOrdinary}

// foreignTPM is a software TPM whose test keeps it open; its control.conf is
// the test's, and no terminal is there until the test gives one.
func foreignTPM(t *testing.T) (string, transport.TPMCloser) {
	t.Helper()
	sock := startSWTPM(t)
	t.Setenv("TPM2_KIRA_CONTROL_CONF", filepath.Join(t.TempDir(), "control.conf"))
	answers(t, "")
	oldList := listLuksDevices
	t.Cleanup(func() { listLuksDevices = oldList })
	listLuksDevices = func() ([]string, error) { return nil, nil }
	tpm, err := tpmdev.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tpm.Close() })
	return sock, tpm
}

// answers is the terminal's lines; "" is no terminal.
func answers(t *testing.T, lines string) {
	t.Helper()
	old := setupTerminal
	t.Cleanup(func() { setupTerminal = old })
	if lines == "" {
		setupTerminal = func() *bufio.Reader { return nil }
		return
	}
	r := bufio.NewReader(strings.NewReader(lines))
	setupTerminal = func() *bufio.Reader { return r }
}

// defineAt defines an index with attrs at index.
func defineAt(t *testing.T, tpm transport.TPM, index uint32, attrs tpm2.TPMANV) {
	t.Helper()
	pub := tpm2.TPMSNVPublic{NVIndex: tpm2.TPMHandle(index), NameAlg: tpm2.TPMAlgSHA256, Attributes: attrs,
		AuthPolicy: tpm2.TPM2BDigest{Buffer: bytes.Repeat([]byte{7}, 32)}, DataSize: 8}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(pub)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
}

// slot delete meets a generation index of another shape: --yes and no terminal
// leave it, shown, and name --force; a terminal asks, No by default; --force
// takes it; and a slot sealed afterwards is a slot.
func TestForeignGenerationIndexSlotDelete(t *testing.T) {
	const slot = uint32(nvslot.NVRAMSlotStart)
	gen := nvslot.GenerationIndex(slot)
	shown := []string{"0x01803810", "read_stclear", "no_da", "SHA-256", "8 bytes", "yes, 32 bytes", "generation index of slot #0", "another program"}
	for _, tc := range []struct {
		name       string
		yes, force bool
		lines      string
		gone       bool
	}{
		{name: "no terminal"},
		{name: "--yes", yes: true},
		{name: "--yes on a terminal never asks", yes: true, lines: "y\n"},
		{name: "answered no", lines: "n\n"},
		{name: "Enter is no", lines: "\n"},
		{name: "answered yes", lines: "y\n", gone: true},
		{name: "--force", force: true, gone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, tpm := foreignTPM(t)
			defineAt(t, tpm, gen, oldGeneration)
			answers(t, tc.lines)
			var err error
			out := captureStdout(t, func() { err = NVRAMDeleteCommand(sock, slot, tc.yes, tc.force, false) })
			for _, want := range shown {
				if !strings.Contains(out, want) {
					t.Errorf("not shown: %q in\n%s", want, out)
				}
			}
			if asked := strings.Contains(out, "[y/N]"); asked != (tc.lines != "" && !tc.yes) {
				t.Errorf("asked %v:\n%s", asked, out)
			}
			if there := tpmdev.NVRAMIndexExists(tpm, gen); there == tc.gone {
				t.Fatalf("the index there: %v; %v\n%s", there, err, out)
			}
			if tc.gone {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !errors.Is(err, persist.ErrNotOurs) || !strings.Contains(err.Error(), "slot delete --nvram 0 --force") {
				t.Fatalf("the refusal: %v", err)
			}
			if !tc.gone {
				return
			}
			sealRealSlot(t, sock, slot)
			if nvslot.ForeignAt(tpm, gen) != nil || !nvslot.SlotExists(tpm, slot) {
				t.Fatal("a slot sealed afterwards has no generation index of tpm2-kira's")
			}
			if err := NVRAMDeleteCommand(sock, slot, false, false, false); err != nil {
				t.Fatalf("the sealed slot, without asking: %v", err)
			}
		})
	}
}

// The other places go the same way: a record counter of another shape in a
// slot, and alone, by its own handle, and the boot settings.
func TestForeignAtEveryOwnPlace(t *testing.T) {
	counter := nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart + 2)
	ordinary := tpm2.TPMANV{OwnerRead: true, OwnerWrite: true, NT: tpm2.TPMNTOrdinary}
	for _, tc := range []struct {
		name  string
		index uint32
		arg   uint32
		flag  string
	}{
		{"a slot's counter", counter, nvslot.NVRAMSlotStart + 2, "--nvram 2 --force"},
		{"a counter by its handle", counter, counter, "--nvram 0x01803822 --force"},
		{"the boot settings by its handle", nvslot.BootSettingsIndex, nvslot.BootSettingsIndex, "--nvram 0x01803000 --force"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, tpm := foreignTPM(t)
			defineAt(t, tpm, tc.index, ordinary)
			var err error
			captureStdout(t, func() { err = NVRAMDeleteCommand(sock, tc.arg, true, false, false) })
			if err == nil || !strings.Contains(err.Error(), tc.flag) || !tpmdev.NVRAMIndexExists(tpm, tc.index) {
				t.Fatalf("--yes: %v", err)
			}
			captureStdout(t, func() { err = NVRAMDeleteCommand(sock, tc.arg, false, true, false) })
			if err != nil || tpmdev.NVRAMIndexExists(tpm, tc.index) {
				t.Fatalf("--force: %v", err)
			}
		})
	}
}

// Without --nvram: every slot and leftover, --yes alone leaving what has
// another shape and naming --force, with --force taking it.
func TestForeignInSlotDeleteEverything(t *testing.T) {
	sock, tpm := foreignTPM(t)
	gen, counter := nvslot.GenerationIndex(nvslot.NVRAMSlotStart), nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart+3)
	ordinary := tpm2.TPMANV{OwnerRead: true, OwnerWrite: true, NT: tpm2.TPMNTOrdinary}
	defineAt(t, tpm, gen, oldGeneration)
	defineAt(t, tpm, counter, ordinary)
	defineAt(t, tpm, nvslot.BootSettingsIndex, ordinary)
	there := []uint32{gen, counter, nvslot.BootSettingsIndex}

	var err error
	out := captureStdout(t, func() { err = NVRAMDeleteCommand(sock, 0, true, false, false) })
	if err == nil || !strings.Contains(err.Error(), "--yes --force") {
		t.Fatalf("--yes: %v\n%s", err, out)
	}
	for _, index := range there {
		if !tpmdev.NVRAMIndexExists(tpm, index) {
			t.Errorf("--yes took 0x%08X", index)
		}
	}
	out = captureStdout(t, func() { err = NVRAMDeleteCommand(sock, 0, true, true, false) })
	if err != nil {
		t.Fatalf("--yes --force: %v\n%s", err, out)
	}
	for _, index := range there {
		if tpmdev.NVRAMIndexExists(tpm, index) {
			t.Errorf("--yes --force left 0x%08X", index)
		}
	}
	// --force is no answer to deleting everything.
	defineAt(t, tpm, gen, oldGeneration)
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, 0, false, true, false) })
	if err == nil || !strings.Contains(err.Error(), "--yes") || !tpmdev.NVRAMIndexExists(tpm, gen) {
		t.Fatalf("--force without a terminal or --yes: %v", err)
	}
}

// --force stops at tpm2-kira's places: not the rest of its range, not a slot's
// number, not what is outside the range.
func TestForceStopsAtTheOwnPlaces(t *testing.T) {
	sock, tpm := foreignTPM(t)
	ordinary := tpm2.TPMANV{OwnerRead: true, OwnerWrite: true, NT: tpm2.TPMNTOrdinary}
	const reserved, slotNumber, outside = uint32(0x01803500), uint32(nvslot.NVRAMSlotStart + 3), uint32(0x01500010)
	for _, index := range []uint32{reserved, slotNumber, outside} {
		defineAt(t, tpm, index, ordinary)
	}
	var err error
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, reserved, false, true, false) })
	if !errors.Is(err, persist.ErrNotOurs) || !strings.Contains(err.Error(), "not one of tpm2-kira's own places") {
		t.Errorf("the rest of the range: %v", err)
	}
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, outside, false, true, false) })
	if err == nil || !strings.Contains(err.Error(), "outside the safe application range") {
		t.Errorf("outside the range: %v", err)
	}
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, slotNumber, false, true, false) })
	if err == nil || !strings.Contains(err.Error(), "nothing to delete") {
		t.Errorf("a slot's number: %v", err)
	}
	// The primitive itself, whatever a caller says yes to.
	always := func(nvslot.Foreign) (bool, error) { t.Error("asked about a place not tpm2-kira's"); return true, nil }
	if _, err := nvslot.RemoveIndex(tpm, reserved, always); !errors.Is(err, persist.ErrNotOurs) {
		t.Errorf("RemoveIndex in the range: %v", err)
	}
	if _, err := nvslot.RemoveIndex(tpm, outside, always); err == nil {
		t.Error("RemoveIndex outside the range took it")
	}
	for _, index := range []uint32{reserved, slotNumber, outside} {
		if !tpmdev.NVRAMIndexExists(tpm, index) {
			t.Errorf("0x%08X was removed", index)
		}
	}
}

// control: the slot's line shows the index and asks, after the slot's own
// question; No leaves it and says what to do, yes leaves nothing dirty. status's
// note says the same.
func TestControlForeignGenerationIndex(t *testing.T) {
	sock, tpm := foreignTPM(t)
	gen := nvslot.GenerationIndex(nvslot.NVRAMSlotStart)
	defineAt(t, tpm, gen, oldGeneration)

	dirt := collectDirt(sock, nil)
	if len(dirt) != 1 {
		t.Fatalf("dirt: %+v", dirt)
	}
	d := dirt[0]
	for what, text := range map[string]string{"cause": d.Cause(), "remedy": d.Remedy(), "remains": d.Remains(), "explain": dirtyLine(d).Explain} {
		want := map[string]string{"cause": "another shape", "remedy": "slot delete --nvram 0 --force", "remains": "0x01803810, of another shape", "explain": "shows the index"}[what]
		if !strings.Contains(text, want) || strings.Contains(text, "fix the cause") {
			t.Errorf("%s: %q lacks %q", what, text, want)
		}
	}
	run := func(lines string) (string, error) {
		var out bytes.Buffer
		c := &controller{out: &out, p: prompt.New(strings.NewReader(lines), &out)}
		c.o.TPMPath = sock
		c.facts.Dirt = dirt
		err := c.runRemoveSlot(0)
		return out.String(), err
	}
	out, err := run("0\n\n") // the slot's word, then No to the index of another shape
	t.Logf("control, answered No:\n%s\n%v", out, err)
	for _, want := range []string{"[y/N]", "read_stclear", "Remove the NV index 0x01803810?"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "not gone whole") || !strings.Contains(err.Error(), "--nvram 0 --force") || strings.Contains(err.Error(), "fix the cause") {
		t.Fatalf("No: %v", err)
	}
	if !tpmdev.NVRAMIndexExists(tpm, gen) {
		t.Fatal("No took the index")
	}
	if out, err = run("0\ny\n"); err != nil {
		t.Fatalf("yes: %v\n%s", err, out)
	}
	if tpmdev.NVRAMIndexExists(tpm, gen) || len(collectDirt(sock, nil)) != 0 {
		t.Fatal("yes left it")
	}
}

// The owner's password: a clear error that says what to do, the index still
// there, for tpm2-kira's own index as for another shape; no prompt's yes helps.
func TestRemovalUnderAnOwnerPassword(t *testing.T) {
	sock, tpm := foreignTPM(t)
	gen := nvslot.GenerationIndex(nvslot.NVRAMSlotStart)
	counter := nvslot.AttestCounterIndex(nvslot.NVRAMSlotStart)
	defineAt(t, tpm, gen, oldGeneration)
	if _, err := nvslot.BumpAttestCounter(tpm, counter); err != nil {
		t.Fatal(err)
	}
	secret := []byte("owner-secret")
	if _, err := (tpm2.HierarchyChangeAuth{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NewAuth: tpm2.TPM2BAuth{Buffer: secret}}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	var err error
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, nvslot.NVRAMSlotStart, false, true, false) })
	if err == nil || strings.Count(err.Error(), "has a password") != 2 || !strings.Contains(err.Error(), "tpm2_changeauth") || !errors.Is(err, tpm2.TPMRCBadAuth) {
		t.Fatalf("under an owner's password: %v", err)
	}
	if !tpmdev.NVRAMIndexExists(tpm, gen) || !tpmdev.NVRAMIndexExists(tpm, counter) {
		t.Fatal("removed, somehow")
	}
	if _, err := (tpm2.HierarchyChangeAuth{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(secret)},
		NewAuth: tpm2.TPM2BAuth{}}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, nvslot.NVRAMSlotStart, false, true, false) })
	if err != nil {
		t.Fatalf("the password gone: %v", err)
	}
}

// What the platform defined at such a place the owner cannot remove: said so,
// not "not ours" again and again.
func TestPlatformIndexAtAnOwnPlace(t *testing.T) {
	sock, tpm := foreignTPM(t)
	gen := nvslot.GenerationIndex(nvslot.NVRAMSlotStart)
	pub := tpm2.TPMSNVPublic{NVIndex: tpm2.TPMHandle(gen), NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{PPRead: true, PPWrite: true, PlatformCreate: true, NT: tpm2.TPMNTOrdinary}, DataSize: 8}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHPlatform, PublicInfo: tpm2.New2B(pub)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	var err error
	captureStdout(t, func() { err = NVRAMDeleteCommand(sock, nvslot.NVRAMSlotStart, false, true, false) })
	if err == nil || !strings.Contains(err.Error(), "platform's firmware defined it") {
		t.Fatalf("the platform's index: %v", err)
	}
}

// Switching the boot settings off is a write: it replaces what is there,
// and does not stop on another shape.
func TestBootSettingsOffOverAnotherShape(t *testing.T) {
	_, tpm := foreignTPM(t)
	defineAt(t, tpm, nvslot.BootSettingsIndex, tpm2.TPMANV{OwnerRead: true, OwnerWrite: true, NT: tpm2.TPMNTOrdinary})
	if err := nvslot.WriteBootSettings(tpm, nvslot.BootSettings{}, testSigner(t)); err != nil {
		t.Fatal(err)
	}
	if tpmdev.NVRAMIndexExists(tpm, nvslot.BootSettingsIndex) {
		t.Fatal("left")
	}
}

// The words: every attribute named, and the kinds.
func TestNVAttributeWords(t *testing.T) {
	got := nvAttributeWords(tpm2.TPMANV{NT: tpm2.TPMNTCounter, OwnerWrite: true, NoDA: true, Written: true, ReadSTClear: true})
	if got != "counter, ownerwrite, no_da, written, read_stclear" {
		t.Fatal(got)
	}
}
