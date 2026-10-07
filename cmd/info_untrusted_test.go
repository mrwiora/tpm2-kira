//go:build unit || !integration

package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"rsc.io/qr"
)

// captureStdout runs fn and returns what it printed to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	return string(<-done)
}

func TestQuoteUntrusted(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/tpm2-kira/keys/seal.key": "/etc/tpm2-kira/keys/seal.key",
		"v0.3.1":                       "v0.3.1",
		"":                             `""`,
		"a b":                          `"a b"`,
		"\x1b[2J":                      `"\x1b[2J"`,
		"x\nFAKE LINE":                 `"x\nFAKE LINE"`,
		"\xff":                         `"\xff"`,
	} {
		if got := quoteUntrusted(in); got != want {
			t.Errorf("quoteUntrusted(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestInfoDoesNotTrustPlantedBlob(t *testing.T) {
	_, ownPriv, _ := writeTestKeyPair(t, newTestKeyDir(t, "owner"))

	// A planted blob, signed by its author, with escape sequences in its
	// strings and key paths pointing into a directory nobody can enter.
	attackerKey, _, _ := writeTestKeyPair(t, newTestKeyDir(t, "attacker"))
	locked := newTestKeyDir(t, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0700) })
	esc := "\x1b[2J"
	sb := &SealedBlob{Version: CurrentBlobVersion, Payload: SealedBlobPayload{
		AppVersion: "evil" + esc, Public: []byte{1}, Private: []byte{2},
		PCRDigests:     []PCRDigestPair{{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}}},
		PolicyRef:      make([]byte, 32),
		EventlogInfo:   &EventlogInfo{EventlogPath: "/x", MeasurePointExtends: "os-separator:0" + esc, MeasurePointDetection: esc},
		PrivateKeyPath: filepath.Join(locked, "k"+esc),
		PublicKeyPath:  filepath.Join(locked, "p"+esc),
	}}
	unsigned, err := sb.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data, err := SignBlobPayload(unsigned, attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := UnmarshalSealedBlob(data)
	if err != nil {
		t.Fatal(err)
	}

	si := slotInfo{Index: NVRAMSlotStart, NVPublic: &tpm2.TPMSNVPublic{DataSize: uint16(len(data))}, Blob: blob, raw: data}
	si.Verify = newBlobVerifier(ownPriv).verify(si.raw, si.Blob)
	if si.Verify.Verified {
		t.Fatal("a blob signed by another key was reported as verified")
	}

	out := captureStdout(t, func() { printSlotTree("", &si, false) })
	t.Logf("output:\n%s", out)
	if strings.ContainsRune(out, 0x1b) {
		t.Error("an escape byte from the blob reached the output")
	}
	if !strings.Contains(out, "Signature: NOT VERIFIED") {
		t.Error("output does not mark the blob as unverified")
	}
	if !strings.Contains(out, "unverified, not opened") {
		t.Error("output does not mark the recorded key paths as unverified")
	}
	if strings.Contains(out, "permission denied") {
		t.Error("a key path from the blob was opened")
	}

	jsonOut := captureStdout(t, func() {
		if err := printJSON([]slotInfo{si}); err != nil {
			t.Error(err)
		}
	})
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatal(err)
	}
	if v, ok := parsed[0]["signature_verified"].(bool); !ok || v {
		t.Errorf("signature_verified = %v, want false", parsed[0]["signature_verified"])
	}
	if bytes.ContainsRune([]byte(jsonOut), 0x1b) {
		t.Error("an escape byte reached the JSON output")
	}
}

func TestInfoVerifiedBlob(t *testing.T) {
	key, priv, pub := writeTestKeyPair(t, newTestKeyDir(t, "owner"))
	data, blob := signedTestBlob(t, key, priv, pub)
	si := slotInfo{Index: NVRAMSlotStart, NVPublic: &tpm2.TPMSNVPublic{DataSize: uint16(len(data))}, Blob: blob, raw: data}
	si.Verify = newBlobVerifier(priv).verify(si.raw, si.Blob)
	if !si.Verify.Verified {
		t.Fatalf("own blob not verified: %s", si.Verify.Reason)
	}
	out := captureStdout(t, func() { printSlotTree("", &si, false) })
	for _, want := range []string{"Signature: valid", "Signing Key: ECDSA-P-256", "Key File Check: " + priv + ": ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestRenderQRCode(t *testing.T) {
	out, err := renderQRCode("otpauth://totp/TPM2-KIRA?secret=JBSWY3DPEHPK3PXP&issuer=TPM2-KIRA")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 10 || !strings.ContainsAny(out, "█▀▄") {
		t.Fatalf("QR output looks empty:\n%s", out)
	}
	// Decode the half blocks back into modules and compare them with the
	// encoder's bitmap, quiet zone included.
	code, err := qr.Encode("otpauth://totp/TPM2-KIRA?secret=JBSWY3DPEHPK3PXP&issuer=TPM2-KIRA", qr.M)
	if err != nil {
		t.Fatal(err)
	}
	const quiet = 4
	for i, l := range lines {
		row := []rune(stripANSI(l))
		if len(row) != code.Size+2*quiet {
			t.Fatalf("line %d has %d modules, want %d", i, len(row), code.Size+2*quiet)
		}
		y := 2*i - quiet
		for j, r := range row {
			x := j - quiet
			top := r == '█' || r == '▀'
			bottom := r == '█' || r == '▄'
			if top != code.Black(x, y) || bottom != code.Black(x, y+1) {
				t.Fatalf("module (%d,%d) rendered as %q, does not match the bitmap", x, y, r)
			}
		}
	}
}

func stripANSI(s string) string {
	s = strings.ReplaceAll(s, "\033[30;47m", "")
	return strings.ReplaceAll(s, "\033[0m", "")
}

// countingTPM counts the commands sent to it and fails them all.
type countingTPM struct{ sent int }

func (c *countingTPM) Send([]byte) ([]byte, error) { c.sent++; return nil, io.ErrUnexpectedEOF }
func (c *countingTPM) Close() error                { return nil }

func TestCleanupTPMSkipsManagedDevice(t *testing.T) {
	inner := &countingTPM{}
	CleanupTPM(&openedTPM{TPMCloser: inner, managed: true}, false)
	if inner.sent != 0 {
		t.Errorf("CleanupTPM sent %d command(s) through the resource manager, want none", inner.sent)
	}
	CleanupTPM(&openedTPM{TPMCloser: inner, managed: false}, false)
	if inner.sent == 0 {
		t.Error("CleanupTPM sent nothing on an unmanaged device")
	}
}
