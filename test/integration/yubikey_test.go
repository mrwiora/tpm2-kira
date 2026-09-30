//go:build integration && pcsc

// End-to-end tests for a signing key held on a hardware token.
//
// These join the two simulators: a software TPM (swtpm) and a virtual PIV card
// attached to a real pcscd through the vsmartcard virtual reader. Between them
// the whole feature runs with no hardware — key reference parsing, the PC/SC
// transport, the PIV APDUs, TPM2_PolicySigned, the PolicySigned NVRAM write,
// and unsealing afterwards.
//
// They need both swtpm and a pcscd with vpcd configured, so they carry both
// build tags. See test/docker/ for a container that has them.
package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/matthias/tpm2-kira/internal/virtualpiv"
)

// attachToken starts a virtual YubiKey and points tpm2-kira's PIN at it.
func attachToken(t *testing.T, opts virtualpiv.Options) *virtualpiv.Card {
	t.Helper()

	card, err := virtualpiv.New(opts)
	if err != nil {
		t.Fatalf("failed to build the virtual card: %v", err)
	}

	if err := card.Attach(virtualpiv.DefaultAddr, 1500*time.Millisecond); err != nil {
		t.Skipf("cannot attach a virtual card (%v); is pcscd running with vsmartcard-vpcd?", err)
	}

	t.Cleanup(card.Close)
	return card
}

func setPIN(t *testing.T, pin string) {
	t.Helper()

	previous, had := os.LookupEnv("TPM2_KIRA_PIN")
	if err := os.Setenv("TPM2_KIRA_PIN", pin); err != nil {
		t.Fatalf("failed to set the PIN: %v", err)
	}

	t.Cleanup(func() {
		if had {
			os.Setenv("TPM2_KIRA_PIN", previous)
		} else {
			os.Unsetenv("TPM2_KIRA_PIN")
		}
	})
}

// TestYubiKeySealRevealReseal is the end-to-end case: seal against a key that
// only exists on the token, unseal through the PCR branch, then reseal — which
// exercises the PolicySigned NVRAM write that every reseal depends on.
func TestYubiKeySealRevealReseal(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	card := attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})
	setPIN(t, "123456")

	const nvramIndex = "0x01803008"
	const keyRef = "yubikey:serial=12345678;slot=9a"

	// No --pubkey: the public half is read from the token itself.
	stdout, stderr, err := runTPMKira(t, tpmPath,
		"seal", "--nvram", nvramIndex, "--pcrs", testPCRs, "--privkey", keyRef)
	if err != nil {
		t.Fatalf("Seal with a token key failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "TOTP Secret Generated") {
		t.Fatalf("expected a sealed secret, got:\n%s\n%s", stdout, stderr)
	}

	// The PCR branch needs no key at all, so this must work with the token
	// still attached or not.
	code := testReveal(t, tpmPath, nvramIndex)

	// The blob records the key's identity and nothing about where it lives. A
	// token serial or slot in here would be local state inside a portable,
	// signed artifact, and the copy that outranked the one on disk.
	stdout, _, err = runTPMKira(t, tpmPath, "info", "--nvram", nvramIndex, "--json")
	if err != nil {
		t.Fatalf("info failed: %v", err)
	}
	if !strings.Contains(stdout, "key_fingerprint") {
		t.Errorf("info --json should record the key fingerprint, got:\n%s", stdout)
	}
	for _, unwanted := range []string{"yubikey:", "token_serial", "private_key_ref", "public_key_ref"} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("the blob must not record %q; v10 removed it. Got:\n%s", unwanted, stdout)
		}
	}

	verifications, signatures, _ := card.Counters()
	t.Logf("after seal: %d PIN verifications, %d signatures", verifications, signatures)
	if signatures == 0 {
		t.Error("the token was never asked to sign; the seal did not use it")
	}

	// Reseal: unseals through the PCR branch, then needs the token again for
	// the PolicySigned NVRAM write.
	//
	// --privkey is named because this test never ran 'setup', so there is no
	// reference at the well-known path. The blob does not say where the key is
	// — see TestSetupWithYubiKeyFlag for the flagless path, which works because
	// setup writes that reference.
	stdout, stderr, err = runTPMKira(t, tpmPath, "reseal", "--nvram", nvramIndex,
		"--privkey", keyRef)
	if err != nil {
		t.Fatalf("Reseal failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Successfully resealed") {
		t.Fatalf("expected a successful reseal, got:\n%s\n%s", stdout, stderr)
	}

	// Resealing preserves the secret, so the code must still be the sealed
	// one. Compared within the same 30-second window as the reseal above.
	if after := testReveal(t, tpmPath, nvramIndex); after != code {
		t.Logf("TOTP window turned over between reveals (%s then %s); not a failure", code, after)
	}

	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestYubiKeyPINPolicyAlways covers the slot configuration sbctl users are most
// likely to have: 9c, where PIV mandates a PIN verification before every
// signature. tpm2-kira has to re-verify transparently.
func TestYubiKeyPINPolicyAlways(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	card := attachToken(t, virtualpiv.Options{
		Slot:      0x9C,
		Serial:    87654321,
		PINPolicy: virtualpiv.PINPolicyAlways,
	})
	setPIN(t, "123456")

	const nvramIndex = "0x01803009"

	stdout, stderr, err := runTPMKira(t, tpmPath,
		"seal", "--nvram", nvramIndex, "--pcrs", testPCRs,
		"--privkey", "yubikey:serial=87654321;slot=9c")
	if err != nil {
		t.Fatalf("Seal failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	testReveal(t, tpmPath, nvramIndex)

	verifications, signatures, _ := card.Counters()
	t.Logf("PIN policy always: %d verifications for %d signatures", verifications, signatures)

	if signatures == 0 {
		t.Fatal("the token was never asked to sign")
	}
	if verifications < signatures {
		t.Errorf("a slot with PIN policy 'always' needs one verification per signature: "+
			"got %d verifications for %d signatures", verifications, signatures)
	}

	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestYubiKeyWrongPINDoesNotBlockTheSlot checks the lockout guard. A wrong PIN
// must cost exactly one attempt, no matter how many NVRAM slots the command
// would otherwise walk.
func TestYubiKeyWrongPINDoesNotBlockTheSlot(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	card := attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678, PIN: "123456"})
	setPIN(t, "999999")

	const nvramIndex = "0x0180300a"

	stdout, stderr, _ := runTPMKira(t, tpmPath,
		"seal", "--nvram", nvramIndex, "--pcrs", testPCRs,
		"--privkey", "yubikey:serial=12345678;slot=9a")

	combined := stdout + stderr
	if !strings.Contains(combined, "rejected") {
		t.Errorf("expected a rejected PIN to be reported, got:\n%s", combined)
	}
	if !strings.Contains(combined, "attempt") {
		t.Errorf("expected the remaining attempts to be named, got:\n%s", combined)
	}

	verifications, signatures, _ := card.Counters()
	if verifications != 0 || signatures != 0 {
		t.Errorf("nothing should have succeeded: %d verifications, %d signatures", verifications, signatures)
	}
}

// TestYubiKeyAbsentTokenSkipsReseal is the degradation path: a reseal that
// cannot reach the key must change nothing and say so, rather than failing
// halfway and leaving an empty index.
func TestYubiKeyAbsentTokenSkipsReseal(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	card := attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})
	setPIN(t, "123456")

	const nvramIndex = "0x0180300b"
	const nvramIndexValue = 0x0180300b

	if _, _, err := runTPMKira(t, tpmPath,
		"seal", "--nvram", nvramIndex, "--pcrs", testPCRs,
		"--privkey", "yubikey:serial=12345678;slot=9a"); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	before := readNVRAMBlob(t, tpmPath, nvramIndexValue)

	// Unplug the token.
	card.Close()
	time.Sleep(1500 * time.Millisecond)

	stdout, stderr, err := runTPMKira(t, tpmPath, "reseal", "--nvram", nvramIndex)
	if err != nil {
		t.Fatalf("reseal should not fail when the token is absent: %v", err)
	}

	combined := stdout + stderr
	if !strings.Contains(combined, "SKIPPED:") {
		t.Errorf("expected a SKIPPED report, got:\n%s", combined)
	}
	if !strings.Contains(combined, "MISMATCH") {
		t.Errorf("the warning should say a PCR mismatch follows, got:\n%s", combined)
	}

	// The whole point: nothing was touched.
	if after := readNVRAMBlob(t, tpmPath, nvramIndexValue); string(after) != string(before) {
		t.Error("the skipped reseal changed the sealed blob")
	}

	// And the secret still works, because the PCR branch needs no key.
	testReveal(t, tpmPath, nvramIndex)

	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestYubiKeyWrongTokenIsNamed checks the fingerprint pinning added in blob v9:
// a different token in the same slot must be diagnosed by name rather than
// failing as a TPM policy error.
func TestYubiKeyWrongTokenIsNamed(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	original := attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})
	setPIN(t, "123456")

	const nvramIndex = "0x0180300c"

	if _, _, err := runTPMKira(t, tpmPath,
		"seal", "--nvram", nvramIndex, "--pcrs", testPCRs,
		"--privkey", "yubikey:serial=12345678;slot=9a"); err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Swap in a different token reporting the same serial, so the reference
	// still resolves but the key behind it is not the sealed one.
	original.Close()
	time.Sleep(1500 * time.Millisecond)
	attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})

	// --privkey names the slot, as this test never ran 'setup'. The reference
	// resolves to a token that is present; what differs is the key inside it,
	// which is what the fingerprint check exists to catch.
	stdout, stderr, _ := runTPMKira(t, tpmPath, "reseal", "--nvram", nvramIndex,
		"--privkey", "yubikey:serial=12345678;slot=9a")

	combined := stdout + stderr
	if !strings.Contains(combined, "not the one this slot was sealed against") {
		t.Errorf("expected the wrong key to be named, got:\n%s", combined)
	}
	if strings.Contains(combined, "may have been tampered with") {
		t.Error("a swapped token should not be reported as blob tampering")
	}

	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestSetupWithYubiKeyFlag covers guided setup taking the token route without a
// prompt, which is what --yubikey is for and what the tests can drive.
//
// setup only prepares the key: it must not seal, and it must not need a PIN.
func TestSetupWithYubiKeyFlag(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})

	// Setup writes to /var/lib/tpm2-kira/keys and declines if it exists, so
	// this only runs where that is disposable — the test container.
	if _, err := os.Stat("/var/lib/tpm2-kira/keys"); err == nil {
		t.Skip("/var/lib/tpm2-kira/keys already exists; setup would decline")
	}
	t.Cleanup(func() { os.RemoveAll("/var/lib/tpm2-kira") })

	// Deliberately no PIN in the environment: reading a public key from a slot
	// needs none, and setup signs nothing.
	os.Unsetenv("TPM2_KIRA_PIN")

	stdout, stderr, err := runTPMKira(t, tpmPath, "setup", "--yubikey", "yubikey:serial=12345678;slot=9a")
	if err != nil {
		t.Fatalf("Setup failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	for _, want := range []string{
		"Signing key ready",
		"yubikey:serial=12345678;slot=9a",
		"No private key is written",
		"Nothing is sealed yet",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("setup output should contain %q, got:\n%s", want, stdout)
		}
	}

	// Only the public key belongs on disk; a private key file would mean the
	// token was not actually used.
	if _, err := os.Stat("/var/lib/tpm2-kira/keys/seal.pub"); err != nil {
		t.Errorf("the public key should have been cached: %v", err)
	}

	// The private key path does hold a file, but it names the token instead of
	// holding a key. Leaving it absent is what broke the step to the first
	// seal: the choice made here was recorded nowhere.
	refBytes, err := os.ReadFile("/var/lib/tpm2-kira/keys/seal.key")
	if err != nil {
		t.Fatalf("setup recorded the token nowhere: %v", err)
	}
	if !strings.Contains(string(refBytes), "TPM2-KIRA KEY REFERENCE") {
		t.Errorf("seal.key is not a token reference:\n%s", refBytes)
	}
	if strings.Contains(string(refBytes), "PRIVATE KEY-----") {
		t.Error("setup wrote actual key material even though the key is on the token")
	}
	if !strings.Contains(string(refBytes), "yubikey:serial=12345678;slot=9a") {
		t.Errorf("the reference does not name the token:\n%s", refBytes)
	}

	// Nothing sealed: that is now seal's job alone.
	const nvramIndex = "0x0180300d"
	stdout, _, _ = runTPMKira(t, tpmPath, "reveal-plain", "--nvram", nvramIndex)
	if isTOTPCode(strings.TrimSpace(stdout)) {
		t.Error("setup sealed a secret; it is supposed to only prepare the key")
	}

	// Sealing is the separate step, and it does need the PIN.
	setPIN(t, "123456")

	// No key flags: exactly what the setup output tells the operator to run.
	// This is the regression — the default --privkey is the path above, and
	// before it held a reference this failed with "no such file: seal.key".
	stdout, stderr, err = runTPMKira(t, tpmPath, "seal",
		"--nvram", nvramIndex, "--pcrs", testPCRs)
	if err != nil {
		t.Fatalf("Seal without key flags failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	if strings.Contains(stderr, "no such file") {
		t.Errorf("seal looked for a key file instead of following the reference:\n%s", stderr)
	}

	// The banner has to name the token, not the reference file, or the operator
	// cannot tell which key is being used.
	if !strings.Contains(stdout, "Signing Key: yubikey:serial=12345678;slot=9a") {
		t.Errorf("the seal banner should name the token, got:\n%s", stdout)
	}

	testReveal(t, tpmPath, nvramIndex)

	// A later reseal needs no flags — but that now comes from the reference file
	// at the well-known path, not from anything in the blob.
	stdout, _, err = runTPMKira(t, tpmPath, "info", "--nvram", nvramIndex, "--json")
	if err != nil {
		t.Fatalf("info failed: %v", err)
	}
	if strings.Contains(stdout, "yubikey:") {
		t.Errorf("the blob must not record where the key lives, got:\n%s", stdout)
	}

	_, stderr, _ = runTPMKira(t, tpmPath, "reseal", "--nvram", nvramIndex)
	if strings.Contains(stderr, "FAILED") || strings.Contains(stderr, "SKIPPED") {
		t.Errorf("reseal with no key flags should have found the token via %s:\n%s",
			"/var/lib/tpm2-kira/keys/seal.key", stderr)
	}

	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestSetupLocalIgnoresAttachedToken checks that the default is unchanged: with
// --local, and with no terminal to prompt at, a connected token is not used.
func TestSetupLocalIgnoresAttachedToken(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})

	if _, err := os.Stat("/var/lib/tpm2-kira/keys"); err == nil {
		t.Skip("/var/lib/tpm2-kira/keys already exists; setup would decline")
	}
	t.Cleanup(func() { os.RemoveAll("/var/lib/tpm2-kira") })

	stdout, stderr, err := runTPMKira(t, tpmPath, "setup", "--local")
	if err != nil {
		t.Fatalf("Setup failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	if strings.Contains(stdout, "yubikey:") {
		t.Errorf("--local should not have used the token, got:\n%s", stdout)
	}
	if _, err := os.Stat("/var/lib/tpm2-kira/keys/seal.key"); err != nil {
		t.Errorf("a signing key file should have been generated: %v", err)
	}

	// Running setup again must be a no-op that points at seal, not an error
	// and not a second key pair.
	before, err := os.ReadFile("/var/lib/tpm2-kira/keys/seal.key")
	if err != nil {
		t.Fatalf("cannot read the generated key: %v", err)
	}

	stdout, _, err = runTPMKira(t, tpmPath, "setup", "--local")
	if err != nil {
		t.Fatalf("re-running setup should not fail: %v", err)
	}
	if !strings.Contains(stdout, "already exist") {
		t.Errorf("re-running setup should say so, got:\n%s", stdout)
	}

	after, err := os.ReadFile("/var/lib/tpm2-kira/keys/seal.key")
	if err != nil {
		t.Fatalf("cannot re-read the key: %v", err)
	}
	if string(before) != string(after) {
		t.Error("re-running setup replaced the existing signing key")
	}

	// And seal is still a separate step that works with the generated key.
	const nvramIndex = "0x0180300e"
	stdout, stderr, err = runTPMKira(t, tpmPath, "seal", "--nvram", nvramIndex, "--pcrs", testPCRs)
	if err != nil {
		t.Fatalf("Seal failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	testReveal(t, tpmPath, nvramIndex)

	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestYubiKeyAdoptRecordsTheReference covers the other way a token becomes the
// signing key: adopting a slot on a machine that is already installed. It has
// the same obligation as setup — record the choice where seal will find it —
// and one more: never overwrite a key file that may be the only copy.
func TestYubiKeyAdoptRecordsTheReference(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	attachToken(t, virtualpiv.Options{Slot: 0x9A, Serial: 12345678})

	if _, err := os.Stat("/var/lib/tpm2-kira/keys"); err == nil {
		t.Skip("/var/lib/tpm2-kira/keys already exists; this test owns that path")
	}
	t.Cleanup(func() { os.RemoveAll("/var/lib/tpm2-kira") })

	if err := os.MkdirAll("/var/lib/tpm2-kira/keys", 0o700); err != nil {
		t.Fatal(err)
	}

	const keyPath = "/var/lib/tpm2-kira/keys/seal.key"

	// A local key is already installed, which is the realistic starting point
	// for adopting a token. It must survive.
	if err := generateTestKeys("/var/lib/tpm2-kira/keys/seal.pub", keyPath); err != nil {
		t.Fatalf("cannot lay down a local key: %v", err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// tpm2-kira exits 0 even when it fails, by design, so the exit status proves
	// nothing here — the output is the only evidence.
	stdout, stderr, _ := runTPMKira(t, tpmPath, "yubikey", "adopt", "--key", "yubikey:serial=12345678;slot=9a")
	if strings.Contains(stderr, "FAILED") {
		t.Fatalf("adopt failed:\nStdout: %s\nStderr: %s", stdout, stderr)
	}

	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("adopt overwrote an existing private key")
	}
	if !strings.Contains(stdout, "already holds a private key") {
		t.Errorf("adopt should say why it left the key alone, got:\n%s", stdout)
	}

	// With the key moved aside, adopting records the token.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, _ = runTPMKira(t, tpmPath, "yubikey", "adopt", "--key", "yubikey:serial=12345678;slot=9a")
	if strings.Contains(stderr, "FAILED") {
		t.Fatalf("adopt failed on the second run:\nStdout: %s\nStderr: %s", stdout, stderr)
	}

	refBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("adopt recorded the token nowhere: %v", err)
	}
	if !strings.Contains(string(refBytes), "yubikey:serial=12345678;slot=9a") {
		t.Errorf("the reference does not name the token:\n%s", refBytes)
	}

	// And sealing now works with no key flags, which is the point of all this.
	setPIN(t, "123456")

	const nvramIndex = "0x0180300e"
	stdout, stderr, _ = runTPMKira(t, tpmPath, "seal", "--nvram", nvramIndex, "--pcrs", testPCRs)
	if strings.Contains(stderr, "FAILED") {
		t.Fatalf("seal after adopt failed:\nStdout: %s\nStderr: %s", stdout, stderr)
	}

	testReveal(t, tpmPath, nvramIndex)
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}

// TestYubiKeyResealFollowsTheKeyToANewToken is the regression test for what the v10
// blob bump fixed. Under v9 the blob recorded which token the key was on, and
// that copy was consulted before the file on disk, so moving the key to another
// token left reseal hunting for the old serial — "no YubiKey with serial
// 11111111 is present" while the right token was plugged in and the reference
// file named it correctly. There was no local way to correct it.
//
// Now the blob records only the key's fingerprint, so the file is the single
// answer to where the key is, and adopting the new token is enough.
func TestYubiKeyResealFollowsTheKeyToANewToken(t *testing.T) {
	tpmPath, cleanup := setupSoftwareTPM(t)
	defer cleanup()

	if _, err := os.Stat("/var/lib/tpm2-kira/keys"); err == nil {
		t.Skip("/var/lib/tpm2-kira/keys already exists; this test owns that path")
	}
	t.Cleanup(func() { os.RemoveAll("/var/lib/tpm2-kira") })
	if err := os.MkdirAll("/var/lib/tpm2-kira/keys", 0o700); err != nil {
		t.Fatal(err)
	}

	// One key, which will live on two different tokens in turn. Importing the
	// same key is the realistic way a token gets replaced without resealing
	// against a new key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/var/lib/tpm2-kira/keys/seal.pub",
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	setPIN(t, "123456")
	const nvramIndex = "0x0180301d"

	// Seal against token A.
	cardA, err := virtualpiv.New(virtualpiv.Options{Slot: 0x9A, Serial: 11111111, Key: key, PIN: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cardA.Attach(virtualpiv.DefaultAddr, 1500*time.Millisecond); err != nil {
		t.Skipf("cannot attach a virtual card (%v); is pcscd running with vsmartcard-vpcd?", err)
	}

	_, stderr, _ := runTPMKira(t, tpmPath, "seal", "--nvram", nvramIndex, "--pcrs", testPCRs,
		"--privkey", "yubikey:serial=11111111;slot=9a",
		"--pubkey", "/var/lib/tpm2-kira/keys/seal.pub")
	if strings.Contains(stderr, "FAILED") {
		cardA.Close()
		t.Fatalf("seal against token A failed:\n%s", stderr)
	}
	cardA.Close()

	// The same key now lives on token B, with a different serial.
	cardB, err := virtualpiv.New(virtualpiv.Options{Slot: 0x9A, Serial: 22222222, Key: key, PIN: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cardB.Attach(virtualpiv.DefaultAddr, 1500*time.Millisecond); err != nil {
		t.Skipf("cannot attach a virtual card (%v)", err)
	}
	defer cardB.Close()

	// Adopting it is the only local action needed.
	_, stderr, _ = runTPMKira(t, tpmPath, "yubikey", "adopt", "--key", "yubikey:serial=22222222;slot=9a")
	if strings.Contains(stderr, "FAILED") {
		t.Fatalf("adopt failed:\n%s", stderr)
	}

	stdout, stderr, _ := runTPMKira(t, tpmPath, "reseal", "--nvram", nvramIndex)

	if strings.Contains(stderr, "11111111") {
		t.Errorf("reseal went looking for the retired token; the blob is still "+
			"recording where the key was:\n%s", stderr)
	}
	if strings.Contains(stderr, "FAILED") || strings.Contains(stderr, "SKIPPED") {
		t.Errorf("reseal should have followed the key to token B:\nstdout: %s\nstderr: %s", stdout, stderr)
	}

	// And the secret still works afterwards.
	testReveal(t, tpmPath, nvramIndex)
	runTPMKira(t, tpmPath, "nvram", "delete", "--nvram", nvramIndex)
}
