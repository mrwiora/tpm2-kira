//go:build integration

package admin

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/hostkey"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/totp"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// slotObjects is one slot with every object the slot's policy guards: the
// TOTP key, the sealed machine-id, the boot key, the release key (with a
// wrapped factor).
type slotObjects struct {
	t    *testing.T
	tpm  transport.TPM
	idx  uint32
	sb   *nvslot.SealedBlob
	mid  *machineid.Sealed
	att  *nvslot.Attestation
	f    []byte
	w    *nvslot.WrappedFactor
	when time.Time
}

func newSlotObjects(t *testing.T, sock string, tpm transport.TPM, idx uint32, bank measure.PCRHashAlgo) *slotObjects {
	t.Helper()
	pubPath, privPath := writeTestKeyPair(t)
	if err := Seal(sock, "23", idx, pubPath, privPath, false, bank, false, true); err != nil {
		t.Fatalf("seal (%s): %v", bank.DisplayString(), err)
	}
	o := &slotObjects{t: t, tpm: tpm, idx: idx, when: time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)}
	var err error
	if _, o.sb, err = phonegate.ReadSlot(tpm, idx); err != nil {
		t.Fatal(err)
	}
	if got := o.sb.GetHashAlgo(); got != bank {
		t.Fatalf("the slot's bank %s, want %s", got.DisplayString(), bank.DisplayString())
	}
	if o.mid, err = machineid.Seal(tpm, o.sb, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("machine-id: %v", err)
	}
	o.att = &nvslot.Attestation{EKAlg: uint16(tpm2.TPMAlgECC)}
	if o.att.BootKeyPublic, o.att.BootKeyPrivate, err = phonegate.CreateBootKey(tpm, o.sb); err != nil {
		t.Fatalf("boot key: %v", err)
	}
	if o.att.ReleaseKeyPublic, o.att.ReleaseKeyPrivate, err = phonegate.CreateReleaseKey(tpm, o.sb); err != nil {
		t.Fatalf("release key: %v", err)
	}
	if o.f, o.w, err = phonegate.WrapFactor(tpm, o.att, nil); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	return o
}

// use tries every object and returns what each answered.
func (o *slotObjects) use() map[string]error {
	errs := map[string]error{}
	_, _, errs["TOTP code"] = totp.SlotCode(o.tpm, o.idx, o.when, false)
	if id, err := o.mid.Unseal(o.tpm, o.sb); err == nil && id != "0123456789abcdef0123456789abcdef" {
		errs["machine-id"] = errors.New("another machine-id")
	} else {
		errs["machine-id"] = err
	}
	point, err := phonegate.BootKeyPoint(o.att)
	if err != nil {
		o.t.Fatal(err)
	}
	ctx := bytes.Repeat([]byte{0x42}, 32)
	ch, secret, err := attest.NewBootChallenge(rand.Reader, point, ctx)
	if err != nil {
		o.t.Fatal(err)
	}
	if code, proof, err := phonegate.OpenBootChallenge(o.tpm, o.sb, o.idx, o.att, ch, ctx); err == nil && (code != secret.Code || !secret.Check(proof)) {
		errs["boot key"] = errors.New("the boot key answered wrongly")
	} else {
		errs["boot key"] = err
	}
	if f, err := phonegate.UnwrapFactor(o.tpm, o.sb, o.idx, o.att, o.w); err == nil && !bytes.Equal(f, o.f) {
		errs["release key"] = errors.New("the factor opened to something else")
	} else {
		errs["release key"] = err
	}
	return errs
}

func (o *slotObjects) allWork(when string) {
	o.t.Helper()
	for what, err := range o.use() {
		if err != nil {
			o.t.Errorf("%s, %s: %v", when, what, err)
		}
	}
}

func (o *slotObjects) allClosed(when string) {
	o.t.Helper()
	for what, err := range o.use() {
		if !errors.Is(err, nvslot.ErrClosed) {
			o.t.Errorf("%s, %s: %v, want closed", when, what, err)
		}
	}
}

// Every slot object works while PCR 15 is zero - in the slot's bank,
// SHA-256 or SHA-1 - and none after the close (aSSH's hostkey.Close, what
// 'tpm2-kira-boot close' runs), until the next boot. That the TOTP key,
// the machine-id, the boot key and the release key open at all proves
// that the policy computed in core (attest.SlotPolicyDigest, their
// authPolicy) is the digest of the real session nvslot runs.
func TestTheCloseEndsEverySlotObject(t *testing.T) {
	for _, bank := range []measure.PCRHashAlgo{measure.PCRHashAlgoSHA256, measure.PCRHashAlgoSHA1} {
		t.Run(bank.DisplayString(), func(t *testing.T) {
			b := startBoots(t)
			o := newSlotObjects(t, b.p.sock, b.dev, machineid.Slot, bank)

			// The next boot: PCR 23 as at the seal, PCR 15 zero.
			b.reboot()
			o.tpm = b.dev
			o.allWork("before the close")
			if err := hmacWithCloseAsIs(b.dev, o); err != nil {
				t.Fatalf("the session without tpm2-kira's check, before the close: %v", err)
			}
			if nvslot.Closed(b.dev) {
				t.Fatal("closed before the close")
			}

			if err := hostkey.Close(b.dev); err != nil {
				t.Fatal(err)
			}
			if !nvslot.Closed(b.dev) {
				t.Fatal("not closed after the close")
			}
			o.allClosed("after the close")
			if line := totp.SlotErrorLine(nvslot.ErrClosed); !bytes.Contains([]byte(line), []byte("Closed until the next boot")) {
				t.Fatalf("the screen's line: %q", line)
			}

			// The TPM refuses, not only tpm2-kira's check: a session that
			// asserts PCR 15 as it is now (closed) fits no slot object's
			// policy.
			if err := hmacWithCloseAsIs(b.dev, o); !errors.Is(err, tpm2.TPMRCPolicyFail) {
				t.Fatalf("the TOTP key after the close: %v, want TPM_RC_POLICY_FAIL", err)
			}

			b.reboot()
			o.tpm = b.dev
			o.allWork("the boot after")
		})
	}
}

// The slot's policy in core is the TPM's: a trial session through
// PolicyAuthorize and PolicyPCR(15 == zero) ends in SlotPolicyDigest, in
// either bank.
func TestSlotPolicyDigestIsTheTPMs(t *testing.T) {
	b := startBoots(t)
	name, ref := append([]byte{0x00, 0x0b}, bytes.Repeat([]byte{9}, 32)...), bytes.Repeat([]byte{7}, 32)
	for _, bank := range []tpm2.TPMIAlgHash{tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA1} {
		sess, err := tpm2.StartAuthSession{
			TPMKey: tpm2.TPMRHNull, Bind: tpm2.TPMRHNull,
			NonceCaller: tpm2.TPM2BNonce{Buffer: make([]byte, 16)},
			SessionType: tpm2.TPMSETrial,
			Symmetric:   tpm2.TPMTSymDef{Algorithm: tpm2.TPMAlgNull},
			AuthHash:    tpm2.TPMAlgSHA256,
		}.Execute(b.dev)
		if err != nil {
			t.Fatal(err)
		}
		h := sess.SessionHandle
		if _, err := (tpm2.PolicyAuthorize{
			PolicySession: h, ApprovedPolicy: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
			PolicyRef: tpm2.TPM2BDigest{Buffer: ref}, KeySign: tpm2.TPM2BName{Buffer: name},
			CheckTicket: tpm2.TPMTTKVerified{Tag: tpm2.TPMSTVerified, Hierarchy: tpm2.TPMRHNull},
		}).Execute(b.dev); err != nil {
			t.Fatalf("PolicyAuthorize (trial): %v", err)
		}
		open, _ := attest.OpenPCRDigest(bank)
		if _, err := (tpm2.PolicyPCR{PolicySession: h, PcrDigest: tpm2.TPM2BDigest{Buffer: open}, Pcrs: attest.ClosePCRSelection(bank)}).Execute(b.dev); err != nil {
			t.Fatalf("PolicyPCR (trial): %v", err)
		}
		got, err := tpm2.PolicyGetDigest{PolicySession: h}.Execute(b.dev)
		if err != nil {
			t.Fatal(err)
		}
		tpm2.FlushContext{FlushHandle: h}.Execute(b.dev)
		want, err := attest.SlotPolicyDigest(name, ref, bank)
		if err != nil || !bytes.Equal(got.PolicyDigest.Buffer, want) {
			t.Fatalf("bank 0x%04x: the TPM's %x, core's %x (%v)", uint16(bank), got.PolicyDigest.Buffer, want, err)
		}
	}
}

// A dictionary attack lockout (wrong PINs at another index) does not stop
// the slots before the close: the generation index PolicyNV reads is
// noDA, and so are the objects.
func TestSlotsWorkInLockout(t *testing.T) {
	b := startBoots(t)
	o := newSlotObjects(t, b.p.sock, b.dev, nvslot.NVRAMSlotStart, measure.PCRHashAlgoSHA256)
	b.reboot()
	o.tpm = b.dev
	if _, err := (tpm2.DictionaryAttackParameters{AuthHandle: tpm2.TPMRHLockout, MaxTries: 1, RecoveryTime: 1800, LockoutRecovery: 1800}).Execute(b.dev); err != nil {
		t.Fatal(err)
	}
	const da tpm2.TPMHandle = 0x01802990
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, Auth: tpm2.TPM2BAuth{Buffer: []byte("pin")}, PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
		NVIndex: da, NameAlg: tpm2.TPMAlgSHA256, DataSize: 8,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTOrdinary, AuthRead: true, AuthWrite: true},
	})}).Execute(b.dev); err != nil {
		t.Fatal(err)
	}
	rsp, err := tpm2.NVReadPublic{NVIndex: da}.Execute(b.dev)
	if err != nil {
		t.Fatal(err)
	}
	write := func(pin string) error {
		_, err := tpm2.NVWrite{AuthHandle: tpm2.AuthHandle{Handle: da, Name: rsp.NVName, Auth: tpm2.PasswordAuth([]byte(pin))},
			NVIndex: tpm2.NamedHandle{Handle: da, Name: rsp.NVName}, Data: tpm2.TPM2BMaxNVBuffer{Buffer: make([]byte, 8)}}.Execute(b.dev)
		return err
	}
	write("wrong")
	write("wrong")
	if err := write("pin"); !errors.Is(err, tpm2.TPMRCLockout) {
		t.Fatalf("not in lockout: %v", err)
	}
	gen, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(nvslot.GenerationIndex(o.idx))}.Execute(b.dev)
	if err != nil {
		t.Fatal(err)
	}
	if pub, _ := gen.NVPublic.Contents(); !pub.Attributes.NoDA || pub.Attributes.ReadSTClear {
		t.Fatalf("the generation index: %+v", pub.Attributes)
	}
	o.allWork("in lockout")
	if err := hostkey.Close(b.dev); err != nil {
		t.Fatalf("the close in lockout: %v", err)
	}
	o.allClosed("in lockout, after the close")
}

// hmacWithCloseAsIs asks for o's TOTP code through the slot's approved
// policy with PCR 15 asserted as it is now, not at zero: what a caller
// that skipped tpm2-kira's check could at most do after the close.
func hmacWithCloseAsIs(tpm transport.TPM, o *slotObjects) error {
	sb := o.sb
	p := &sb.Payload
	signingPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](p.SigningPublic)
	if err != nil {
		return err
	}
	approval, err := tpm2.Unmarshal[tpm2.TPMTSignature](p.ApprovalSignature)
	if err != nil {
		return err
	}
	genIndex := tpm2.TPMHandle(nvslot.GenerationIndex(o.idx))
	genPub, err := tpm2.NVReadPublic{NVIndex: genIndex}.Execute(tpm)
	if err != nil {
		return err
	}
	signKey, err := tpm2.LoadExternal{InPublic: tpm2.New2B(*signingPublic), Hierarchy: tpm2.TPMRHOwner}.Execute(tpm)
	if err != nil {
		return err
	}
	defer tpm2.FlushContext{FlushHandle: signKey.ObjectHandle}.Execute(tpm)
	bank := sb.GetHashAlgo()
	session := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, h tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		if _, err := (tpm2.PolicyPCR{PolicySession: h, Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: bank.TPMAlg(), PCRSelect: measure.PcrsToBitmapBytes(sb.GetPCRIndices())}}}}).Execute(tpm); err != nil {
			return err
		}
		if _, err := (tpm2.PolicyNV{
			AuthHandle:    tpm2.AuthHandle{Handle: genIndex, Name: genPub.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:       tpm2.NamedHandle{Handle: genIndex, Name: genPub.NVName},
			PolicySession: h, OperandB: tpm2.TPM2BOperand{Buffer: binary.BigEndian.AppendUint64(nil, p.Generation)}, Operation: tpm2.TPMEOEq,
		}).Execute(tpm); err != nil {
			return err
		}
		pgd, err := tpm2.PolicyGetDigest{PolicySession: h}.Execute(tpm)
		if err != nil {
			return err
		}
		ticket, err := tpm2.VerifySignature{KeyHandle: signKey.ObjectHandle,
			Digest: tpm2.TPM2BDigest{Buffer: vaultproto.ApprovalDigest(pgd.PolicyDigest.Buffer, p.PolicyRef)}, Signature: *approval}.Execute(tpm)
		if err != nil {
			return err
		}
		if _, err := (tpm2.PolicyAuthorize{PolicySession: h, ApprovedPolicy: pgd.PolicyDigest, PolicyRef: tpm2.TPM2BDigest{Buffer: p.PolicyRef},
			KeySign: signKey.Name, CheckTicket: ticket.Validation}).Execute(tpm); err != nil {
			return err
		}
		// PCR 15 without a digest: the TPM takes its current value.
		_, err = tpm2.PolicyPCR{PolicySession: h, Pcrs: attest.ClosePCRSelection(bank.TPMAlg())}.Execute(tpm)
		return err
	})
	primary, err := tpmdev.CreatePrimaryKey(tpm)
	if err != nil {
		return err
	}
	defer tpmdev.FlushHandle(tpm, primary.ObjectHandle)
	key, err := totp.LoadSealedObject(tpm, primary, sb)
	if err != nil {
		return err
	}
	defer tpmdev.FlushHandle(tpm, key.ObjectHandle)
	_, err = tpm2.Hmac{
		Handle:  tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: session},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: make([]byte, 8)},
		HashAlg: p.TOTPAlgorithm,
	}.Execute(tpm)
	return err
}
