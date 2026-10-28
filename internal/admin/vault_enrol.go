package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/untrusted"
	"github.com/mrwiora/tpm2-kira/internal/vaultkey"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
	"github.com/mrwiora/tpm2-kira/vaultproto"
)

// VaultEnrolOptions is what 'vault enrol' and 'luks enrol --mode tpm+vault'
// take.
type VaultEnrolOptions struct {
	TPMPath     string
	SealIndex   uint32
	URL         string
	Pin         string
	Token       string
	Label       string
	Name        string
	PrivKeyPath string
	Pepper      bool   // the key needs an operator's pepper too, asked here once
	Out         string // 'vault enrol' only: where the key is written
	Yes         bool   // the recovery passphrase is in place; do not ask
	Debug       bool
}

// VaultEnrol enrols the slot with the vault and writes the key to o.Out
// (tmpfs) for 'cryptsetup luksAddKey'; 'luks enrol --mode tpm+vault' does
// the keyslot as well.
func VaultEnrol(o VaultEnrolOptions) error {
	if o.Out == "" {
		return errors.New("--out PATH is required: the derived key is written there, on tmpfs, for cryptsetup luksAddKey")
	}
	if err := checkKeyOut(o.Out); err != nil {
		return err
	}
	if !o.Yes && !confirmRecoveryKeyslot() {
		return errors.New("a tpm+vault keyslot must never be the disk's only one: add a recovery passphrase first")
	}
	key, slot, err := vaultEnrolKey(o)
	if err != nil {
		return err
	}
	defer wipe.Bytes(key)
	if err := writeKeyOut(o.Out, key); err != nil {
		return err
	}
	fmt.Printf("\nKey written to %s\n\n", o.Out)
	fmt.Println("Next steps:")
	fmt.Printf("    cryptsetup luksAddKey <device> %s\n", o.Out)
	fmt.Printf("    tpm2-kira luks mark <device> --keyslot <the new keyslot> --mode %s --nvram %d\n", diskkey.LuksModeTPMVault, slot)
	fmt.Printf("    rm %s\n", o.Out)
	fmt.Println("('tpm2-kira luks enrol <device> --mode tpm+vault ...' does all of it at once.)")
	return nil
}

// vaultEnrolKey hands the slot to the vault and returns the key of the
// keyslot and the slot's number. The slot gets what it lacks - the
// attestation part (device ID, attestation key), the release key - and,
// once the vault has confirmed, the vault method with the wrapped local
// part; the blob is written and signed once, at the end.
func vaultEnrolKey(o VaultEnrolOptions) ([]byte, uint32, error) {
	label := o.Label
	if label == "" {
		label = "luks"
	}
	idx, err := nvslot.AttestIndexForSlot(o.SealIndex)
	if err != nil {
		return nil, 0, err
	}
	slot := nvslot.AttestSlot(idx)
	client, err := vaultkey.NewClient(o.URL, o.Pin)
	if err != nil {
		return nil, 0, err
	}
	if o.Token == "" {
		return nil, 0, errors.New("--token: the one-time token from 'tpm2-kira-vault token create'")
	}
	privKeyPath := o.PrivKeyPath
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}
	priv, err := signing.LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("the vault method is written into the slot's blob with the signing key only: %w", err)
	}
	if err := signing.PrepareSigningKey(priv); err != nil {
		return nil, 0, fmt.Errorf("the signing key is not usable: %w", err)
	}

	tpmDev, err := tpmdev.Open(o.TPMPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open TPM at %s: %w", o.TPMPath, err)
	}
	defer tpmDev.Close()
	defer tpmdev.Cleanup(tpmDev, o.Debug)

	raw, sealed, err := phonegate.ReadSlot(tpmDev, idx)
	if err != nil {
		return nil, 0, fmt.Errorf("slot %d holds no sealed blob (%v): seal first with 'tpm2-kira slot add --nvram %d'", slot, err, slot)
	}
	if err := nvslot.VerifyBlobSignature(raw, sealed, priv.Public()); err != nil {
		return nil, 0, foreignSlotError(slot, err)
	}
	att := sealed.Payload.Attestation
	if att != nil && att.Vault.Enabled() {
		return nil, 0, fmt.Errorf("slot %d is enrolled with the vault at %s already; 'tpm2-kira vault unenrol --nvram %d' first", slot, att.Vault.URL, slot)
	}
	sel := vaultkey.SealedSelection(sealed)
	if att == nil {
		fmt.Println("Creating an attestation key in the TPM ...")
		akPub, akPriv, akName, err := phonegate.CreateAK(tpmDev)
		if err != nil {
			return nil, 0, err
		}
		name := o.Name
		if name == "" {
			name, _ = os.Hostname()
		}
		if len(name) > 64 {
			name = name[:64]
		}
		att = &nvslot.Attestation{
			DeviceID: randBytes(attest.DeviceIDSize), FriendlyName: name,
			AKPublic: akPub, AKPrivate: akPriv, AKName: akName,
			PCRAlg: sel.Alg, PCRSelection: sel.Indices,
		}
	}
	if att.EKAlg == 0 {
		alg, ek, _, err := phonegate.PickCertifiedEK(tpmDev)
		if err != nil {
			return nil, 0, err
		}
		tpmdev.FlushHandle(tpmDev, ek.Handle)
		att.EKAlg = alg
	}
	if len(att.ReleaseKeyPublic) == 0 {
		pub, privArea, err := phonegate.CreateReleaseKey(tpmDev, sealed)
		if err != nil {
			return nil, 0, err
		}
		att.ReleaseKeyPublic, att.ReleaseKeyPrivate = pub, privArea
	}

	var pepper []byte
	if o.Pepper {
		// Asked before anything is sent or written: the operator gives it
		// with every approval, and nothing but its check is kept here.
		if pepper, err = askPepper(); err != nil {
			return nil, 0, err
		}
		defer wipe.Bytes(pepper)
	}

	local, wLocal, err := phonegate.WrapFactor(tpmDev, att, nil)
	if err != nil {
		return nil, 0, err
	}
	defer wipe.Bytes(local)
	remote, wRemote, err := phonegate.WrapFactor(tpmDev, att, nil)
	if err != nil {
		return nil, 0, err
	}
	defer wipe.Bytes(remote)
	// The blob must still fit its NV index with the vault method in it.
	key := vaultkey.Key(local, remote, label, pepper)
	att.Vault = nvslot.VaultAttestation{URL: strings.TrimSuffix(o.URL, "/"), Pin: strings.ToLower(o.Pin), Label: label, Local: *wLocal}
	if pepper != nil {
		att.Vault.PepperCheck = vaultkey.PepperCheck(key)
	}
	if err := checkEnrolmentFits(tpmDev, sealed, att, slot); err != nil {
		return nil, 0, err
	}

	ek, ekPub, err := phonegate.CreateEK(tpmDev, att.EKAlg)
	if err != nil {
		return nil, 0, err
	}
	tpmdev.FlushHandle(tpmDev, ek.Handle)
	genName, err := nvslot.GenerationIndexName(tpmDev, nvslot.GenerationIndex(idx))
	if err != nil {
		return nil, 0, err
	}
	p := &sealed.Payload
	req := vaultproto.EnrolRequest{
		Token: o.Token, DeviceID: att.DeviceID, Name: att.FriendlyName,
		EKPublic: ekPub, EKCert: phonegate.ReadEKCert(tpmDev, att.EKAlg), AKPublic: att.AKPublic,
		SigningPublic: p.SigningPublic, PolicyRef: p.PolicyRef,
		GenerationIndexName: genName, Generation: p.Generation, Selection: sel,
		Remote: vaultproto.Wrapped{Credential: wRemote.Credential, EncryptedSecret: wRemote.EncryptedSecret},
		Label:  label,
		Pepper: pepper != nil,
	}
	if err := req.Check(); err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var ch vaultproto.EnrolChallenge
	if err := client.Post(ctx, vaultproto.PathEnrol, req, &ch); err != nil {
		return nil, 0, err
	}
	be := &phonegate.TPMBackend{TPM: tpmDev, Blob: att, EKAlgorithm: att.EKAlg}
	secret, err := be.ActivateCredential(ch.Challenge.Credential, ch.Challenge.EncryptedSecret)
	if err != nil {
		return nil, 0, fmt.Errorf("proving the attestation key to the vault: %w", err)
	}
	defer wipe.Bytes(secret)
	var res vaultproto.EnrolResult
	if err := client.Post(ctx, vaultproto.PathEnrolConfirm, vaultproto.EnrolConfirm{EnrolID: ch.EnrolID, Secret: secret}, &res); err != nil {
		return nil, 0, err
	}
	if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
		return nil, 0, fmt.Errorf("the vault keeps the device, but the slot's blob was not written: %w\n"+
			"Enrol again with a token made with 'tpm2-kira-vault token create --replace %x'", err, att.DeviceID)
	}
	fmt.Printf("Slot %d is enrolled with the vault at %s as device %x (release mode %s).\n", slot, att.Vault.URL, att.DeviceID, res.Mode)
	fmt.Println("The local part is in the slot's blob, the remote part only with the vault; both")
	fmt.Println("open at boot, in the initrd, in the boot state the signing key approved.")
	if pepper != nil {
		fmt.Println("The key needs the pepper as well: every boot waits until an operator approves it")
		fmt.Println("on the vault with that pepper.")
	}
	if cfg, err := LoadControlConfig(controlConfigPath()); err == nil && cfg.Remote.Net.Mode == "off" {
		fmt.Println()
		fmt.Println("NOTE: the boot image has no network (TPM2_KIRA_NET=off), so it cannot reach the")
		fmt.Println("      vault: turn it on in 'tpm2-kira control' (Network and SSH at boot) and")
		fmt.Println("      rebuild the image.")
	}
	return key, slot, nil
}

// askPepper asks the operator's pepper twice, on the terminal.
func askPepper() ([]byte, error) {
	p, err := terminalAsk("Pepper (the operator gives it with every approval on the vault): ")
	if err != nil {
		return nil, err
	}
	again, err := terminalAsk("The same pepper again: ")
	if err != nil {
		wipe.Bytes(p)
		return nil, err
	}
	defer wipe.Bytes(again)
	if !bytes.Equal(p, again) {
		wipe.Bytes(p)
		return nil, errors.New("the peppers differ; nothing was enrolled")
	}
	if len(p) > vaultproto.MaxPepper {
		wipe.Bytes(p)
		return nil, fmt.Errorf("a pepper is at most %d bytes", vaultproto.MaxPepper)
	}
	return p, nil
}

// VaultStatus shows a slot's vault method and asks the vault for a
// challenge: it answers one only for a device it knows. (A release is not
// possible here: after 'cap' the parts do not open.)
func VaultStatus(tpmPath string, sealIndex uint32, debug bool) error {
	idx, err := nvslot.AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	slot := nvslot.AttestSlot(idx)
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	_, sb, err := phonegate.ReadSlot(tpmDev, idx)
	if err != nil {
		return err
	}
	att := sb.Payload.Attestation
	if att == nil || !att.Vault.Enabled() {
		return fmt.Errorf("slot %d is not enrolled with a vault", slot)
	}
	v := &att.Vault
	fmt.Printf("Slot %d: vault %s\n", slot, v.URL)
	fmt.Printf("  pin:       %s\n", v.Pin)
	fmt.Printf("  device:    %x (%s)\n", att.DeviceID, untrusted.Quote(att.FriendlyName))
	fmt.Printf("  label:     %s\n", v.Label)
	if len(v.PepperCheck) > 0 {
		fmt.Println("  pepper:    yes - every boot waits for an operator's approval with it")
	}
	fmt.Printf("  quoted:    %s, generation %d\n", vaultSelectionString(vaultkey.SealedSelection(sb)), sb.Payload.Generation)
	c, err := vaultkey.NewClient(v.URL, v.Pin)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ch vaultproto.ChallengeResponse
	if err := c.Post(ctx, vaultproto.PathChallenge, vaultproto.ChallengeRequest{DeviceID: att.DeviceID}, &ch); err != nil {
		fmt.Printf("  reachable: \033[0;31mno\033[0m - %v\n", err)
		return nil
	}
	fmt.Println("  reachable: \033[0;32myes\033[0m, the pinned key, and it knows this device")
	return nil
}

// VaultUnenrol takes the vault method out of the slot's blob: the local
// part is gone with it, so a tpm+vault keyslot of this slot no longer
// opens. The vault keeps its record until the operator revokes it.
func VaultUnenrol(tpmPath string, sealIndex uint32, privKeyPath string, debug bool) error {
	idx, err := nvslot.AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	slot := nvslot.AttestSlot(idx)
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	_, sb, err := phonegate.ReadSlot(tpmDev, idx)
	if err != nil {
		return err
	}
	att := sb.Payload.Attestation
	if att == nil || !att.Vault.Enabled() {
		return fmt.Errorf("slot %d is not enrolled with a vault", slot)
	}
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}
	priv, err := signing.LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("removing the vault method rewrites the slot's blob and needs the signing key: %w", err)
	}
	if err := signing.PrepareSigningKey(priv); err != nil {
		return fmt.Errorf("the signing key is not usable: %w", err)
	}
	id, url := att.DeviceID, att.Vault.URL
	att.Vault = nvslot.VaultAttestation{}
	if !att.Phone.Enabled() {
		att = nil // nothing else uses the attestation part
	}
	if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
		return err
	}
	fmt.Printf("Slot %d is no longer enrolled with the vault at %s; its local part is gone.\n", slot, url)
	fmt.Println("Its tpm+vault keyslot opens no more: remove it with 'tpm2-kira luks remove'.")
	fmt.Printf("On the vault: tpm2-kira-vault device revoke %x\n", id)
	return nil
}

// vaultSelectionString names a selection: "sha256:0,7,11".
func vaultSelectionString(s vaultproto.Selection) string {
	bank := "sha256"
	if tpm2.TPMAlgID(s.Alg) == tpm2.TPMAlgSHA1 {
		bank = "sha1"
	}
	var parts []string
	for _, i := range s.Indices {
		parts = append(parts, fmt.Sprint(i))
	}
	return bank + ":" + strings.Join(parts, ",")
}
