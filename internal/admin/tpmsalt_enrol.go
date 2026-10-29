package admin

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// The salt in this TPM (recipe 0x1200): a part T drawn here, wrapped for
// the TPM's EK and the slot's release key and kept in the slot's blob, as
// the vault's local part is. At boot the TPM opens it while the code
// screen holds - only in a boot the slot's signing key approved, before
// the separator - and the salt is FactorSalt(T, label); the password is
// typed at the machine, and the key is the combiner's of the two. The
// disk's header and the password alone open nothing: the salt needs this
// TPM in an approved boot. One per slot; a new one replaces the old.

// tpmSaltKey puts a TPM salt into the slot and returns the key of the
// keyslot and the slot's number. The slot gets what it lacks first (the
// attestation part, the release key); the blob is signed once, at the end.
func tpmSaltKey(o FactorEnrolOptions) ([]byte, uint32, error) {
	label := o.Label
	if label == "" {
		label = "luks"
	}
	idx, err := nvslot.AttestIndexForSlot(o.SealIndex)
	if err != nil {
		return nil, 0, err
	}
	slot := nvslot.AttestSlot(idx)
	privKeyPath := o.PrivKeyPath
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}
	priv, err := signing.LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("the TPM salt is written into the slot's blob with the signing key only: %w", err)
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
	att, err := ensureAttestation(tpmDev, sealed, "")
	if err != nil {
		return nil, 0, err
	}
	if len(att.TPMSalt.Credential) != 0 {
		fmt.Printf("Slot %d holds a TPM salt already: it is replaced, and a keyslot enrolled with it opens no more.\n", slot)
	}

	pw, err := terminalAsk("Password (typed at the machine at every boot): ")
	if err != nil {
		return nil, 0, err
	}
	defer wipe.Bytes(pw)
	again, err := terminalAsk("The same password again: ")
	if err != nil {
		return nil, 0, err
	}
	defer wipe.Bytes(again)
	if !bytes.Equal(pw, again) {
		return nil, 0, errors.New("the passwords differ; nothing was written")
	}

	t, w, err := phonegate.WrapFactor(tpmDev, att, nil)
	if err != nil {
		return nil, 0, err
	}
	defer wipe.Bytes(t)
	salt := phonegate.FactorSalt(t, label)
	defer wipe.Bytes(salt)
	att.TPMSalt = *w
	if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
		return nil, 0, err
	}
	fmt.Printf("Slot %d holds the TPM salt, for this TPM's EK and the slot's release key.\n", slot)

	fmt.Fprintln(os.Stderr, "Deriving the key (Argon2id, 1 GiB, a few seconds) ...")
	key, err := diskkey.Combine(pw, salt)
	if err != nil {
		return nil, 0, err
	}
	return key, slot, nil
}
