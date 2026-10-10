package cmd

// The SSH host key of the boot image, sealed to the TPM (docs/REMOTE-SSH.md).
//
// The image is unencrypted, so a host key stored in it serves anyone who
// can read /boot to impersonate the machine. Instead the image build
// ('remote initramfs') seals the key's secret half to this TPM, under a
// policy of PCR 0 (firmware) and PCR 7 (Secure Boot state and keys), and
// the image holds only the sealed object. 'run' unseals it once, at the
// start of the code screen, into the initramfs's memory, where tinysshd
// reads it; it never reaches a disk.
//
// The policy is checked before the OS separator - the code screen holds
// the boot ahead of systemd-pcrosseparator - so the values sealed are
// those of tpm2-kira's measure point, replayed from the firmware event
// log, not the registers of the running system (measurepoint.go). They
// are sealed afresh at every image build: after a firmware or Secure Boot
// update the image serves a throwaway key until one boot, unlocked at the
// console, rebuilds it.
//
// The key is the running system's OpenSSH host key by default
// (/etc/ssh/ssh_host_ed25519_key): the image answers as the system does,
// and the clients need no second known_hosts entry. A tinysshd key
// directory (tinysshd-makekey) serves instead for a key of the image's own.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

// hostKeyPCRs are the registers the host key is sealed to: the firmware
// and the Secure Boot state. Neither changes with the image, so the key
// survives a kernel update; both are final before tpm2-kira runs.
var hostKeyPCRs = []int{0, 7}

// The sealed key's file in the image, and where 'run' unseals it to.
const (
	ImageSealedHostKey = "/etc/tpm2-kira/ssh/ed25519.sealed"
	// The initramfs's own root, not /run: /run is carried over into the
	// booted system, the initramfs is freed at switch-root.
	DefaultHostKeyDir = "/tmp/tpm2-kira-ssh"
)

// sealedHostKey is the file in the image.
type sealedHostKey struct {
	Version   int            `json:"version"`
	PublicKey []byte         `json:"public_key"` // ed25519, 32 bytes, for the fingerprint
	Bank      string         `json:"bank"`       // "sha256" or "sha1"
	PCRs      map[int][]byte `json:"pcrs"`       // the values sealed to, for the diagnosis
	Public    []byte         `json:"tpm_public"`
	Private   []byte         `json:"tpm_private"`
}

const sealedHostKeyVersion = 1

// loadHostKey reads the key at path: an OpenSSH private key file
// (ssh-ed25519, unencrypted) or a tinysshd key directory.
func loadHostKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no SSH host key at %s: TPM2_KIRA_SSH_HOSTKEY names an OpenSSH ed25519 key or a key directory made by 'tinysshd-makekey DIR' (tpm2-kira control offers both)", path)
	}
	if err != nil {
		return nil, fmt.Errorf("SSH host key: %w", err)
	}
	if st.IsDir() {
		sk, err := os.ReadFile(filepath.Join(path, ".ed25519.sk"))
		if err != nil {
			return nil, fmt.Errorf("SSH host key: %w (create one with 'tinysshd-makekey %s')", err, path)
		}
		pk, err := os.ReadFile(filepath.Join(path, "ed25519.pk"))
		if err != nil {
			return nil, fmt.Errorf("SSH host key: %w", err)
		}
		if len(sk) != ed25519.PrivateKeySize || len(pk) != ed25519.PublicKeySize || !bytes.Equal(sk[32:], pk) {
			return nil, fmt.Errorf("SSH host key: %s does not hold a tinysshd ed25519 key pair", path)
		}
		return ed25519.PrivateKey(sk), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("SSH host key: %w", err)
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, fmt.Errorf("SSH host key %s is protected by a passphrase", path)
	}
	if err != nil {
		return nil, fmt.Errorf("SSH host key %s: %w", path, err)
	}
	k, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("SSH host key %s is not an ed25519 key, the only kind tinysshd serves", path)
	}
	return *k, nil
}

// hostKeyFingerprint is the key's SHA256 fingerprint as ssh prints it.
func hostKeyFingerprint(pub ed25519.PublicKey) string {
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "?"
	}
	return ssh.FingerprintSHA256(k)
}

// hostKeyBank is the PCR bank the key is sealed in: SHA-256 where the TPM
// has it.
func hostKeyBank(tpmDev transport.TPM) PCRHashAlgo {
	if TPMHasPCRBank(tpmDev, PCRHashAlgoSHA256) {
		return PCRHashAlgoSHA256
	}
	return PCRHashAlgoSHA1
}

// sealHostKey seals key to PCR 0 and 7 as they will be at tpm2-kira's
// measure point in the next boot.
func sealHostKey(tpmDev transport.TPM, key ed25519.PrivateKey) (*sealedHostKey, error) {
	bank := hostKeyBank(tpmDev)
	specs := make([]PCRSpec, len(hostKeyPCRs))
	for i, idx := range hostKeyPCRs {
		specs[i] = PCRSpec{Index: idx, Source: PCRSourceEventlog}
	}
	values, err := ReadPCRValues(tpmDev, specs, bank, MeasurePointModeSetting, MeasurePointBeforeSeparator, false)
	if err != nil {
		return nil, fmt.Errorf("the values of PCR 0 and 7 at boot cannot be told from the event log: %w", err)
	}
	policy, err := ComputePolicyDigestFromPCRValues(tpmDev, hostKeyPCRs, values.Values, bank)
	if err != nil {
		return nil, err
	}
	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	// The secret goes to the TPM in a salted, parameter-encrypted session.
	session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(primary.ObjectHandle, primary.Public),
		tpm2.AESEncryption(128, tpm2.EncryptIn))
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: session},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: key.Seed()}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
				// UserWithAuth not set: the PCR policy alone.
			},
			AuthPolicy: policy,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
		}),
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("sealing the SSH host key: %w", err)
	}
	s := &sealedHostKey{Version: sealedHostKeyVersion, PublicKey: key.Public().(ed25519.PublicKey),
		Bank: bank.String(), PCRs: map[int][]byte{},
		Public: rsp.OutPublic.Bytes(), Private: rsp.OutPrivate.Buffer}
	for _, idx := range hostKeyPCRs {
		s.PCRs[idx] = values.Values[idx]
	}
	return s, nil
}

// unsealHostKey gets the secret back, if PCR 0 and 7 hold what was sealed.
// On a mismatch the error names the registers that changed.
func unsealHostKey(tpmDev transport.TPM, s *sealedHostKey) (ed25519.PrivateKey, error) {
	if s.Version != sealedHostKeyVersion {
		return nil, fmt.Errorf("sealed host key of version %d, not %d: rebuild the image", s.Version, sealedHostKeyVersion)
	}
	bank := PCRHashAlgoSHA256
	if s.Bank == PCRHashAlgoSHA1.String() {
		bank = PCRHashAlgoSHA1
	}
	primary, err := CreatePrimaryKey(tpmDev)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(tpmDev, primary.ObjectHandle)
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](s.Public),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: s.Private},
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("the sealed host key does not load in this TPM: %w", err)
	}
	defer FlushHandle(tpmDev, loaded.ObjectHandle)
	session := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		_, err := tpm2.PolicyPCR{
			PolicySession: handle,
			Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: bank.TPMAlg(), PCRSelect: PcrsToBitmapBytes(hostKeyPCRs),
			}}},
		}.Execute(tpm)
		return err
	}, tpm2.Salted(primary.ObjectHandle, primary.Public), tpm2.AESEncryption(128, tpm2.EncryptOut))
	rsp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: session},
	}.Execute(tpmDev)
	if err != nil {
		if changed := changedHostKeyPCRs(tpmDev, s, bank); changed != "" {
			return nil, fmt.Errorf("%s changed since the image was built", changed)
		}
		return nil, fmt.Errorf("unsealing the host key: %w", err)
	}
	if len(rsp.OutData.Buffer) != ed25519.SeedSize {
		return nil, errors.New("the sealed host key is not an ed25519 seed")
	}
	key := ed25519.NewKeyFromSeed(rsp.OutData.Buffer)
	if !bytes.Equal(key.Public().(ed25519.PublicKey), s.PublicKey) {
		return nil, errors.New("the unsealed host key does not fit its public key")
	}
	return key, nil
}

// changedHostKeyPCRs names the registers that no longer hold the sealed
// values ("PCR 7", "PCR 0 and 7"), "" when they all do or cannot be read.
func changedHostKeyPCRs(tpmDev transport.TPM, s *sealedHostKey, bank PCRHashAlgo) string {
	regs, err := ReadPCRRegisters(tpmDev, hostKeyPCRs, bank, false)
	if err != nil {
		return ""
	}
	var changed []string
	for _, idx := range hostKeyPCRs {
		if !bytes.Equal(regs[idx], s.PCRs[idx]) {
			changed = append(changed, fmt.Sprint(idx))
		}
	}
	if len(changed) == 0 {
		return ""
	}
	return "PCR " + strings.Join(changed, " and ")
}

// writeTinysshKey writes key as a tinysshd key directory.
func writeTinysshKey(dir string, key ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, ".ed25519.sk"), key, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "ed25519.pk"), key.Public().(ed25519.PublicKey), 0o644)
}

// hostKeyAtBoot is what the SSH server serves.
type hostKeyAtBoot struct {
	Dir         string // the tinysshd key directory
	Fingerprint string
	Throwaway   string // why the sealed key is not served, "" when it is
}

// prepareHostKey unseals the image's host key into dir. When it cannot
// (a firmware or Secure Boot update since the build, another TPM), a
// throwaway key is served instead: the ssh client then warns of a changed
// host key, and the console shows the throwaway's fingerprint to compare.
func prepareHostKey(tpmPath, sealedPath, dir string) (hostKeyAtBoot, error) {
	key, why := unsealHostKeyFile(tpmPath, sealedPath)
	if key == nil {
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return hostKeyAtBoot{}, err
		}
		key = sk
	}
	os.RemoveAll(dir)
	if err := writeTinysshKey(dir, key); err != nil {
		os.RemoveAll(dir)
		return hostKeyAtBoot{}, err
	}
	return hostKeyAtBoot{Dir: dir, Fingerprint: hostKeyFingerprint(key.Public().(ed25519.PublicKey)), Throwaway: why}, nil
}

// unsealHostKeyFile is the key, or nil and why not.
func unsealHostKeyFile(tpmPath, sealedPath string) (ed25519.PrivateKey, string) {
	data, err := os.ReadFile(sealedPath)
	if err != nil {
		return nil, "the image holds no sealed host key"
	}
	var s sealedHostKey
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, "the sealed host key does not parse"
	}
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return nil, "no TPM: " + err.Error()
	}
	defer tpmDev.Close()
	key, err := unsealHostKey(tpmDev, &s)
	if err != nil {
		return nil, err.Error()
	}
	return key, ""
}
