// Package machineid is the machine-id the boot image releases, as
// safearch's initrd releases its own: the installed system's
// /etc/machine-id, sealed in this TPM under slot 0's policy and kept in the
// EFI variable KIRAmachineID. Only the boot image, in a boot state the
// signing key approved, can have it unsealed: the policy is the slot's,
// which the OS separator closes before the installed system runs. The image
// writes it where PID 1 and systemd-networkd take it, before the network
// starts: the image has the installed system's machine-id, and networkd
// derives its default DUID from it - the installed system's, where that is
// networkd's default. A DHCP identity the image carries (remote_dhcpid.go:
// copied from the installed system's client) is asked with instead. Every
// failure only means no machine-id: the boot goes on.
package machineid

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/tpm2-trust/assh/persist"

	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// GUID is the vendor GUID of tpm2-kira's own EFI variables.
const GUID = nvslot.VarGUID

// Var is the variable that keeps the sealed machine-id.
const Var = persist.VarPrefix + "KIRAmachineID-" + GUID

// Slot is the slot whose policy seals it: slot 0, the one bound to the
// most (firmware, option ROMs, Secure Boot, the image).
const Slot = nvslot.NVRAMSlotStart

// version is the variable's format.
const version = 1

// Where the machine-id goes: PID 1 bind-mounts the one over the other in a
// systemd image; vars for the tests.
var (
	RunPath = "/run/machine-id"
	EtcPath = "/etc/machine-id"
)

// TestPaths points the EFI variables and the machine-id files at a test's
// directory when TPM2_KIRA_TEST_DIR is set: the test suite runs the
// binaries, and they must not touch the host's efivarfs or machine-id.
func TestPaths() {
	dir := os.Getenv("TPM2_KIRA_TEST_DIR")
	if dir == "" {
		return
	}
	persist.VarDir = dir + "/efivars"
	EtcPath = dir + "/machine-id"
	RunPath = dir + "/run-machine-id"
}

// Sealed is the variable's contents.
type Sealed struct {
	Version int    `json:"version"`
	Slot    uint32 `json:"slot"`
	// Policy is the slot policy it is sealed under: another one (the slot
	// made again, another signing key) makes it stale.
	Policy []byte `json:"policy"`
	// IDHash tells a changed /etc/machine-id from the same one, and nothing
	// of it: a SHA-256 of 128 random bits.
	IDHash  []byte `json:"id_hash"`
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

// ReadID reads a machine-id file: 32 lowercase hex digits.
func ReadID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || id == strings.Repeat("0", 32) {
		return "", fmt.Errorf("%s holds no machine-id", path)
	}
	return id, nil
}

func idHash(id string) []byte {
	h := sha256.Sum256([]byte("tpm2-kira machine-id\x00" + id))
	return h[:]
}

// Current says whether s is sealed under sb's policy, of id.
func (s *Sealed) Current(sb *nvslot.SealedBlob, id string) bool {
	policy, err := sb.SlotPolicy()
	return err == nil && s.Version == version && s.Slot == Slot &&
		bytes.Equal(s.Policy, policy) && bytes.Equal(s.IDHash, idHash(id))
}

// Seal seals id in this TPM under the policy of the slot sb is.
func Seal(t transport.TPM, sb *nvslot.SealedBlob, id string) (*Sealed, error) {
	policy, err := sb.SlotPolicy()
	if err != nil {
		return nil, err
	}
	primary, err := tpmdev.CreatePrimaryKey(t)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(t, primary.ObjectHandle)
	// The machine-id goes to the TPM in a salted, parameter-encrypted
	// session, as the TOTP key does.
	session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(primary.ObjectHandle, primary.Public), tpm2.AESEncryption(128, tpm2.EncryptIn))
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: session},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: []byte(id)}),
		}},
		InPublic: tpm2.New2B(template(policy)),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("sealing the machine-id in the TPM: %w", err)
	}
	return &Sealed{Version: version, Slot: Slot, Policy: policy, IDHash: idHash(id),
		Public: rsp.OutPublic.Bytes(), Private: rsp.OutPrivate.Buffer}, nil
}

// template is a sealed data object the slot's policy alone opens: no
// UserWithAuth, no key of its own.
func template(policy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			NoDA:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
	}
}

// Unseal opens s with the approved session of the slot sb is (at Slot):
// the TPM gives it only in a boot state the signing key approved, before
// the separator.
func (s *Sealed) Unseal(t transport.TPM, sb *nvslot.SealedBlob) (string, error) {
	primary, err := tpmdev.CreatePrimaryKey(t)
	if err != nil {
		return "", err
	}
	defer tpmdev.FlushHandle(t, primary.ObjectHandle)
	obj, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](s.Public),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: s.Private},
	}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("loading the sealed machine-id (was the TPM cleared?): %w", err)
	}
	defer tpmdev.FlushHandle(t, obj.ObjectHandle)
	session, done, err := nvslot.ApprovedSession(t, sb, s.Slot)
	if err != nil {
		return "", fmt.Errorf("slot 0's policy does not hold: %w", err)
	}
	defer done()
	rsp, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: obj.ObjectHandle, Name: obj.Name, Auth: session}}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("the TPM did not unseal the machine-id: %w", err)
	}
	id := string(rsp.OutData.Buffer)
	if !bytes.Equal(idHash(id), s.IDHash) {
		return "", errors.New("the unsealed machine-id is not the one the variable names")
	}
	return id, nil
}

// Load reads the variable; an error os.IsNotExist knows when there is none.
func Load() (*Sealed, error) {
	b, err := persist.ReadVar(Var)
	if err != nil {
		return nil, err
	}
	var s Sealed
	if err := json.Unmarshal(b, &s); err != nil || s.Version != version {
		return nil, fmt.Errorf("%s is not a sealed machine-id of this version: seal it again (tpm2-kira slot approve)", Var)
	}
	return &s, nil
}

// Save writes the variable, in place.
func (s *Sealed) Save() error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return persist.WriteVar(Var, b)
}

// Remove removes the variable; it reports whether there was one.
func Remove() (bool, error) { return persist.RemoveVar(Var) }

// Release hands id to PID 1 and the image's network: written in place into
// RunPath, which PID 1 bind-mounts over EtcPath, and into EtcPath where it
// does not. systemd-networkd, started after, derives its DUID from it.
func Release(id string) error {
	line := []byte(id + "\n")
	wrote := false
	if _, err := os.Stat(RunPath); err == nil {
		if err := writeInPlace(RunPath, line); err != nil {
			return err
		}
		wrote = true
	}
	if cur, err := os.ReadFile(EtcPath); err == nil && strings.TrimSpace(string(cur)) == id {
		return nil
	}
	if err := writeInPlace(EtcPath, line); err != nil && !wrote {
		return err
	}
	return nil
}

// writeInPlace overwrites path's contents without replacing the file: a
// bind mount over it stays.
func writeInPlace(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o444)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Boot is 'tpm2-kira-boot machine-id', run before the image's network: it
// releases the sealed machine-id when slot 0's policy holds. Nothing there
// is no error; the error says why it was not released, and the boot goes
// on without it.
func Boot(tpmPath string) (released bool, err error) {
	s, err := Load()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !tpmdev.AwaitNode(tpmPath, tpmWait) {
		return false, fmt.Errorf("%s did not appear", tpmPath)
	}
	t, err := tpmdev.Open(tpmdev.PreferResourceManager(tpmPath))
	if err != nil {
		return false, err
	}
	defer t.Close()
	data, err := tpmdev.ReadFromNVRAM(t, s.Slot)
	if err != nil {
		return false, fmt.Errorf("slot 0 is not in the TPM: %w", err)
	}
	sb, err := nvslot.UnmarshalSealedBlob(data)
	if err != nil {
		return false, err
	}
	id, err := s.Unseal(t, sb)
	if err != nil {
		return false, err
	}
	return true, Release(id)
}

// tpmWait is how long Boot waits for the TPM's device, as run does.
const tpmWait = 5 * time.Second
