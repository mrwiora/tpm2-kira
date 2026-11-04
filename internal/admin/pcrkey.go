package admin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
	"github.com/mrwiora/tpm2-kira/internal/measure"
)

// tpm2-kira's PCR key signs PCR 11 of a unified kernel image for the phase
// enter-initrd (ukify, reading /etc/kernel/uki.conf), so that the slots and the
// SSH CA take it signed: a kernel update needs no approval of 11. enter-initrd
// alone: the slots are used in the initrd and closed before leave-initrd, and a
// root cannot replay a phase that was never signed. Any image ever signed with
// it keeps 11 valid, like the db key; revocation is a new PCR key and the slots
// approved again (docs/SSH.md, "Known limits").

const (
	// DefaultPCRKey and DefaultPCRPub are the PCR key, root's alone, and its
	// public part.
	DefaultPCRKey = "/etc/tpm2-kira/pcr.key"
	DefaultPCRPub = "/etc/tpm2-kira/pcr.pem"
	// DefaultUKIConf is what mkinitcpio's ukify build reads.
	DefaultUKIConf = "/etc/kernel/uki.conf"
)

// Vars: the tests point them elsewhere.
var (
	pcrKeyPath  = DefaultPCRKey
	pcrPubPath  = DefaultPCRPub
	ukiConfPath = DefaultUKIConf
)

// ensurePCRKey makes the PCR key if it is not there.
func ensurePCRKey() error {
	if _, err := os.Stat(pcrKeyPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("making the PCR key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(pathDir(pcrKeyPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(pcrKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o400); err != nil {
		return fmt.Errorf("writing the PCR key: %w", err)
	}
	return os.WriteFile(pcrPubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o644)
}

func pathDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}

// readPCRPub is the PCR key's public part in PKIX DER.
func readPCRPub() ([]byte, error) {
	b, err := os.ReadFile(pcrPubPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s holds no public key", pcrPubPath)
	}
	return block.Bytes, nil
}

// ukiConfBlock is what control asks to put into uki.conf.
func ukiConfBlock() string {
	return "[PCRSignature:tpm2-kira]\nPCRPrivateKey=" + pcrKeyPath + "\nPCRPublicKey=" + pcrPubPath + "\nPhases=enter-initrd\n"
}

// ukiConfSigns says whether uki.conf has ukify sign with the PCR key, for
// enter-initrd alone.
func ukiConfSigns() bool {
	b, err := os.ReadFile(ukiConfPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), ukiConfBlock())
}

// adoptUKIConf appends the block to uki.conf, changing nothing else of it.
func adoptUKIConf() error {
	old, err := os.ReadFile(ukiConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Contains(old, []byte(ukiConfBlock())) {
		return nil
	}
	if err := os.MkdirAll(pathDir(ukiConfPath), 0o755); err != nil {
		return err
	}
	out := old
	if len(out) > 0 {
		if out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, '\n')
	}
	return os.WriteFile(ukiConfPath, append(out, ukiConfBlock()...), 0o644)
}

// ukiSignedFor says whether the image at path carries what the slots need: an
// empty reason, or why not.
func ukiSignedReason(path string) string {
	key, err := readPCRPub()
	if err != nil {
		return err.Error()
	}
	if err := measure.CheckUKIPCRSig(path, key); err != nil {
		return err.Error()
	}
	return ""
}

// signedSelection is specs with PCR 11 signed, where the machine signs its
// images and this one is: a slot approved from now on takes it so.
func signedSelection(specs []measure.PCRSpec) []measure.PCRSpec {
	out := slices.Clone(specs)
	for i, s := range out {
		if s.Source == measure.PCRSourceUKI && s.Index == measure.TPM2PCRKernelBoot && ukiConfSigns() && ukiSignedReason(s.Command) == "" {
			out[i].Source = measure.PCRSourceSigned
		}
	}
	return out
}

// approvedPCRPolicy is the first part of the policy the signing key approves,
// and the PCR key, when specs have a signed PCR: a PolicyPCR of the values, or
// PolicyAuthorize(PCR key) and then that of the others.
func approvedPCRPolicy(tpmDev transport.TPM, specs []measure.PCRSpec, values map[int][]byte, algo measure.PCRHashAlgo) ([]byte, []byte, error) {
	var plain []int
	signed := false
	for _, s := range specs {
		if s.Source == measure.PCRSourceSigned {
			signed = true
		} else {
			plain = append(plain, s.Index)
		}
	}
	if !signed {
		d, err := measure.ComputePolicyDigestFromPCRValues(tpmDev, plain, values, algo)
		return d.Buffer, nil, err
	}
	if len(plain) == 0 {
		return nil, nil, errors.New("a selection of signed PCRs alone: the approval would cover none")
	}
	key, err := readPCRPub()
	if err != nil {
		return nil, nil, fmt.Errorf("the PCR key: %w", err)
	}
	slices.Sort(plain)
	sel := vaultproto.Selection{Alg: uint16(algo.TPMAlg())}
	var vals []vaultproto.PCRValue
	for _, i := range plain {
		v, ok := values[i]
		if !ok {
			return nil, nil, fmt.Errorf("no value of PCR %d", i)
		}
		sel.Indices = append(sel.Indices, uint8(i))
		vals = append(vals, vaultproto.PCRValue{Index: uint8(i), Value: v})
	}
	pol, err := vaultproto.SignedPCRPolicy(key, sel, vals)
	return pol, key, err
}
