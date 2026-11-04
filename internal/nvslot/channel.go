package nvslot

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// The phone channel's secrets: the machine's static Noise key and the
// advertising key, sealed in one TPM object that the slot's record carries.
// Its policy is not the slot's:
//
//	PolicyOR( PolicyPCR(channelPCRs as sealed, 15 == zero) ; PolicyCommandCode(Unseal),
//	          PolicySigned(signing key, policyRef) ; PolicyCommandCode(Unseal) )
//
// The first branch is the gate's: before the close, in a boot of this machine's
// Secure Boot state (PCR 7), whatever image it runs, approved or not, so that the
// phone can show a boot nobody approved as changed. Another Secure Boot state - a
// live USB signed by another key, Secure Boot off, a db or dbx update - does not
// open them: no gate, and the phone finds no machine. The second branch is the
// running system's: another phone, the phone salt's hand-over, sealing them again
// at slot approve, each with a signature over the TPM's fresh nonce. After the
// close nothing else opens it.
//
// The channel follows a moved PCR 7 only when a person says so: an approval of a
// hook leaves it (internal/admin's ChannelApproval). Following it unattended would
// hand the secrets to whatever moved it.

// channelPCRs are the registers the first branch reads besides PCR 15: this list
// alone says which. Their values are the ones the gate will see, before the
// separator (ReadChannelPCRs), and the record carries them.
var channelPCRs = []int{7}

// ErrChannelMoved marks a boot before the close whose channel PCRs are not those
// the channel's secrets are sealed to.
var ErrChannelMoved = fmt.Errorf("PCR %s moved since the phone channel was sealed (a db or dbx update, Secure Boot switched, another signed system): only the signing key opens it, 'tpm2-kira slot approve' at a terminal seals it again", ChannelPCRList())

// ChannelPCRList names channelPCRs for a message.
func ChannelPCRList() string { return measure.FormatPCRList(channelPCRs) }

// channelSecretSize is what the object holds: the Noise key, then the
// advertising key.
const channelSecretSize = 64

// ChannelSecrets are the channel's secrets in the clear, in memory only.
type ChannelSecrets struct {
	NoisePrivate []byte // 32 bytes: the machine's static key of the encrypted channel
	AdvKey       []byte // 32 bytes: lets an enrolled phone recognise the advertising
}

// Wipe clears them.
func (c *ChannelSecrets) Wipe() {
	if c != nil {
		wipe.Bytes(c.NoisePrivate)
		wipe.Bytes(c.AdvKey)
	}
}

// ChannelPCR is one register's value in the first branch of the object's policy.
type ChannelPCR struct {
	Index  int
	Digest []byte
}

// ReadChannelPCRs returns channelPCRs' values as the gate will see them at the
// next boot: replayed from the event log, because on the running system the
// separator has moved the registers. Without a usable log it returns the registers,
// and why in afterSeparator: the gate's boot sees those only where no separator ran.
func ReadChannelPCRs(t transport.TPM, bank measure.PCRHashAlgo) (pcrs []ChannelPCR, afterSeparator string, err error) {
	specs := make([]measure.PCRSpec, len(channelPCRs))
	for i, index := range channelPCRs {
		specs[i] = measure.PCRSpec{Index: index, Source: measure.PCRSourceRegister}
	}
	res, err := measure.ReadPCRValues(t, specs, bank, measure.MeasurePointModeSetting, measure.MeasurePointBeforeSeparator, false)
	if err != nil {
		return nil, "", fmt.Errorf("the channel's PCRs: %w", err)
	}
	for _, index := range channelPCRs {
		pcrs = append(pcrs, ChannelPCR{Index: index, Digest: res.Values[index]})
	}
	return pcrs, res.AfterSeparator, nil
}

// channelPolicy is the object's policy for signingName and policyRef, with pcrs
// and PCR 15 read in bank, and the two branches PolicyOR takes.
func channelPolicy(signingName tpm2.TPM2BName, policyRef []byte, bank measure.PCRHashAlgo, pcrs []ChannelPCR) (policy []byte, branches tpm2.TPMLDigest, err error) {
	selection, digest, err := channelSelection(bank, pcrs)
	if err != nil {
		return nil, branches, err
	}
	unseal := tpm2.PolicyCommandCode{Code: tpm2.TPMCCUnseal}
	gate := attest.PolicyDigest(tpm2.PolicyPCR{PcrDigest: digest, Pcrs: selection}.Update, unseal.Update)
	signed := attest.PolicyDigest(tpm2.PolicySigned{
		AuthObject: tpm2.NamedHandle{Name: signingName},
		PolicyRef:  tpm2.TPM2BNonce{Buffer: policyRef},
	}.Update, unseal.Update)
	branches = tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{{Buffer: gate}, {Buffer: signed}}}
	return attest.PolicyDigest(tpm2.PolicyOr{PHashList: branches}.Update), branches, nil
}

// channelSelection is the first branch's PolicyPCR: the registers in ascending
// order, PCR 15 at zero among them, and the digest of their values.
func channelSelection(bank measure.PCRHashAlgo, pcrs []ChannelPCR) (tpm2.TPMLPCRSelection, tpm2.TPM2BDigest, error) {
	values := map[int][]byte{attest.ClosePCR: make([]byte, bank.DigestSize())}
	indices := []int{attest.ClosePCR}
	for _, p := range pcrs {
		values[p.Index] = p.Digest
		indices = append(indices, p.Index)
	}
	slices.Sort(indices)
	digest, err := measure.BuildPCRDigest(indices, values, bank)
	if err != nil {
		return tpm2.TPMLPCRSelection{}, tpm2.TPM2BDigest{}, err
	}
	return measure.CreatePCRSelection(indices, bank), digest, nil
}

// channelTemplate is a sealed data object only its policy opens.
func channelTemplate(policy []byte) tpm2.TPMTPublic {
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

// SealChannel seals c in this TPM for the slot sb is, to the channel PCRs'
// values at the next boot, and sets the object and those values in phone. The
// secrets go to the TPM in a salted, parameter-encrypted session. afterSeparator
// is ReadChannelPCRs'.
func SealChannel(t transport.TPM, sb *SealedBlob, phone *PhoneAttestation, c *ChannelSecrets) (afterSeparator string, err error) {
	pcrs, afterSeparator, err := ReadChannelPCRs(t, sb.GetHashAlgo())
	if err != nil {
		return "", err
	}
	if err := SealChannelTo(t, sb, phone, c, pcrs); err != nil {
		return "", err
	}
	return afterSeparator, nil
}

// SealChannelTo is SealChannel to the values pcrs.
func SealChannelTo(t transport.TPM, sb *SealedBlob, phone *PhoneAttestation, c *ChannelSecrets, pcrs []ChannelPCR) error {
	if len(c.NoisePrivate)+len(c.AdvKey) != channelSecretSize || len(c.NoisePrivate) != 32 {
		return errors.New("the channel's secrets are incomplete")
	}
	name, err := slotSigningName(sb)
	if err != nil {
		return err
	}
	policy, _, err := channelPolicy(name, sb.Payload.PolicyRef, sb.GetHashAlgo(), pcrs)
	if err != nil {
		return err
	}
	public, private, err := sealChannelObject(t, policy, c)
	if err != nil {
		return err
	}
	phone.ChannelPublic, phone.ChannelPrivate, phone.ChannelPCRs = public, private, pcrs
	return nil
}

// sealChannelObject makes the object under policy.
func sealChannelObject(t transport.TPM, policy []byte, c *ChannelSecrets) (public, private []byte, err error) {
	primary, err := tpmdev.CreatePrimaryKey(t)
	if err != nil {
		return nil, nil, err
	}
	defer tpmdev.FlushHandle(t, primary.ObjectHandle)
	session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(primary.ObjectHandle, primary.Public), tpm2.AESEncryption(128, tpm2.EncryptIn))
	data := append(append(make([]byte, 0, channelSecretSize), c.NoisePrivate...), c.AdvKey...)
	defer wipe.Bytes(data)
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: session},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data}),
		}},
		InPublic: tpm2.New2B(channelTemplate(policy)),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing the channel's secrets in the TPM: %w", err)
	}
	return rsp.OutPublic.Bytes(), rsp.OutPrivate.Buffer, nil
}

// slotSigningName is the Name of the slot's signing key.
func slotSigningName(sb *SealedBlob) (tpm2.TPM2BName, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](sb.Payload.SigningPublic)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("the slot holds no valid signing public key: %w", err)
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	if len(sb.Payload.PolicyRef) == 0 {
		return tpm2.TPM2BName{}, errors.New("the slot has no policy reference")
	}
	return *name, nil
}

// channelObject is what unsealing needs: the bank the object reads its PCRs in, the
// slot's bank when it was sealed, which the object's own policy tells.
func channelObject(sb *SealedBlob) (name tpm2.TPM2BName, bank measure.PCRHashAlgo, branches tpm2.TPMLDigest, err error) {
	att := sb.Payload.Attestation
	if att == nil || !att.Phone.Enabled() {
		return name, "", branches, errors.New("the slot has no phone channel")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](att.Phone.ChannelPublic)
	if err != nil {
		return name, "", branches, fmt.Errorf("the channel's sealed object does not parse: %w", err)
	}
	if name, err = slotSigningName(sb); err != nil {
		return name, "", branches, err
	}
	for _, bank := range []measure.PCRHashAlgo{measure.PCRHashAlgoSHA256, measure.PCRHashAlgoSHA1} {
		policy, branches, err := channelPolicy(name, sb.Payload.PolicyRef, bank, att.Phone.ChannelPCRs)
		if err == nil && bytes.Equal(policy, pub.AuthPolicy.Buffer) {
			return name, bank, branches, nil
		}
	}
	return name, "", branches, errors.New("the channel's sealed object is not this slot's: its policy differs; enrol the phones again")
}

// ChannelMove is a phone channel whose PCRs at the next boot are not those its
// secrets are sealed to.
type ChannelMove struct {
	Bank     measure.PCRHashAlgo
	Sealed   []ChannelPCR // what the object's policy reads
	NextBoot []ChannelPCR // what the next boot will have
	// AfterSeparator is ReadChannelPCRs': NextBoot are registers, and why.
	AfterSeparator string
}

// ChannelMoves is the slot's move; nil when the channel has not moved, or the slot
// has none.
func ChannelMoves(t transport.TPM, sb *SealedBlob) (*ChannelMove, error) {
	att := sb.Payload.Attestation
	if att == nil || !att.Phone.Enabled() {
		return nil, nil
	}
	_, bank, _, err := channelObject(sb)
	if err != nil {
		return nil, err
	}
	pcrs, afterSeparator, err := ReadChannelPCRs(t, bank)
	if err != nil {
		return nil, err
	}
	if slices.EqualFunc(pcrs, att.Phone.ChannelPCRs, func(a, b ChannelPCR) bool {
		return a.Index == b.Index && bytes.Equal(a.Digest, b.Digest)
	}) {
		return nil, nil
	}
	return &ChannelMove{Bank: bank, Sealed: att.Phone.ChannelPCRs, NextBoot: pcrs, AfterSeparator: afterSeparator}, nil
}

// ChannelMoved says whether the channel PCRs at the next boot are not those the
// channel's secrets are sealed to.
func ChannelMoved(t transport.TPM, sb *SealedBlob) (bool, error) {
	move, err := ChannelMoves(t, sb)
	return move != nil, err
}

// ResealChannelIfMoved seals the channel's secrets again, in sb's own record part,
// when ChannelMoved says so: opened with the signing key, the same secrets, so the
// phones keep what they pinned. It reports whether it did. afterSeparator is
// ReadChannelPCRs'.
func ResealChannelIfMoved(t transport.TPM, sb *SealedBlob, signer crypto.Signer) (resealed bool, afterSeparator string, err error) {
	moved, err := ChannelMoved(t, sb)
	if err != nil || !moved {
		return false, "", err
	}
	c, err := UnsealChannelSigned(t, sb, signer)
	if err != nil {
		return false, "", err
	}
	defer c.Wipe()
	afterSeparator, err = SealChannel(t, sb, &sb.Payload.Attestation.Phone, c)
	if err != nil {
		return false, "", err
	}
	return true, afterSeparator, nil
}

// unsealChannel loads the object and opens it with what assert puts into the
// session before PolicyCommandCode and PolicyOR. The response comes in a salted,
// parameter-encrypted session.
func unsealChannel(t transport.TPM, sb *SealedBlob, branches tpm2.TPMLDigest, assert func(transport.TPM, tpm2.TPMHandle, tpm2.TPM2BNonce) error) (*ChannelSecrets, error) {
	phone := &sb.Payload.Attestation.Phone
	primary, err := tpmdev.CreatePrimaryKey(t)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(t, primary.ObjectHandle)
	obj, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](phone.ChannelPublic),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: phone.ChannelPrivate},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading the channel's sealed object (was the TPM cleared?): %w", err)
	}
	defer tpmdev.FlushHandle(t, obj.ObjectHandle)
	// A session of its own, flushed on every way out.
	session, flush, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, tpm2.Salted(primary.ObjectHandle, primary.Public), tpm2.AESEncryption(128, tpm2.EncryptOut))
	if err != nil {
		return nil, fmt.Errorf("a policy session for the channel's secrets: %w", err)
	}
	defer flush()
	if err := assert(t, session.Handle(), session.NonceTPM()); err != nil {
		return nil, err
	}
	if _, err := (tpm2.PolicyCommandCode{PolicySession: session.Handle(), Code: tpm2.TPMCCUnseal}).Execute(t); err != nil {
		return nil, fmt.Errorf("PolicyCommandCode: %w", err)
	}
	if _, err := (tpm2.PolicyOr{PolicySession: session.Handle(), PHashList: branches}).Execute(t); err != nil {
		return nil, fmt.Errorf("PolicyOR: %w", err)
	}
	rsp, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: obj.ObjectHandle, Name: obj.Name, Auth: session}}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("the TPM did not open the channel's secrets: %w", err)
	}
	if len(rsp.OutData.Buffer) != channelSecretSize {
		return nil, errors.New("the channel's sealed object holds something else")
	}
	return &ChannelSecrets{NoisePrivate: rsp.OutData.Buffer[:32:32], AdvKey: rsp.OutData.Buffer[32:]}, nil
}

// UnsealChannel opens the channel's secrets the gate's way: before the close, in
// a boot whose channel PCRs are as sealed. ErrClosed after the close, ErrChannelMoved
// when those moved.
func UnsealChannel(t transport.TPM, sb *SealedBlob) (*ChannelSecrets, error) {
	_, bank, branches, err := channelObject(sb)
	if err != nil {
		return nil, err
	}
	selection, digest, err := channelSelection(bank, sb.Payload.Attestation.Phone.ChannelPCRs)
	if err != nil {
		return nil, err
	}
	return unsealChannel(t, sb, branches, func(tpm transport.TPM, handle tpm2.TPMHandle, _ tpm2.TPM2BNonce) error {
		// With the digest given, the TPM compares at once.
		if _, err := (tpm2.PolicyPCR{
			PolicySession: handle,
			PcrDigest:     digest,
			Pcrs:          selection,
		}).Execute(tpm); err != nil {
			if errors.Is(err, tpm2.TPMRCValue) {
				if err := CheckOpen(tpm, bank); err != nil {
					return err
				}
				return ErrChannelMoved
			}
			return fmt.Errorf("PolicyPCR: %w", err)
		}
		return nil
	})
}

// UnsealChannelSigned opens the channel's secrets with the slot's signing key,
// which signs the TPM's nonce for this one session: on the running system, for
// another phone, the phone salt's hand-over or sealing them again.
func UnsealChannelSigned(t transport.TPM, sb *SealedBlob, signer crypto.Signer) (*ChannelSecrets, error) {
	name, _, branches, err := channelObject(sb)
	if err != nil {
		return nil, err
	}
	public, err := tpm2.Unmarshal[tpm2.TPMTPublic](sb.Payload.SigningPublic)
	if err != nil {
		return nil, err
	}
	ref := sb.Payload.PolicyRef
	return unsealChannel(t, sb, branches, func(tpm transport.TPM, handle tpm2.TPMHandle, nonce tpm2.TPM2BNonce) error {
		key, err := tpm2.LoadExternal{InPublic: tpm2.New2B(*public), Hierarchy: tpm2.TPMRHOwner}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("failed to load the signing public key: %w", err)
		}
		defer tpmdev.FlushHandle(tpm, key.ObjectHandle)
		// aHash = SHA-256(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef), cpHashA empty.
		h := sha256.New()
		h.Write(nonce.Buffer)
		h.Write([]byte{0, 0, 0, 0})
		h.Write(ref)
		sig, err := signing.SignForTPM(signer, h.Sum(nil))
		if err != nil {
			return fmt.Errorf("the signing key's signature for the channel's secrets: %w", err)
		}
		if _, err := (tpm2.PolicySigned{
			AuthObject:    tpm2.NamedHandle{Handle: key.ObjectHandle, Name: name},
			PolicySession: handle,
			NonceTPM:      nonce,
			PolicyRef:     tpm2.TPM2BNonce{Buffer: ref},
			Auth:          sig,
		}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicySigned: %w", err)
		}
		return nil
	})
}
