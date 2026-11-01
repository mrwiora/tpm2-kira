package nvslot

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// The phone channel's secrets: the machine's static Noise key and the
// advertising key, sealed in one TPM object that the slot's record carries.
// Its policy is not the slot's:
//
//	PolicyOR( PolicyPCR(15 == zero) ; PolicyCommandCode(Unseal),
//	          PolicySigned(signing key, policyRef) ; PolicyCommandCode(Unseal) )
//
// The first branch is the gate's: before the close, in any boot, approved or
// not, so that the phone can show a boot nobody approved as changed. The second
// is the running system's: another phone, the phone salt's hand-over, each with
// a signature over the TPM's fresh nonce. After the close nothing else opens it.

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

// channelPolicy is the object's policy for signingName and policyRef, with PCR
// 15 read in bank, and the two branches PolicyOR takes.
func channelPolicy(signingName tpm2.TPM2BName, policyRef []byte, bank tpm2.TPMIAlgHash) (policy []byte, branches tpm2.TPMLDigest, err error) {
	open, err := attest.OpenPCRDigest(bank)
	if err != nil {
		return nil, branches, err
	}
	unseal := tpm2.PolicyCommandCode{Code: tpm2.TPMCCUnseal}
	digest := func(update ...func(*tpm2.PolicyCalculator) error) (tpm2.TPM2BDigest, error) {
		calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return tpm2.TPM2BDigest{}, err
		}
		for _, u := range update {
			if err := u(calc); err != nil {
				return tpm2.TPM2BDigest{}, err
			}
		}
		return tpm2.TPM2BDigest{Buffer: calc.Hash().Digest}, nil
	}
	gate, err := digest(tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: open}, Pcrs: attest.ClosePCRSelection(bank)}.Update, unseal.Update)
	if err != nil {
		return nil, branches, err
	}
	signed, err := digest(tpm2.PolicySigned{
		AuthObject: tpm2.NamedHandle{Name: signingName},
		PolicyRef:  tpm2.TPM2BNonce{Buffer: policyRef},
	}.Update, unseal.Update)
	if err != nil {
		return nil, branches, err
	}
	branches = tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{gate, signed}}
	all, err := digest(tpm2.PolicyOr{PHashList: branches}.Update)
	if err != nil {
		return nil, branches, err
	}
	return all.Buffer, branches, nil
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

// SealChannel seals c in this TPM for the slot sb is, and returns the object's
// public and private areas, what the record's phone method holds. The secrets go
// to the TPM in a salted, parameter-encrypted session.
func SealChannel(t transport.TPM, sb *SealedBlob, c *ChannelSecrets) (public, private []byte, err error) {
	if len(c.NoisePrivate)+len(c.AdvKey) != channelSecretSize || len(c.NoisePrivate) != 32 {
		return nil, nil, errors.New("the channel's secrets are incomplete")
	}
	name, err := slotSigningName(sb)
	if err != nil {
		return nil, nil, err
	}
	policy, _, err := channelPolicy(name, sb.Payload.PolicyRef, sb.GetHashAlgo().TPMAlg())
	if err != nil {
		return nil, nil, err
	}
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

// channelObject is what unsealing needs: the bank the object reads PCR 15 in, the
// slot's bank when it was sealed, which the object's own policy tells.
func channelObject(sb *SealedBlob) (name tpm2.TPM2BName, bank tpm2.TPMIAlgHash, branches tpm2.TPMLDigest, err error) {
	att := sb.Payload.Attestation
	if att == nil || !att.Phone.Enabled() {
		return name, 0, branches, errors.New("the slot has no phone channel")
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](att.Phone.ChannelPublic)
	if err != nil {
		return name, 0, branches, fmt.Errorf("the channel's sealed object does not parse: %w", err)
	}
	if name, err = slotSigningName(sb); err != nil {
		return name, 0, branches, err
	}
	for _, bank := range []tpm2.TPMIAlgHash{tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA1} {
		policy, branches, err := channelPolicy(name, sb.Payload.PolicyRef, bank)
		if err != nil {
			return name, 0, branches, err
		}
		if bytes.Equal(policy, pub.AuthPolicy.Buffer) {
			return name, bank, branches, nil
		}
	}
	return name, 0, branches, errors.New("the channel's sealed object is not this slot's: its policy differs; enrol the phones again")
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
	// A session of its own, flushed on every way out: a callback session that
	// fails its policy would stay in the TPM.
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
// any boot. ErrClosed after it.
func UnsealChannel(t transport.TPM, sb *SealedBlob) (*ChannelSecrets, error) {
	_, bank, branches, err := channelObject(sb)
	if err != nil {
		return nil, err
	}
	open, err := attest.OpenPCRDigest(bank)
	if err != nil {
		return nil, err
	}
	return unsealChannel(t, sb, branches, func(tpm transport.TPM, handle tpm2.TPMHandle, _ tpm2.TPM2BNonce) error {
		if _, err := (tpm2.PolicyPCR{
			PolicySession: handle,
			PcrDigest:     tpm2.TPM2BDigest{Buffer: open},
			Pcrs:          attest.ClosePCRSelection(bank),
		}).Execute(tpm); err != nil {
			if errors.Is(err, tpm2.TPMRCValue) {
				return ErrClosed
			}
			return fmt.Errorf("PolicyPCR(%d): %w", attest.ClosePCR, err)
		}
		return nil
	})
}

// UnsealChannelSigned opens the channel's secrets with the slot's signing key,
// which signs the TPM's nonce for this one session: on the running system, for
// another phone or the phone salt's hand-over.
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
