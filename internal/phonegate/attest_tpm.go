package phonegate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// TPM-facing half of attestation: AK and EK handling, quotes and credential
// activation. The protocol and every verification decision live in attest/;
// this file only talks to the TPM.

// EK certificate NV indices (TCG EK Credential Profile).
const (
	ekCertNVRSA = 0x01C00002
	ekCertNVECC = 0x01C0000A
)

// createAKParent derives the AK's parent: the same storage primary template
// as CreatePrimaryKey, but in the *endorsement* hierarchy.
//
// This matters for the evidence, not for convenience. TPM 2.0 Part 1 §36.7:
// when the signing key is not in the endorsement or platform hierarchy,
// TPM2_Quote obfuscates clockInfo.resetCount, restartCount and
// firmwareVersion with a per-key mask. An owner-hierarchy AK therefore
// reports counters whose order means nothing, and the verifier's "reset count
// went backwards" replay check would be void. In the endorsement hierarchy the
// TPM reports them plainly.
//
// Side effect, also wanted: the endorsement seed survives TPM2_Clear, so the
// AK does too, while resetCount restarts — which the verifier then flags.
func createAKParent(tpmDev transport.TPM) (*tpmdev.PrimaryKeyResponse, error) {
	tmpl := tpmdev.StoragePrimaryTemplate()
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to create the attestation key's parent in the endorsement hierarchy (endorsement auth set?): %w", err)
	}
	return &tpmdev.PrimaryKeyResponse{ObjectHandle: rsp.ObjectHandle, Name: rsp.Name}, nil
}

// CreateAK creates an attestation key under the endorsement-hierarchy
// storage primary and returns its marshalled public area, private area and
// Name. The ECC template is tried first; RSA is the fallback for TPMs that
// refuse it.
func CreateAK(tpmDev transport.TPM) (pub, priv, name []byte, err error) {
	primary, err := createAKParent(tpmDev)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tpmdev.FlushHandle(tpmDev, primary.ObjectHandle)

	var lastErr error
	for _, tmpl := range []tpm2.TPMTPublic{attest.AKTemplateECC(), attest.AKTemplateRSA()} {
		rsp, err := tpm2.Create{
			ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
			InPublic:     tpm2.New2B(tmpl),
		}.Execute(tpmDev)
		if err != nil {
			lastErr = err
			continue
		}
		pubT, err := rsp.OutPublic.Contents()
		if err != nil {
			return nil, nil, nil, err
		}
		n, err := tpm2.ObjectName(pubT)
		if err != nil {
			return nil, nil, nil, err
		}
		return tpm2.Marshal(*pubT), rsp.OutPrivate.Buffer, n.Buffer, nil
	}
	return nil, nil, nil, fmt.Errorf("TPM refused to create an attestation key: %w", lastErr)
}

type loadedKey struct {
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
}

// loadAK loads the AK from the blob under a freshly derived storage primary.
// The caller must flush the returned handle.
func loadAK(tpmDev transport.TPM, b *nvslot.Attestation) (*loadedKey, error) {
	primary, err := createAKParent(tpmDev)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(tpmDev, primary.ObjectHandle)
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](b.AKPublic)
	if err != nil {
		return nil, fmt.Errorf("stored AK public area is corrupt: %w", err)
	}
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(*pub),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: b.AKPrivate},
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("failed to load the attestation key (was the TPM cleared?): %w", err)
	}
	if !bytes.Equal(rsp.Name.Buffer, b.AKName) {
		tpmdev.FlushHandle(tpmDev, rsp.ObjectHandle)
		return nil, fmt.Errorf("loaded attestation key does not match the stored Name")
	}
	return &loadedKey{Handle: rsp.ObjectHandle, Name: rsp.Name}, nil
}

// CreateEK creates the endorsement key from the TCG template for alg.
// The caller must flush the returned handle.
func CreateEK(tpmDev transport.TPM, alg uint16) (*loadedKey, []byte, error) {
	tmpl := attest.EKTemplateECC
	if alg == uint16(tpm2.TPMAlgRSA) {
		tmpl = attest.EKTemplateRSA
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the endorsement key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		tpmdev.FlushHandle(tpmDev, rsp.ObjectHandle)
		return nil, nil, err
	}
	return &loadedKey{Handle: rsp.ObjectHandle, Name: rsp.Name}, tpm2.Marshal(*pub), nil
}

// pickEK creates the ECC EK if the TPM supports it, otherwise the RSA EK.
func pickEK(tpmDev transport.TPM) (uint16, *loadedKey, []byte, error) {
	if k, pub, err := CreateEK(tpmDev, uint16(tpm2.TPMAlgECC)); err == nil {
		return uint16(tpm2.TPMAlgECC), k, pub, nil
	}
	k, pub, err := CreateEK(tpmDev, uint16(tpm2.TPMAlgRSA))
	if err != nil {
		return 0, nil, nil, err
	}
	return uint16(tpm2.TPMAlgRSA), k, pub, nil
}

// PickCertifiedEK prefers the EK whose algorithm has a vendor certificate,
// so the phone can verify it: Intel PTT, for one, often certifies only the
// RSA EK. Without any certificate it falls back to pickEK.
func PickCertifiedEK(tpmDev transport.TPM) (uint16, *loadedKey, []byte, error) {
	for _, alg := range []uint16{uint16(tpm2.TPMAlgECC), uint16(tpm2.TPMAlgRSA)} {
		if len(ReadEKCert(tpmDev, alg)) == 0 {
			continue
		}
		if k, pub, err := CreateEK(tpmDev, alg); err == nil {
			return alg, k, pub, nil
		}
	}
	return pickEK(tpmDev)
}

// ReadEKCertChain reads the TPM's intermediates for the EK certificate (Intel
// PTT keeps them concatenated in EKCertChainNVIndex); nil when absent.
func ReadEKCertChain(tpmDev transport.TPM, leaf []byte) []byte {
	data, err := tpmdev.ReadFromNVRAM(tpmDev, attest.EKCertChainNVIndex)
	if err != nil || len(data) > attest.MaxEKCertChain {
		data = nil
	}
	// The issuers the TPM does not carry - Intel's P_MCC issuing CA of
	// this product family - from the caIssuers URL, cached: the phone has
	// no network, the machine sends what it found. Trust comes from the
	// embedded root alone (attest.CompleteEKChain).
	return attest.CompleteEKChain(leaf, data, FetchEKIssuer)
}

// EKIssuerCacheDir keeps the issuers fetched for the EK chain; a var for
// the tests. Anything in it is an untrusted intermediate like the TPM's.
var EKIssuerCacheDir = "/var/cache/tpm2-kira/ek-issuers"

// EKFetchFailed remembers, for this process, the URLs that failed: an
// offline machine pays the timeout once per run, not per overview.
var EKFetchFailed sync.Map

// FetchEKIssuer fetches a certificate from a caIssuers URL: the cache
// first, then the network (http or https, 5 s, 64 KiB at most).
var FetchEKIssuer = func(url string) ([]byte, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("not an http URL: %q", url)
	}
	sum := sha256.Sum256([]byte(url))
	cached := filepath.Join(EKIssuerCacheDir, hex.EncodeToString(sum[:])+".der")
	if b, err := os.ReadFile(cached); err == nil {
		return b, nil
	}
	if _, failed := EKFetchFailed.Load(url); failed {
		return nil, errors.New("fetched before, and it failed")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		EKFetchFailed.Store(url, true)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		EKFetchFailed.Store(url, true)
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		EKFetchFailed.Store(url, true)
		return nil, err
	}
	if os.MkdirAll(EKIssuerCacheDir, 0o755) == nil {
		_ = os.WriteFile(cached, b, 0o644) // a cache: losing it costs a fetch
	}
	return b, nil
}

// ReadEKCert reads the vendor EK certificate, if the TPM has one. Firmware
// TPMs frequently do not; that is reported, never required.
func ReadEKCert(tpmDev transport.TPM, alg uint16) []byte {
	idx := uint32(ekCertNVECC)
	if alg == uint16(tpm2.TPMAlgRSA) {
		idx = ekCertNVRSA
	}
	data, err := tpmdev.ReadFromNVRAM(tpmDev, idx)
	if err != nil || len(data) == 0 {
		return nil
	}
	// Some TPMs pad the NV index; trim to the DER length.
	if len(data) > 4 && data[0] == 0x30 && data[1] == 0x82 {
		if n := int(data[2])<<8 | int(data[3]); 4+n <= len(data) {
			data = data[:4+n]
		}
	}
	return data
}

// EndorsementPolicy satisfies the TCG EK's authPolicy:
// TPM2_PolicySecret(TPM_RH_ENDORSEMENT) with an empty endorsement auth.
// Using the EK with a plain password session fails with TPM_RC_AUTH_UNAVAILABLE.
func EndorsementPolicy() tpm2.Session {
	return tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonce tpm2.TPM2BNonce) error {
		_, err := tpm2.PolicySecret{
			AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
			PolicySession: handle,
			NonceTPM:      nonce,
		}.Execute(tpm)
		return err
	})
}

// ReadPCRBank reads PCRs in chunks of at most 8 (the most a TPM returns per
// PCR_Read) and checks the TPM returned exactly what was asked for.
func ReadPCRBank(tpmDev transport.TPM, sel attest.PCRSelection) ([]attest.PCRValue, error) {
	var out []attest.PCRValue
	for i := 0; i < len(sel.Indices); i += 8 {
		end := i + 8
		if end > len(sel.Indices) {
			end = len(sel.Indices)
		}
		part := attest.PCRSelection{Alg: sel.Alg, Indices: sel.Indices[i:end]}
		rsp, err := tpm2.PCRRead{PCRSelectionIn: part.ToTPM()}.Execute(tpmDev)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs: %w", err)
		}
		if len(rsp.PCRValues.Digests) != len(part.Indices) {
			return nil, fmt.Errorf("TPM returned %d of %d requested PCRs (bank 0x%04x enabled?)", len(rsp.PCRValues.Digests), len(part.Indices), sel.Alg)
		}
		for j, d := range rsp.PCRValues.Digests {
			out = append(out, attest.PCRValue{Index: part.Indices[j], Digest: d.Buffer})
		}
	}
	return out, nil
}

// TPMBackend implements attest.EnrolBackend on a real TPM.
type TPMBackend struct {
	TPM       transport.TPM
	Blob      *nvslot.Attestation
	SealIndex uint32
	Sealed    *nvslot.SealedBlob // may be nil
	Debug     bool
	BootCode  string // the code of the last boot challenge the TPM opened

	// enrolment only
	Baseline     *measurePoint // the baseline prediction, computed once
	OnConfirmSAS func(code string) (bool, error)
	OnCommit     func(v attest.EnrolledVerifier) error
	PhoneJudge   attest.PhoneAttestationJudge // nil: no check of the phone's key
	EKAlgorithm  uint16
	EventlogData []byte
	EventlogRead bool
	initrd       *initrdCoverage // read once from the event log
}

// Quote implements attest.AttesterBackend.
func (b *TPMBackend) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
	ak, err := loadAK(b.TPM, b.Blob)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(b.TPM, ak.Handle)

	// PCRs are read after the quote. If one is extended in between, the
	// values no longer reproduce the quoted digest: retry rather than send
	// evidence the verifier would reject.
	for attempt := 0; attempt < 3; attempt++ {
		rsp, err := tpm2.Quote{
			SignHandle:     tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
			QualifyingData: tpm2.TPM2BData{Buffer: qd},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
			PCRSelect:      sel.ToTPM(),
		}.Execute(b.TPM)
		if err != nil {
			return nil, fmt.Errorf("TPM2_Quote failed: %w", err)
		}
		quoted := rsp.Quoted.Bytes()
		att, err := rsp.Quoted.Contents()
		if err != nil {
			return nil, err
		}
		info, err := att.Attested.Quote()
		if err != nil {
			return nil, err
		}
		vals, err := ReadPCRBank(b.TPM, sel)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(attest.CompositeDigest(sel, vals), info.PCRDigest.Buffer) {
			if b.Debug {
				fmt.Println("PCRs changed between quote and read; quoting again")
			}
			continue
		}
		return &attest.QuoteResult{Quoted: quoted, Signature: tpm2.Marshal(rsp.Signature), Values: vals}, nil
	}
	return nil, fmt.Errorf("PCRs kept changing while quoting")
}

// BootContext implements attest.AttesterBackend.
func (b *TPMBackend) BootContext() attest.BootContext {
	bc := attest.BootContext{BlobVersion: nvslot.CurrentBlobVersion, NVRAMIndex: b.SealIndex, UptimeMS: uptimeMS()}
	if b.Sealed != nil {
		bc.BlobVersion = b.Sealed.Version
	}
	if b.Sealed != nil {
		bc.MeasurePoint = b.Sealed.MeasurePointExtends()
		for _, i := range b.Sealed.GetPCRIndices() {
			if i >= 0 && i < attest.MaxPCRIndex {
				bc.SealPCRSelection = append(bc.SealPCRSelection, uint8(i))
			}
		}
	}
	if b.initrd == nil {
		cov, _ := readInitrdCoverage(measure.DefaultEventlogPath)
		b.initrd = &cov
	}
	// Only a recognised measurement is reported; "none found" may just be a
	// boot path this version does not know, so it stays unknown.
	if len(b.initrd.PCRs) > 0 {
		bc.InitrdState = attest.InitrdMeasured
		for _, p := range b.initrd.PCRs {
			bc.InitrdPCRs = append(bc.InitrdPCRs, uint8(p))
		}
	}
	sb := measure.ReadSecureBootState()
	switch {
	case !sb.Known:
		bc.SecureBootState = attest.SecureBootUnknown
	case sb.SetupMode:
		bc.SecureBootState = attest.SecureBootSetupMode
	case sb.Enabled:
		bc.SecureBootState = attest.SecureBootEnabled
	default:
		bc.SecureBootState = attest.SecureBootDisabled
	}
	return bc
}

func uptimeMS() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	s, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return uint64(s * 1000)
}

// Eventlog implements attest.AttesterBackend. The log is only ever read from
// DefaultEventlogPath, never from a path supplied by a blob or a peer.
func (b *TPMBackend) Eventlog() ([]byte, error) {
	if !b.EventlogRead {
		b.EventlogRead = true
		data, err := os.ReadFile(measure.DefaultEventlogPath)
		if err == nil && len(data) <= attest.MaxEventlogSize {
			b.EventlogData = data
		}
	}
	return b.EventlogData, nil
}

// EKPublic implements attest.EnrolBackend.
func (b *TPMBackend) EKPublic() ([]byte, []byte, error) {
	alg, ek, pub, err := PickCertifiedEK(b.TPM)
	if err != nil {
		return nil, nil, err
	}
	tpmdev.FlushHandle(b.TPM, ek.Handle)
	b.EKAlgorithm = alg
	b.Blob.EKAlg = alg
	return pub, ReadEKCert(b.TPM, alg), nil
}

// EKCertChain implements attest.EKChainProvider.
func (b *TPMBackend) EKCertChain() []byte {
	return ReadEKCertChain(b.TPM, ReadEKCert(b.TPM, b.EKAlgorithm))
}

// ActivateCredential implements attest.EnrolBackend.
func (b *TPMBackend) ActivateCredential(blob, encSecret []byte) ([]byte, error) {
	ak, err := loadAK(b.TPM, b.Blob)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(b.TPM, ak.Handle)
	ek, _, err := CreateEK(b.TPM, b.EKAlgorithm)
	if err != nil {
		return nil, err
	}
	defer tpmdev.FlushHandle(b.TPM, ek.Handle)
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.Handle, Name: ek.Name, Auth: EndorsementPolicy()},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: blob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
	}.Execute(b.TPM)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ActivateCredential failed: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// ConfirmSAS implements attest.EnrolBackend.
func (b *TPMBackend) ConfirmSAS(code string) (bool, error) { return b.OnConfirmSAS(code) }

// JudgePhone implements attest.PhoneAttestationJudge.
func (b *TPMBackend) JudgePhone(a attest.PhoneAttestation) (bool, error) {
	if b.PhoneJudge == nil {
		return true, nil
	}
	return b.PhoneJudge.JudgePhone(a)
}

// BootKey implements attest.EnrolBackend: the slot's boot key, made at the
// first enrolment under the policy of the slot's TOTP key, and certified by
// the attestation key.
func (b *TPMBackend) BootKey(qd []byte) (*attest.BootKeyOffer, error) {
	if b.Sealed == nil {
		return nil, errors.New("the slot has no sealed TOTP key whose policy the boot key could share")
	}
	if len(b.Blob.BootKeyPublic) == 0 {
		pub, priv, err := CreateBootKey(b.TPM, b.Sealed)
		if err != nil {
			return nil, err
		}
		b.Blob.BootKeyPublic, b.Blob.BootKeyPrivate = pub, priv
	}
	info, sig, err := certifyBootKey(b.TPM, b.Blob, qd)
	if err != nil {
		return nil, err
	}
	return &attest.BootKeyOffer{
		PubArea: b.Blob.BootKeyPublic, CertifyInfo: info, CertifySig: sig,
		SigningPub: b.Sealed.Payload.SigningPublic, PolicyRef: b.Sealed.Payload.PolicyRef,
	}, nil
}

// ProveBootKey implements attest.AttesterBackend. The code is kept for
// whoever shows it to the person at the machine (BootCode).
func (b *TPMBackend) ProveBootKey(ch *attest.BootChallenge, context, quoteDigest []byte) (*attest.BootAnswer, uint8) {
	b.BootCode = ""
	code, proof, err := OpenBootChallenge(b.TPM, b.Sealed, b.SealIndex, b.Blob, ch, context)
	var sig []byte
	if err == nil {
		d := sha256.Sum256(attest.BootSignatureMessage(context, quoteDigest))
		sig, err = SignWithBootKey(b.TPM, b.Sealed, b.SealIndex, b.Blob, d[:])
	}
	switch {
	case errors.Is(err, nvslot.ErrCodesLocked):
		// The booted system: 'cap' locked the slot until the next boot.
		if b.Debug {
			fmt.Printf("tpm2-kira: boot key: %v\n", err)
		}
		return nil, attest.BootKeyLocked
	case errors.Is(err, ErrBootKeyRefused):
		if b.Debug {
			fmt.Printf("tpm2-kira: boot key: %v\n", err)
		}
		return nil, attest.BootKeyRefused
	case err != nil:
		if b.Debug {
			fmt.Printf("tpm2-kira: boot key: %v\n", err)
		}
		return nil, attest.BootKeyFailed
	}
	b.BootCode = code
	return &attest.BootAnswer{Proof: proof, Signature: sig}, attest.BootKeyProved
}

// Commit implements attest.EnrolBackend.
func (b *TPMBackend) Commit(v attest.EnrolledVerifier) error { return b.OnCommit(v) }
