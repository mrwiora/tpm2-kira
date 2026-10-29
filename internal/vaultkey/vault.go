// Package vaultkey makes the disk's key from a vault at boot: the remote part
// released under the slot's approval, joined with this TPM's local part.
package vaultkey

// The disk's key from two TPMs: the local part in this machine's TPM, the
// remote part kept by tpm2-kira-vault (docs/VAULT.md, package vaultproto).
//
// Both parts are 32 random bytes, wrapped (TPM2_MakeCredential) for this
// TPM's EK and the slot's release key: they open only through the release
// key's policy, the slot's approval for this boot state, and only before
// 'cap'. The local part is kept in the slot's blob (the vault method); the
// remote part only by the vault, which releases it to a fresh quote of a
// boot state the slot's signing key approved. Neither is ever stored in
// the clear, and the key is derived from both in the moment.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/hkdf"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/vaultproto"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/screen"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
	"github.com/mrwiora/tpm2-kira/internal/untrusted"
	"github.com/mrwiora/tpm2-kira/internal/wipe"
)

// The derivation strings of the vault's parts as the combiner's inputs:
// part of the contract between an enrolled keyslot and this code.
const (
	vaultSaltInfo     = "tpm2-kira/vault/salt/v1"
	vaultPasswordInfo = "tpm2-kira/vault/password/v1"
)

// Salt makes the vault's part R the combiner's salt: 64 lowercase
// hexadecimal characters, HKDF-SHA256(R, salt = pepper, info =
// vaultSaltInfo ‖ lp(label)). With a pepper (an operator's, given at the
// vault's approval, docs/VAULT.md §12) the salt is another, so every
// guessed pepper costs a whole Argon2id of the combiner; nil without.
func Salt(remote []byte, label string, pepper []byte) []byte {
	return hkdfHex(remote, pepper, vaultSaltInfo, label)
}

// Password makes the TPM's part L the password of an unattended recipe
// (0x2400, 0x2401): 64 lowercase hexadecimal characters, HKDF-SHA256(L,
// info = vaultPasswordInfo ‖ lp(label)).
func Password(local []byte, label string) []byte {
	return hkdfHex(local, nil, vaultPasswordInfo, label)
}

// Key is an unattended recipe's key: the combiner's (Argon2id) of the
// TPM's part as the password and the vault's as the salt. The caller
// wipes it.
func Key(local, remote []byte, label string, pepper []byte) ([]byte, error) {
	pw := Password(local, label)
	defer wipe.Bytes(pw)
	salt := Salt(remote, label, pepper)
	defer wipe.Bytes(salt)
	return diskkey.Combine(pw, salt)
}

func hkdfHex(secret, salt []byte, what, label string) []byte {
	if label == "" {
		label = "luks"
	}
	info := append([]byte(what), byte(len(label)>>8), byte(len(label)))
	info = append(info, label...)
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), out); err != nil {
		panic(err) // HKDF with a fixed length cannot fail
	}
	defer wipe.Bytes(out)
	return []byte(hex.EncodeToString(out))
}

// ── the client ─────────────────────────────────────────────────────────────

// vaultClient speaks to the vault over HTTPS with its key pinned: TLS 1.3,
// the certificate's SubjectPublicKeyInfo must hash to the pin. There is no
// chain and no expiry to check - the initrd has no clock to check one with
// - and a key that does not match is a refused vault, not a warning.
type vaultClient struct {
	base string
	hc   *http.Client
}

func NewClient(rawURL, pin string) (*vaultClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("the vault's URL must be https://host[:port], not %q", rawURL)
	}
	if !strings.HasPrefix(pin, "sha256:") || len(pin) != 7+64 {
		return nil, fmt.Errorf("the vault's pin must be sha256: and 64 hexadecimal characters, as 'tpm2-kira-vault token create' prints it")
	}
	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // the pin below is the check
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the vault presented no certificate")
			}
			return checkVaultPin(cs.PeerCertificates[0], pin)
		},
	}
	return &vaultClient{
		base: "https://" + u.Host,
		hc: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConf, Proxy: nil, ForceAttemptHTTP2: false},
			Timeout:   15 * time.Second,
		},
	}, nil
}

func checkVaultPin(cert *x509.Certificate, pin string) error {
	if got := vaultproto.PinOf(cert.RawSubjectPublicKeyInfo); got != strings.ToLower(pin) {
		return fmt.Errorf("the vault's key is not the pinned one (%s, pinned %s)", got, pin)
	}
	return nil
}

// Post sends in as JSON and decodes the answer into out; an answer that is
// not 2xx is an error with the vault's words.
func (c *vaultClient) Post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	rsp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
	if err != nil {
		return err
	}
	if rsp.StatusCode/100 != 2 {
		var e vaultproto.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("the vault: %s", untrusted.Quote(e.Error))
		}
		return fmt.Errorf("the vault answered %s", rsp.Status)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("the vault's answer does not parse: %w", err)
	}
	return nil
}

// vaultCheck is control's look at a vault: whether it answers with the
// pinned key, and whether it knows this machine.
type CheckResult struct {
	Answers bool   // reached, the pinned key, and it answered
	Knows   bool   // it handed out a challenge for the device
	Problem string // why not; "" when it answers and knows the device
}

// checkVault asks the vault for a challenge for device - nil before the
// enrolment: an ID of zeros, which no vault hands out, so any answer of
// the vault's own is the one wanted. From the running system: the image's
// network may reach it by another route, or not at all.
func Check(rawURL, pin string, device []byte, timeout time.Duration) CheckResult {
	c, err := NewClient(rawURL, pin)
	if err != nil {
		return CheckResult{Problem: err.Error()}
	}
	if device == nil {
		device = make([]byte, vaultproto.DeviceIDSize)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var ch vaultproto.ChallengeResponse
	err = c.Post(ctx, vaultproto.PathChallenge, vaultproto.ChallengeRequest{DeviceID: device}, &ch)
	var ue *url.Error
	switch {
	case err == nil:
		return CheckResult{Answers: true, Knows: true}
	case strings.Contains(err.Error(), "not the pinned one"):
		return CheckResult{Problem: "it answers with another key than the pinned one"}
	case errors.As(err, &ue):
		return CheckResult{Problem: "not reachable (" + ue.Err.Error() + ")"}
	}
	return CheckResult{Answers: true, Problem: err.Error()}
}

// ── one slot's vault ──────────────────────────────────────────────────────

// vaultSlot is a slot whose blob carries the vault method.
type vaultSlot struct {
	Idx    uint32
	Sealed *nvslot.SealedBlob
	Att    *nvslot.Attestation
}

// vaultSlots lists the slots with the vault method.
func Slots(tpmDev transport.TPM, debug bool) []vaultSlot {
	var out []vaultSlot
	for _, idx := range nvslot.FindPopulatedSlots(tpmDev, debug) {
		_, sb, err := phonegate.ReadSlot(tpmDev, idx)
		if err != nil || sb.Payload.Attestation == nil || !sb.Payload.Attestation.Vault.Enabled() {
			continue
		}
		out = append(out, vaultSlot{Idx: idx, Sealed: sb, Att: sb.Payload.Attestation})
	}
	return out
}

// SealedSelection is the slot's sealed PCR selection: what the approval
// covers, and so what is quoted for the vault.
func SealedSelection(sb *nvslot.SealedBlob) vaultproto.Selection {
	var idx []uint8
	for _, i := range sb.GetPCRIndices() {
		idx = append(idx, uint8(i))
	}
	sort.Slice(idx, func(a, b int) bool { return idx[a] < idx[b] })
	return vaultproto.Selection{Alg: uint16(sb.GetHashAlgo().TPMAlg()), Indices: idx}
}

// FetchRemote asks the vault for the slot's remote part: a challenge, a
// quote of the slot's selection over it, the slot's approval - and, while
// the vault says pending, the same request again. say tells the console.
func FetchRemote(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, c *vaultClient, say func(string)) (*vaultproto.ReleaseResponse, error) {
	id := vs.Att.DeviceID
	var ch vaultproto.ChallengeResponse
	if err := c.Post(ctx, vaultproto.PathChallenge, vaultproto.ChallengeRequest{DeviceID: id}, &ch); err != nil {
		return nil, err
	}
	if len(ch.Nonce) != vaultproto.NonceSize || ch.RequestID == "" {
		return nil, errors.New("the vault's challenge is malformed")
	}
	sel := SealedSelection(vs.Sealed)
	be := &phonegate.TPMBackend{TPM: tpmDev, Blob: vs.Att}
	q, err := be.Quote(vaultproto.QualifyingData(id, ch.RequestID, ch.Nonce), attest.PCRSelection{Alg: sel.Alg, Indices: sel.Indices})
	if err != nil {
		return nil, err
	}
	p := &vs.Sealed.Payload
	req := vaultproto.ReleaseRequest{
		RequestID:         ch.RequestID,
		DeviceID:          id,
		Quoted:            q.Quoted,
		QuoteSignature:    q.Signature,
		Generation:        p.Generation,
		ApprovalSignature: p.ApprovalSignature,
	}
	for _, v := range q.Values {
		req.PCRValues = append(req.PCRValues, vaultproto.PCRValue{Index: v.Index, Value: v.Digest})
	}
	toldPending := false
	for {
		var rsp vaultproto.ReleaseResponse
		if err := c.Post(ctx, vaultproto.PathRelease, req, &rsp); err != nil {
			return nil, err
		}
		switch rsp.Status {
		case vaultproto.StatusReleased:
			if rsp.Remote == nil {
				return nil, errors.New("the vault released nothing")
			}
			return &rsp, nil
		case vaultproto.StatusDenied:
			return nil, fmt.Errorf("the vault refused: %s", untrusted.Quote(rsp.Reason))
		case vaultproto.StatusPending:
			if !toldPending {
				say("the vault waits for an operator's approval of this boot")
				toldPending = true
			}
			wait := time.Duration(rsp.RetryAfter) * time.Second
			if wait < time.Second || wait > 10*time.Second {
				wait = 2 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, errors.New("the code screen ended before the vault approved")
			case <-time.After(wait):
			}
		default:
			return nil, fmt.Errorf("the vault answered %q", untrusted.Quote(rsp.Status))
		}
	}
}

// Open makes what the slot's vault method gives in this boot. Unattended
// (the TPM's part L in the slot: 0x2400, 0x2401), the key: L first - when
// the TPM does not open it, this boot state is not one the signing key
// approved, and the vault is not asked - then the vault's part, opened
// under the same policy, and the combiner; for a keyslot enrolled with a
// pepper, one that does not fit the slot's check (mistyped at the
// approval) is not handed to cryptsetup: the vault is asked again, for a
// new approval. With a typed password (0x1400, 0x1401), the salt, for the
// key provider to combine with the password asked after the code screen.
// The caller wipes what it gets.
func Open(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, say func(string)) (key, salt []byte, err error) {
	v := &vs.Att.Vault
	var local []byte
	if v.Unattended() {
		if local, err = phonegate.UnwrapFactor(tpmDev, vs.Sealed, vs.Idx, vs.Att, &v.Local); err != nil {
			return nil, nil, fmt.Errorf("the local part: %w", err)
		}
		defer wipe.Bytes(local)
	}
	c, err := NewClient(v.URL, v.Pin)
	if err != nil {
		return nil, nil, err
	}
	for {
		rsp, err := fetchRemoteRetrying(ctx, tpmDev, vs, c, say)
		if err != nil {
			return nil, nil, err
		}
		salt, err := saltOf(tpmDev, vs, rsp)
		if err != nil {
			return nil, nil, err
		}
		if local == nil {
			return nil, salt, nil
		}
		pw := Password(local, v.Label)
		key, err := diskkey.Combine(pw, salt)
		wipe.Bytes(pw)
		wipe.Bytes(salt)
		if err != nil {
			return nil, nil, err
		}
		if len(v.PepperCheck) > 0 && !hmac.Equal(PepperCheck(key), v.PepperCheck) {
			wipe.Bytes(key)
			say("the pepper given with the approval does not fit this keyslot; asking the vault for a new approval")
			continue
		}
		return key, nil, nil
	}
}

// saltOf opens the released remote part and makes it the salt, with the
// pepper the release carries when the keyslot was enrolled with one. R and
// the pepper's key K open alike: ActivateCredential with the slot's
// release key, through the slot's approval for this boot.
func saltOf(tpmDev transport.TPM, vs vaultSlot, rsp *vaultproto.ReleaseResponse) ([]byte, error) {
	v := &vs.Att.Vault
	switch {
	case !v.Pepper && rsp.Pepper != nil:
		return nil, errors.New("the vault sent a pepper, and this keyslot was enrolled without one")
	case v.Pepper && rsp.Pepper == nil:
		return nil, errors.New("the vault released without a pepper, and this keyslot was enrolled with one")
	}
	remote, err := phonegate.UnwrapFactor(tpmDev, vs.Sealed, vs.Idx, vs.Att, &nvslot.WrappedFactor{Credential: rsp.Remote.Credential, EncryptedSecret: rsp.Remote.EncryptedSecret})
	if err != nil {
		return nil, fmt.Errorf("the remote part: %w", err)
	}
	defer wipe.Bytes(remote)
	if !v.Pepper {
		return Salt(remote, v.Label, nil), nil
	}
	p, err := openPepper(tpmDev, vs, rsp.Pepper)
	if err != nil {
		return nil, err
	}
	defer wipe.Bytes(p)
	return Salt(remote, v.Label, p), nil
}

// openPepper opens the pepper's key K in the TPM and the pepper with it.
func openPepper(tpmDev transport.TPM, vs vaultSlot, w *vaultproto.WrappedPepper) ([]byte, error) {
	k, err := phonegate.UnwrapFactor(tpmDev, vs.Sealed, vs.Idx, vs.Att, &nvslot.WrappedFactor{Credential: w.Key.Credential, EncryptedSecret: w.Key.EncryptedSecret})
	if err != nil {
		return nil, fmt.Errorf("the pepper: %w", err)
	}
	defer wipe.Bytes(k)
	p, err := vaultproto.OpenPepper(k, vs.Att.DeviceID, w)
	if err != nil {
		return nil, fmt.Errorf("the pepper: %w", err)
	}
	return p, nil
}

// fetchRemoteRetrying is fetchRemote while the network comes up:
// connection errors are tried again until ctx ends, an answer is final.
func fetchRemoteRetrying(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, c *vaultClient, say func(string)) (*vaultproto.ReleaseResponse, error) {
	told := false
	for {
		rsp, err := FetchRemote(ctx, tpmDev, vs, c, say)
		if err == nil || !Retryable(err) {
			return rsp, err
		}
		if !told {
			say(fmt.Sprintf("the vault at %s is not reachable yet (%v); trying until it is", vs.Att.Vault.URL, err))
			told = true
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("the code screen ended before the vault at %s was reached: %v", vs.Att.Vault.URL, err)
		case <-time.After(time.Second):
		}
	}
}

// vaultPepperCheck is what the slot keeps to recognise the key made with
// the right pepper: HMAC-SHA256(key, "tpm2-kira/vault/pepper-check/v1").
// It is no help in guessing the pepper without L and R, which only the
// TPM opens.
func PepperCheck(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tpm2-kira/vault/pepper-check/v1"))
	return m.Sum(nil)
}

// retryableVaultError: the vault was not reached (no route, no address
// yet, refused connection, a timeout), as opposed to an answer.
func Retryable(err error) bool {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return false
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) || strings.Contains(err.Error(), "not the pinned one") {
		return false // reached, and it is not our vault
	}
	return true
}

// ── at boot ───────────────────────────────────────────────────────────────

// Keys are what run made of the vault in this boot, by slot number, for
// the key provider to answer with: an unattended recipe's key, a typed
// recipe's salt; done is closed when every slot has been tried.
type Keys struct {
	keys  map[int][]byte
	salts map[int][]byte
	errs  map[int]error
	done  chan struct{}
}

// startVaultKeys opens, in the background, the key of every slot with the
// vault method - while the code screen holds, because the parts open only
// in the approved boot state; ctx ends with the hold. What happens goes to
// out (the console) and to log (the boot's log). Nil when no slot has the
// method.
func Start(ctx context.Context, tpmPath string, out io.Writer, log func(string), debug bool) *Keys {
	tpmDev, err := tpmdev.Open(tpmdev.PreferResourceManager(tpmPath))
	if err != nil {
		return nil
	}
	slots := Slots(tpmDev, debug)
	if len(slots) == 0 {
		tpmDev.Close()
		return nil
	}
	vk := &Keys{keys: map[int][]byte{}, salts: map[int][]byte{}, errs: map[int]error{}, done: make(chan struct{})}
	go func() {
		defer close(vk.done)
		defer tpmDev.Close()
		for _, vs := range slots {
			n := nvslot.SlotNumber(vs.Idx)
			say := func(s string) {
				fmt.Fprintf(out, "%s Slot #%d: %s\n", screen.Tag(screen.TagYellow), n, s)
				log(fmt.Sprintf("vault: slot %d: %s", n, s))
			}
			say(fmt.Sprintf("asking the vault at %s for the disk's remote part ...", vs.Att.Vault.URL))
			key, salt, err := Open(ctx, tpmDev, vs, say)
			if err != nil {
				vk.errs[n] = err
				fmt.Fprintf(out, "%s \033[0;31mSlot #%d: nothing from the vault:\033[0m %v\n", screen.Tag(screen.TagYellow), n, err)
				log(fmt.Sprintf("vault: slot %d: no key: %v", n, err))
				continue
			}
			if salt != nil {
				vk.salts[n] = salt
				fmt.Fprintf(out, "%s \033[0;32mSlot #%d: the vault released the salt; the password is asked after the code screen.\033[0m\n", screen.Tag(screen.TagYellow), n)
				log(fmt.Sprintf("vault: slot %d: released; the salt is opened", n))
				continue
			}
			vk.keys[n] = key
			fmt.Fprintf(out, "%s \033[0;32mSlot #%d: the vault released the remote part; the disk's key is made.\033[0m\n", screen.Tag(screen.TagYellow), n)
			log(fmt.Sprintf("vault: slot %d: released; the key is made", n))
		}
	}()
	return vk
}

// Ready is closed once every slot has been tried; nil-safe.
func (vk *Keys) Ready() <-chan struct{} {
	if vk == nil {
		return nil
	}
	return vk.done
}

// Made reports whether at least one key was made, once all were tried.
func (vk *Keys) Made() bool {
	if vk == nil {
		return false
	}
	select {
	case <-vk.done:
		return len(vk.keys) > 0
	default:
		return false
	}
}

// ForVolume is the key for a volume whose keyslot has an unattended vault recipe: the
// key of the slot its token is bound to. It waits for the attempt to end.
func (vk *Keys) ForVolume(volume string) ([]byte, error) {
	if vk == nil {
		return nil, errors.New("no slot of this machine has a vault")
	}
	<-vk.done
	dev, err := diskkey.VolumeDevice(volume)
	if err != nil {
		return nil, err
	}
	toks, err := diskkey.ReadLuks2Tokens(dev)
	if err != nil {
		return nil, err
	}
	for _, t := range toks {
		if t.Obsolete || !t.Recipe.Unattended() || t.Slot == nil {
			continue
		}
		if key, ok := vk.keys[*t.Slot]; ok {
			return append([]byte(nil), key...), nil
		}
		if err := vk.errs[*t.Slot]; err != nil {
			return nil, fmt.Errorf("slot %d: %w", *t.Slot, err)
		}
		return nil, fmt.Errorf("slot %d has no vault", *t.Slot)
	}
	return nil, errors.New("no keyslot of the volume has an unattended vault recipe")
}

// SaltFor is the salt for a volume whose keyslot has a vault recipe with a
// typed password (0x1400, 0x1401): the salt of the slot its token is bound
// to, or nil. It waits for the attempt to end. The caller wipes it.
func (vk *Keys) SaltFor(volume string, r diskkey.Recipe) []byte {
	if vk == nil {
		return nil
	}
	<-vk.done
	tok, err := diskkey.TokenOf(volume, r)
	if err != nil || tok.Slot == nil {
		return nil
	}
	if salt, ok := vk.salts[*tok.Slot]; ok {
		return append([]byte(nil), salt...)
	}
	return nil
}

// ── enrolment, status, removal ────────────────────────────────────────────
