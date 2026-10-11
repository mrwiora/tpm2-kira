package cmd

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
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/hkdf"

	"github.com/mrwiora/tpm2-kira/attest"
	"github.com/mrwiora/tpm2-kira/vaultproto"
)

// vaultInfo is the derivation string of the key: part of the contract
// between an enrolled keyslot and this code.
const vaultInfo = "tpm2-kira/vault/v1"

// VaultKey derives a tpm+vault keyslot's key: 64 lowercase hexadecimal
// characters, HKDF-SHA256(L ‖ R [‖ pepper], info = vaultInfo ‖ lp(label)
// [‖ "pepper"]). The pepper is reserved for a device the vault releases
// only with an operator's pepper (docs/VAULT.md §8); nil without.
func VaultKey(local, remote []byte, label string, pepper []byte) []byte {
	if label == "" {
		label = "luks"
	}
	ikm := append(append(append([]byte(nil), local...), remote...), pepper...)
	defer wipe(ikm)
	info := append([]byte(vaultInfo), byte(len(label)>>8), byte(len(label)))
	info = append(info, label...)
	if pepper != nil {
		info = append(info, "pepper"...)
	}
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, info), out); err != nil {
		panic(err) // HKDF with a fixed length cannot fail
	}
	defer wipe(out)
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

func newVaultClient(rawURL, pin string) (*vaultClient, error) {
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

// post sends in as JSON and decodes the answer into out; an answer that is
// not 2xx is an error with the vault's words.
func (c *vaultClient) post(ctx context.Context, path string, in, out any) error {
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
			return fmt.Errorf("the vault: %s", quoteUntrusted(e.Error))
		}
		return fmt.Errorf("the vault answered %s", rsp.Status)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("the vault's answer does not parse: %w", err)
	}
	return nil
}

// ── one slot's vault ──────────────────────────────────────────────────────

// vaultSlot is a slot whose blob carries the vault method.
type vaultSlot struct {
	idx    uint32
	sealed *SealedBlob
	att    *Attestation
}

// vaultSlots lists the slots with the vault method.
func vaultSlots(tpmDev transport.TPM, debug bool) []vaultSlot {
	var out []vaultSlot
	for _, idx := range FindPopulatedSlots(tpmDev, debug) {
		_, sb, err := readSlot(tpmDev, idx)
		if err != nil || sb.Payload.Attestation == nil || !sb.Payload.Attestation.Vault.Enabled() {
			continue
		}
		out = append(out, vaultSlot{idx: idx, sealed: sb, att: sb.Payload.Attestation})
	}
	return out
}

// sealedSelection is the slot's sealed PCR selection: what the approval
// covers, and so what is quoted for the vault.
func sealedSelection(sb *SealedBlob) vaultproto.Selection {
	var idx []uint8
	for _, i := range sb.GetPCRIndices() {
		idx = append(idx, uint8(i))
	}
	sort.Slice(idx, func(a, b int) bool { return idx[a] < idx[b] })
	return vaultproto.Selection{Alg: uint16(sb.GetHashAlgo().TPMAlg()), Indices: idx}
}

// fetchRemote asks the vault for the slot's remote part: a challenge, a
// quote of the slot's selection over it, the slot's approval - and, while
// the vault says pending, the same request again. say tells the console.
func fetchRemote(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, c *vaultClient, say func(string)) (*vaultproto.ReleaseResponse, error) {
	id := vs.att.DeviceID
	var ch vaultproto.ChallengeResponse
	if err := c.post(ctx, vaultproto.PathChallenge, vaultproto.ChallengeRequest{DeviceID: id}, &ch); err != nil {
		return nil, err
	}
	if len(ch.Nonce) != vaultproto.NonceSize || ch.RequestID == "" {
		return nil, errors.New("the vault's challenge is malformed")
	}
	sel := sealedSelection(vs.sealed)
	be := &tpmBackend{tpm: tpmDev, blob: vs.att}
	q, err := be.Quote(vaultproto.QualifyingData(id, ch.RequestID, ch.Nonce), attest.PCRSelection{Alg: sel.Alg, Indices: sel.Indices})
	if err != nil {
		return nil, err
	}
	p := &vs.sealed.Payload
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
		if err := c.post(ctx, vaultproto.PathRelease, req, &rsp); err != nil {
			return nil, err
		}
		switch rsp.Status {
		case vaultproto.StatusReleased:
			if rsp.Remote == nil {
				return nil, errors.New("the vault released nothing")
			}
			return &rsp, nil
		case vaultproto.StatusDenied:
			return nil, fmt.Errorf("the vault refused: %s", quoteUntrusted(rsp.Reason))
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
			return nil, fmt.Errorf("the vault answered %q", quoteUntrusted(rsp.Status))
		}
	}
}

// openVaultKey makes the slot's key in this boot: the local part first -
// when the TPM does not open it, this boot state is not one the signing
// key approved, and the vault is not asked - then the remote part from
// the vault, opened under the same policy. The caller wipes the key.
func openVaultKey(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, say func(string)) ([]byte, error) {
	v := &vs.att.Vault
	local, err := unwrapFactor(tpmDev, vs.sealed, vs.idx, vs.att, &v.Local)
	if err != nil {
		return nil, fmt.Errorf("the local part: %w", err)
	}
	defer wipe(local)
	c, err := newVaultClient(v.URL, v.Pin)
	if err != nil {
		return nil, err
	}
	// The network may still be coming up: connection errors are tried
	// again until the bound, a refusal is final.
	var rsp *vaultproto.ReleaseResponse
	told := false
	for {
		rsp, err = fetchRemote(ctx, tpmDev, vs, c, say)
		if err == nil || !retryableVaultError(err) {
			break
		}
		if !told {
			say(fmt.Sprintf("the vault at %s is not reachable yet (%v); trying until it is", v.URL, err))
			told = true
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("the code screen ended before the vault at %s was reached: %v", v.URL, err)
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return nil, err
	}
	if rsp.Pepper != nil {
		wipe(rsp.Pepper)
		return nil, errors.New("the vault sent a pepper, and this keyslot was enrolled without one")
	}
	remote, err := unwrapFactor(tpmDev, vs.sealed, vs.idx, vs.att, &WrappedFactor{Credential: rsp.Remote.Credential, EncryptedSecret: rsp.Remote.EncryptedSecret})
	if err != nil {
		return nil, fmt.Errorf("the remote part: %w", err)
	}
	defer wipe(remote)
	return VaultKey(local, remote, v.Label, nil), nil
}

// retryableVaultError: the vault was not reached (no route, no address
// yet, refused connection, a timeout), as opposed to an answer.
func retryableVaultError(err error) bool {
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

// vaultKeys are the keys run made in this boot, by slot number, for the
// key provider to answer with; done is closed when every slot has been
// tried.
type vaultKeys struct {
	keys map[int][]byte
	errs map[int]error
	done chan struct{}
}

// startVaultKeys opens, in the background, the key of every slot with the
// vault method - while the code screen holds, because the parts open only
// in the approved boot state; ctx ends with the hold. What happens goes to
// out (the console) and to log (the boot's log). Nil when no slot has the
// method.
func startVaultKeys(ctx context.Context, tpmPath string, out io.Writer, log func(string), debug bool) *vaultKeys {
	tpmDev, err := OpenTPM(preferResourceManager(tpmPath))
	if err != nil {
		return nil
	}
	slots := vaultSlots(tpmDev, debug)
	if len(slots) == 0 {
		tpmDev.Close()
		return nil
	}
	vk := &vaultKeys{keys: map[int][]byte{}, errs: map[int]error{}, done: make(chan struct{})}
	go func() {
		defer close(vk.done)
		defer tpmDev.Close()
		for _, vs := range slots {
			n := SlotNumber(vs.idx)
			say := func(s string) {
				fmt.Fprintf(out, "%s Slot #%d: %s\n", kiraTag(tagYellow), n, s)
				log(fmt.Sprintf("vault: slot %d: %s", n, s))
			}
			say(fmt.Sprintf("asking the vault at %s for the disk's remote part ...", vs.att.Vault.URL))
			key, err := openVaultKey(ctx, tpmDev, vs, say)
			if err != nil {
				vk.errs[n] = err
				fmt.Fprintf(out, "%s \033[0;31mSlot #%d: no key from the vault:\033[0m %v\n", kiraTag(tagYellow), n, err)
				log(fmt.Sprintf("vault: slot %d: no key: %v", n, err))
				continue
			}
			vk.keys[n] = key
			fmt.Fprintf(out, "%s \033[0;32mSlot #%d: the vault released the remote part; the disk's key is made.\033[0m\n", kiraTag(tagYellow), n)
			log(fmt.Sprintf("vault: slot %d: released; the key is made", n))
		}
	}()
	return vk
}

// ready is closed once every slot has been tried; nil-safe.
func (vk *vaultKeys) ready() <-chan struct{} {
	if vk == nil {
		return nil
	}
	return vk.done
}

// made reports whether at least one key was made, once all were tried.
func (vk *vaultKeys) made() bool {
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

// forVolume is the key for a volume whose keyslot is marked tpm+vault: the
// key of the slot its token is bound to. It waits for the attempt to end.
func (vk *vaultKeys) forVolume(volume string) ([]byte, error) {
	if vk == nil {
		return nil, errors.New("no slot of this machine has a vault")
	}
	<-vk.done
	dev, err := volumeDevice(volume)
	if err != nil {
		return nil, err
	}
	toks, err := ReadLuks2Tokens(dev)
	if err != nil {
		return nil, err
	}
	for _, t := range toks {
		if t.Mode != LuksModeTPMVault || t.Slot == nil {
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
	return nil, errors.New("no keyslot of the volume is marked tpm+vault")
}

// ── enrolment, status, removal ────────────────────────────────────────────

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
	defer wipe(key)
	if err := writeKeyOut(o.Out, key); err != nil {
		return err
	}
	fmt.Printf("\nKey written to %s\n\n", o.Out)
	fmt.Println("Next steps:")
	fmt.Printf("    cryptsetup luksAddKey <device> %s\n", o.Out)
	fmt.Printf("    tpm2-kira luks mark <device> --keyslot <the new keyslot> --mode %s --nvram %d\n", LuksModeTPMVault, slot)
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
	idx, err := AttestIndexForSlot(o.SealIndex)
	if err != nil {
		return nil, 0, err
	}
	slot := attestSlot(idx)
	client, err := newVaultClient(o.URL, o.Pin)
	if err != nil {
		return nil, 0, err
	}
	if o.Token == "" {
		return nil, 0, errors.New("--token: the one-time token from 'tpm2-kira-vault token create'")
	}
	privKeyPath := o.PrivKeyPath
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}
	priv, err := LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("the vault method is written into the slot's blob with the signing key only: %w", err)
	}
	if err := PrepareSigningKey(priv); err != nil {
		return nil, 0, fmt.Errorf("the signing key is not usable: %w", err)
	}

	tpmDev, err := OpenTPM(o.TPMPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open TPM at %s: %w", o.TPMPath, err)
	}
	defer tpmDev.Close()
	defer CleanupTPM(tpmDev, o.Debug)

	raw, sealed, err := readSlot(tpmDev, idx)
	if err != nil {
		return nil, 0, fmt.Errorf("slot %d holds no sealed blob (%v): seal first with 'tpm2-kira seal --nvram %d'", slot, err, slot)
	}
	if err := VerifyBlobSignature(raw, sealed, priv.Public()); err != nil {
		return nil, 0, foreignSlotError(slot, err)
	}
	att := sealed.Payload.Attestation
	if att != nil && att.Vault.Enabled() {
		return nil, 0, fmt.Errorf("slot %d is enrolled with the vault at %s already; 'tpm2-kira vault unenrol --nvram %d' first", slot, att.Vault.URL, slot)
	}
	sel := sealedSelection(sealed)
	if att == nil {
		fmt.Println("Creating an attestation key in the TPM ...")
		akPub, akPriv, akName, err := CreateAK(tpmDev)
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
		att = &Attestation{
			DeviceID: randBytes(attest.DeviceIDSize), FriendlyName: name,
			AKPublic: akPub, AKPrivate: akPriv, AKName: akName,
			PCRAlg: sel.Alg, PCRSelection: sel.Indices,
		}
	}
	if att.EKAlg == 0 {
		alg, ek, _, err := pickCertifiedEK(tpmDev)
		if err != nil {
			return nil, 0, err
		}
		FlushHandle(tpmDev, ek.handle)
		att.EKAlg = alg
	}
	if len(att.ReleaseKeyPublic) == 0 {
		pub, privArea, err := createReleaseKey(tpmDev, sealed)
		if err != nil {
			return nil, 0, err
		}
		att.ReleaseKeyPublic, att.ReleaseKeyPrivate = pub, privArea
	}

	local, wLocal, err := wrapFactor(tpmDev, att, nil)
	if err != nil {
		return nil, 0, err
	}
	defer wipe(local)
	remote, wRemote, err := wrapFactor(tpmDev, att, nil)
	if err != nil {
		return nil, 0, err
	}
	defer wipe(remote)
	// The blob must still fit its NV index with the vault method in it.
	att.Vault = VaultAttestation{URL: strings.TrimSuffix(o.URL, "/"), Pin: strings.ToLower(o.Pin), Label: label, Local: *wLocal}
	if err := checkEnrolmentFits(tpmDev, sealed, att, slot); err != nil {
		return nil, 0, err
	}

	ek, ekPub, err := createEK(tpmDev, att.EKAlg)
	if err != nil {
		return nil, 0, err
	}
	FlushHandle(tpmDev, ek.handle)
	genName, err := generationIndexName(tpmDev, GenerationIndex(idx))
	if err != nil {
		return nil, 0, err
	}
	p := &sealed.Payload
	req := vaultproto.EnrolRequest{
		Token: o.Token, DeviceID: att.DeviceID, Name: att.FriendlyName,
		EKPublic: ekPub, EKCert: readEKCert(tpmDev, att.EKAlg), AKPublic: att.AKPublic,
		SigningPublic: p.SigningPublic, PolicyRef: p.PolicyRef,
		GenerationIndexName: genName, Generation: p.Generation, Selection: sel,
		Remote: vaultproto.Wrapped{Credential: wRemote.Credential, EncryptedSecret: wRemote.EncryptedSecret},
		Label:  label,
	}
	if err := req.Check(); err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var ch vaultproto.EnrolChallenge
	if err := client.post(ctx, vaultproto.PathEnrol, req, &ch); err != nil {
		return nil, 0, err
	}
	be := &tpmBackend{tpm: tpmDev, blob: att, ekAlg: att.EKAlg}
	secret, err := be.ActivateCredential(ch.Challenge.Credential, ch.Challenge.EncryptedSecret)
	if err != nil {
		return nil, 0, fmt.Errorf("proving the attestation key to the vault: %w", err)
	}
	defer wipe(secret)
	var res vaultproto.EnrolResult
	if err := client.post(ctx, vaultproto.PathEnrolConfirm, vaultproto.EnrolConfirm{EnrolID: ch.EnrolID, Secret: secret}, &res); err != nil {
		return nil, 0, err
	}
	if err := writeAttestBlob(tpmDev, idx, att, priv); err != nil {
		return nil, 0, fmt.Errorf("the vault keeps the device, but the slot's blob was not written: %w\n"+
			"Enrol again with a token made with 'tpm2-kira-vault token create --replace %x'", err, att.DeviceID)
	}
	fmt.Printf("Slot %d is enrolled with the vault at %s as device %x (release mode %s).\n", slot, att.Vault.URL, att.DeviceID, res.Mode)
	fmt.Println("The local part is in the slot's blob, the remote part only with the vault; both")
	fmt.Println("open at boot, in the initrd, in the boot state the signing key approved.")
	if cfg, err := LoadControlConfig(controlConfigPath()); err == nil && cfg.Remote.Net.Mode == "off" {
		fmt.Println()
		fmt.Println("NOTE: the boot image has no network (TPM2_KIRA_NET=off), so it cannot reach the")
		fmt.Println("      vault: turn it on in 'tpm2-kira control' (Network and SSH at boot) and")
		fmt.Println("      rebuild the image.")
	}
	return VaultKey(local, remote, label, nil), slot, nil
}

// VaultStatus shows a slot's vault method and asks the vault for a
// challenge: it answers one only for a device it knows. (A release is not
// possible here: after 'cap' the parts do not open.)
func VaultStatus(tpmPath string, sealIndex uint32, debug bool) error {
	idx, err := AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	slot := attestSlot(idx)
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	_, sb, err := readSlot(tpmDev, idx)
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
	fmt.Printf("  device:    %x (%s)\n", att.DeviceID, quoteUntrusted(att.FriendlyName))
	fmt.Printf("  label:     %s\n", v.Label)
	fmt.Printf("  quoted:    %s, generation %d\n", vaultSelectionString(sealedSelection(sb)), sb.Payload.Generation)
	c, err := newVaultClient(v.URL, v.Pin)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ch vaultproto.ChallengeResponse
	if err := c.post(ctx, vaultproto.PathChallenge, vaultproto.ChallengeRequest{DeviceID: att.DeviceID}, &ch); err != nil {
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
	idx, err := AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	slot := attestSlot(idx)
	tpmDev, err := OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	_, sb, err := readSlot(tpmDev, idx)
	if err != nil {
		return err
	}
	att := sb.Payload.Attestation
	if att == nil || !att.Vault.Enabled() {
		return fmt.Errorf("slot %d is not enrolled with a vault", slot)
	}
	if privKeyPath == "" {
		privKeyPath = DefaultPrivateKeyPath
	}
	priv, err := LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("removing the vault method rewrites the slot's blob and needs the signing key: %w", err)
	}
	if err := PrepareSigningKey(priv); err != nil {
		return fmt.Errorf("the signing key is not usable: %w", err)
	}
	id, url := att.DeviceID, att.Vault.URL
	att.Vault = VaultAttestation{}
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
