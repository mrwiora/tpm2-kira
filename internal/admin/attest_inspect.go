package admin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/signing"
	"github.com/tpm2-trust/tpm2-kira/internal/tpmdev"
)

// AttestStatus shows the enrolment of one slot or all slots.
func AttestStatus(tpmPath string, sealIndex uint32, jsonOut bool, debug bool) error {
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()

	var indices []uint32
	if sealIndex != 0 {
		idx, err := nvslot.AttestIndexForSlot(sealIndex)
		if err != nil {
			return err
		}
		indices = []uint32{idx}
	} else {
		indices = phonegate.EnrolledSlots(tpmDev, debug)
	}
	type verifierJSON struct {
		ID           string `json:"id"`
		PolicyID     string `json:"policy_id,omitempty"`
		AnchorDigest string `json:"anchor_digest"`
	}
	type slotJSON struct {
		Slot         int            `json:"slot_number"`
		NVRAMIndex   string         `json:"nvram_index"`
		DeviceID     string         `json:"device_id"`
		FriendlyName string         `json:"friendly_name"`
		AKName       string         `json:"ak_name"`
		EKAlg        string         `json:"ek_alg"`
		PCRSelection string         `json:"pcr_selection"`
		Signature    string         `json:"blob_signature"` // valid | invalid | unchecked
		Current      string         `json:"record_current"` // yes | no | unchecked: count equals the TPM counter
		SigningKey   string         `json:"signing_key,omitempty"`
		Verifiers    []verifierJSON `json:"verifiers"`
	}
	invalid := 0
	var out []slotJSON
	for _, idx := range indices {
		b, err := phonegate.LoadAttestBlob(tpmDev, idx)
		if err != nil {
			if sealIndex != 0 {
				return fmt.Errorf("slot is not enrolled for attestation: %w", err)
			}
			continue
		}
		sel, _ := b.Selection()
		s := slotJSON{
			Slot:         int(nvslot.AttestSlot(idx)),
			NVRAMIndex:   fmt.Sprintf("0x%08X", idx),
			DeviceID:     hex.EncodeToString(b.DeviceID),
			FriendlyName: b.FriendlyName,
			AKName:       hex.EncodeToString(b.AKName),
			EKAlg:        nvslot.EKAlgName(b.EKAlg),
			PCRSelection: sel.String(),
			Signature:    "unchecked",
			Current:      "unchecked",
		}
		if counter, err := nvslot.ReadAttestCounter(tpmDev, nvslot.AttestCounterIndex(idx)); err == nil && counter == b.Count {
			s.Current = "yes"
		} else {
			s.Current = "no"
			invalid++
		}
		if raw, err := nvslot.ReadRecord(idx); err == nil {
			if pub, path, err := phonegate.AttestPublicKey(""); err == nil {
				s.SigningKey = path
				if phonegate.VerifyAttestBlobSignature(raw, pub) == nil {
					s.Signature = "valid"
				} else {
					s.Signature = "invalid"
					invalid++
				}
			}
		}
		for _, v := range b.Phone.Verifiers {
			s.Verifiers = append(s.Verifiers, verifierJSON{ID: v.ID, PolicyID: v.PolicyID, AnchorDigest: hex.EncodeToString(attest.AnchorDigest(v.AnchorPub))})
		}
		out = append(out, s)
	}
	if jsonOut {
		if out == nil {
			out = []slotJSON{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
		return tamperedErr(invalid)
	}
	if len(out) == 0 {
		fmt.Println("No slot is enrolled for attestation. Run: tpm2-kira phone enrol")
		return nil
	}
	for _, s := range out {
		fmt.Printf("Slot #%d (in the slot's blob, %s)\n", s.Slot, s.NVRAMIndex)
		fmt.Printf("├── Machine:    %s\n", s.FriendlyName)
		fmt.Printf("├── Device ID:  %s\n", s.DeviceID)
		fmt.Printf("├── AK Name:    %s\n", s.AKName)
		fmt.Printf("├── EK:         %s\n", s.EKAlg)
		fmt.Printf("├── PCRs:       %s\n", s.PCRSelection)
		switch s.Signature {
		case "valid":
			fmt.Printf("├── Signature:  valid (%s)\n", s.SigningKey)
		case "invalid":
			fmt.Printf("├── Signature:  INVALID: the slot's blob was not written by this machine's signing key (%s). It was replaced, or is left from another installation; trust only the phone.\n", s.SigningKey)
		default:
			fmt.Printf("├── Signature:  not checked (signing public key not found)\n")
		}
		if s.Current == "yes" {
			fmt.Printf("├── Current:    yes (its revision equals the TPM's revision counter)\n")
		} else {
			fmt.Printf("├── Current:    NO: its revision differs from the TPM's revision counter. An older blob was put back, or the counter was raised; the gate refuses it. Enrol again.\n")
		}
		fmt.Printf("└── Verifiers:  %d\n", len(s.Verifiers))
		for i, v := range s.Verifiers {
			branch := "├──"
			if i == len(s.Verifiers)-1 {
				branch = "└──"
			}
			fmt.Printf("    %s phone %d (%s), anchor %s…\n", branch, i+1, v.ID, v.AnchorDigest[:16])
		}
	}
	return tamperedErr(invalid)
}

func tamperedErr(invalid int) error {
	if invalid > 0 {
		return fmt.Errorf("%d attestation blob(s) are not signed by this machine's signing key", invalid)
	}
	return nil
}

// AttestQuote produces evidence without a peer, for carrying to another
// machine and judging there with `phone verify`.
func AttestQuote(tpmPath string, sealIndex uint32, nonceHex, pcrs, outPath string, debug bool) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return fmt.Errorf("--nonce must be 16-64 bytes of hex, chosen by the verifier")
	}
	tpmDev, err := tpmdev.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("failed to open TPM at %s: %w", tpmPath, err)
	}
	defer tpmDev.Close()
	defer tpmdev.Cleanup(tpmDev, debug)

	idx, err := nvslot.AttestIndexForSlot(sealIndex)
	if err != nil {
		return err
	}
	blob, err := phonegate.LoadAttestBlob(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot is not enrolled for attestation: %w", err)
	}
	sel, err := blob.Selection()
	if err != nil {
		return err
	}
	if pcrs != "" {
		if sel, err = parseAttestPCRs(pcrs, sel.Alg); err != nil {
			return err
		}
	}
	be := &phonegate.TPMBackend{TPM: tpmDev, Blob: blob, SealIndex: nvslot.ResolveNVRAMIndex(sealIndex), Sealed: phonegate.ReadSealedSlot(tpmDev, nvslot.ResolveNVRAMIndex(sealIndex)), Debug: debug}
	q, err := be.Quote(attest.OfflineQualifyingData(nonce), sel)
	if err != nil {
		return err
	}
	ev := &attest.Evidence{
		Schema:      attest.SchemaVersion,
		DeviceID:    blob.DeviceID,
		AKName:      blob.AKName,
		Quoted:      q.Quoted,
		Signature:   q.Signature,
		PCRAlg:      sel.Alg,
		PCRValues:   q.Values,
		BootContext: be.BootContext(),
		AppVersion:  nvslot.AppVersion,
	}
	data, err := ev.Encode()
	if err != nil {
		return err
	}
	if outPath == "" || outPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}
	fmt.Printf("Evidence written to %s (%d bytes, %s)\n", outPath, len(data), sel)
	return nil
}

// AttestVerify judges an evidence file against a machine record, with no
// TPM. Returns whether the evidence matched a known-good profile.
func AttestVerify(evidencePath, recordPath, nonceHex string, jsonOut bool) (bool, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return false, fmt.Errorf("--nonce must be the 16-64 bytes of hex given to 'phone quote'")
	}
	evData, err := os.ReadFile(evidencePath)
	if err != nil {
		return false, err
	}
	d, err := attest.Decode(evData)
	if err != nil {
		return false, err
	}
	ev, err := attest.DecodeEvidence(d)
	if err != nil {
		return false, err
	}
	recData, err := os.ReadFile(recordPath)
	if err != nil {
		return false, err
	}
	var rec attest.MachineRecord
	if err := json.Unmarshal(recData, &rec); err != nil {
		return false, fmt.Errorf("machine record: %w", err)
	}
	if err := rec.Validate(); err != nil {
		return false, err
	}
	pin := &attest.PinnedIdentity{DeviceID: rec.DeviceID, EKPub: rec.EKPub, AKPub: rec.AKPub, AKName: rec.AKName, ResetCount: rec.ResetCount, FirmwareVersion: rec.FirmwareVersion}
	pol := rec.Policy
	if sel := (attest.PCRSelection{Alg: ev.PCRAlg, Indices: pcrIndicesOf(ev)}); !sel.Equal(attest.PCRSelection{Alg: pol.PCRAlg, Indices: pol.Selection}) {
		fmt.Fprintf(os.Stderr, "note: evidence covers %s, the record's policy %s\n", sel, attest.PCRSelection{Alg: pol.PCRAlg, Indices: pol.Selection})
	}
	v := attest.Verify(ev, &pol, pin, attest.OfflineQualifyingData(nonce), time.Now())
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return v.OK, enc.Encode(v)
	}
	printVerdict(v)
	return v.OK, nil
}

func pcrIndicesOf(ev *attest.Evidence) []uint8 {
	var out []uint8
	for _, v := range ev.PCRValues {
		out = append(out, v.Index)
	}
	return out
}

func printVerdict(v *attest.Verdict) {
	switch v.State {
	case attest.StateMatch:
		fmt.Printf("MATCH: evidence matches profile %q\n", v.Profile)
	case attest.StateChanged:
		fmt.Println("CHANGED: evidence is authentic but matches no known-good profile")
	default:
		fmt.Println("FAILED: a hard check failed")
	}
	for _, r := range v.Reasons {
		kind := "soft"
		if r.Hard {
			kind = "HARD"
		}
		fmt.Printf("  [%s] %s: %s\n", kind, r.Code, r.Detail)
	}
	for _, w := range v.Warnings {
		fmt.Printf("  [warn] %s: %s\n", w.Code, w.Detail)
	}
	if v.Explanation != "" {
		fmt.Printf("  %s\n", v.Explanation)
	}
	for _, d := range v.PCRDiff {
		fmt.Printf("  PCR %2d  %s\n          expected %s\n          actual   %s\n", d.Index, d.Description, d.Expected, d.Actual)
	}
}

// AttestUnenrol deletes a slot's attestation blob. The sealed TOTP secret in
// the same slot is untouched.
func AttestUnenrol(tpmPath string, sealIndex uint32, privKeyPath string, debug bool) error {
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

	att, err := phonegate.LoadAttestBlob(tpmDev, idx)
	if err != nil {
		return fmt.Errorf("slot %d has no phone enrolled", slot)
	}
	// The vault method stays, and the attestation key and release key with
	// it: they are its too.
	var keep *nvslot.Attestation
	if att.Vault.Enabled() {
		att.Phone = nvslot.PhoneAttestation{}
		keep = att
	}

	// The enrolment is part of the slot's blob: taking it out writes and
	// signs that blob again, which needs the signing key.
	if privKeyPath == "" {
		privKeyPath = signing.DefaultPrivateKeyPath
	}
	priv, err := signing.LoadCheckedSigningPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("removing the enrolment rewrites the slot's blob and needs the signing key: %w\n"+
			"Without the key, 'tpm2-kira slot delete --nvram %d' removes the whole slot, TOTP key included", err, slot)
	}
	if err := signing.PrepareSigningKey(priv); err != nil {
		return fmt.Errorf("the signing key is not usable: %w", err)
	}
	// The counter is raised with it, so the blob as it was is stale should
	// anyone put it back.
	if err := writeAttestBlob(tpmDev, idx, keep, priv); err != nil {
		return err
	}
	fmt.Printf("Attestation enrolment removed from slot %d. Its TOTP key is unchanged.\n", slot)
	fmt.Println("The phone still lists this machine; remove it there too.")
	fmt.Println("The initramfs still carries the Bluetooth gate, which now has nothing to")
	fmt.Println("serve; its next build leaves it out.")
	return nil
}
