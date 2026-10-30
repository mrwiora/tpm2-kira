package vaultproto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
)

// machine is a TPM double and a signing key that approved its PCRs at a
// generation: what tpm2-kira has after seal or reseal.
type machine struct {
	tpm    *attesttest.SoftTPM
	signer *ecdsa.PrivateKey
	dev    *Device
	gen    uint64
	appr   []byte
}

func newMachine(t *testing.T) *machine {
	t.Helper()
	s, err := attesttest.NewSoftTPM()
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := attest.AKTemplateECC()
	tmpl.ObjectAttributes.Restricted = false
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: k.PublicKey.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: k.PublicKey.Y.FillBytes(make([]byte, 32))},
	})
	m := &machine{tpm: s, signer: k, gen: 5}
	m.dev = &Device{
		DeviceID:            bytes.Repeat([]byte{1}, DeviceIDSize),
		AKPublic:            s.AKPub,
		SigningPublic:       tpm2.Marshal(tmpl),
		PolicyRef:           bytes.Repeat([]byte{0x9E}, 16),
		GenerationIndexName: append([]byte{0, 0x0b}, bytes.Repeat([]byte{7}, 32)...),
		Selection:           Selection{Alg: uint16(tpm2.TPMAlgSHA256), Indices: []uint8{0, 7, 11}},
	}
	m.approve()
	return m
}

// approve signs the current PCR values at m.gen, as reseal does.
func (m *machine) approve() {
	var vals []PCRValue
	for _, i := range m.dev.Selection.Indices {
		vals = append(vals, PCRValue{Index: i, Value: m.tpm.PCRs[i]})
	}
	d := ApprovalDigest(ApprovedPolicy(PolicyPCRDigest(m.dev.Selection, vals), m.dev.GenerationIndexName, m.gen), m.dev.PolicyRef)
	r, s, _ := ecdsa.Sign(rand.Reader, m.signer, d)
	m.appr = tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
		}),
	})
}

// request is the machine's release request for a challenge.
func (m *machine) request(t *testing.T, requestID string, nonce []byte) *ReleaseRequest {
	t.Helper()
	sel := attest.PCRSelection{Alg: m.dev.Selection.Alg, Indices: m.dev.Selection.Indices}
	q, err := m.tpm.Quote(QualifyingData(m.dev.DeviceID, requestID, nonce), sel)
	if err != nil {
		t.Fatal(err)
	}
	req := &ReleaseRequest{RequestID: requestID, DeviceID: m.dev.DeviceID, Quoted: q.Quoted, QuoteSignature: q.Signature, Generation: m.gen, ApprovalSignature: m.appr}
	for _, v := range q.Values {
		req.PCRValues = append(req.PCRValues, PCRValue{Index: v.Index, Value: v.Digest})
	}
	return req
}

func nonce(b byte) []byte { return bytes.Repeat([]byte{b}, NonceSize) }

// The vault releases to a fresh quote of a state the signing key approved,
// and to nothing else.
func TestVerifyRelease(t *testing.T) {
	m := newMachine(t)
	got, err := VerifyRelease(m.dev, nonce(1), m.request(t, "r1", nonce(1)), 5)
	if err != nil {
		t.Fatalf("an approved boot: %v", err)
	}
	if got.Generation != 5 || got.ResetCount != m.tpm.ResetCount || len(got.PCRValues) != 3 {
		t.Fatalf("checked %+v", got)
	}

	cases := []struct {
		name  string
		want  string
		setup func(m *machine) (*ReleaseRequest, []byte, uint64)
	}{
		{"another nonce", "not for this challenge", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			return m.request(t, "r1", nonce(1)), nonce(2), 5
		}},
		{"another request", "not for this challenge", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			r := m.request(t, "r1", nonce(1))
			r.RequestID = "r2"
			return r, nonce(1), 5
		}},
		{"another device", "another device", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			r := m.request(t, "r1", nonce(1))
			r.DeviceID = bytes.Repeat([]byte{2}, DeviceIDSize)
			return r, nonce(1), 5
		}},
		{"a PCR moved", "approval does not cover", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			m.tpm.Extend(11, "a kernel the signing key never saw")
			return m.request(t, "r1", nonce(1)), nonce(1), 5
		}},
		{"values that are not the quoted ones", "do not reproduce", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			r := m.request(t, "r1", nonce(1))
			r.PCRValues[1].Value = bytes.Repeat([]byte{0xff}, 32)
			return r, nonce(1), 5
		}},
		{"a rolled-back generation", "older than", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			return m.request(t, "r1", nonce(1)), nonce(1), 6
		}},
		{"a generation the approval is not for", "approval does not cover", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			r := m.request(t, "r1", nonce(1))
			r.Generation = 9
			return r, nonce(1), 5
		}},
		{"another selection", "another PCR selection", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			r := m.request(t, "r1", nonce(1))
			m.dev.Selection.Indices = []uint8{0, 7}
			return r, nonce(1), 5
		}},
		{"a quote by another key", "the quote", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			other, _ := attesttest.NewSoftTPM()
			m.dev.AKPublic = other.AKPub
			return m.request(t, "r1", nonce(1)), nonce(1), 5
		}},
		{"not a quote", "not a TPM quote", func(m *machine) (*ReleaseRequest, []byte, uint64) {
			m.tpm.TamperQuote = func(a *tpm2.TPMSAttest) { a.Magic = 0x12345678 }
			return m.request(t, "r1", nonce(1)), nonce(1), 5
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine(t)
			req, n, min := c.setup(m)
			if _, err := VerifyRelease(m.dev, n, req, min); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// A reseal (a new approval at a higher generation) is accepted without
// anything changing at the vault.
func TestVerifyReleaseAfterReseal(t *testing.T) {
	m := newMachine(t)
	m.tpm.Extend(11, "the new kernel")
	m.gen = 6
	m.approve()
	if _, err := VerifyRelease(m.dev, nonce(3), m.request(t, "r", nonce(3)), 5); err != nil {
		t.Fatalf("after a reseal: %v", err)
	}
}

// The messages keep their field names: they are the REST interface.
func TestReleaseResponseJSON(t *testing.T) {
	b, _ := json.Marshal(ReleaseResponse{Status: StatusReleased, Remote: &Wrapped{Credential: []byte{1}, EncryptedSecret: []byte{2}}})
	if string(b) != `{"status":"released","remote":{"credential":"AQ==","encrypted_secret":"Ag=="}}` {
		t.Fatalf("%s", b)
	}
	if p := PinOf([]byte("x")); !strings.HasPrefix(p, "sha256:2d711642") || len(p) != 71 {
		t.Fatalf("pin %s", p)
	}
}
