package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// tokenSigner stands in for a key held on a hardware token: it satisfies
// crypto.Signer and nothing else, so any code that type-asserts its way to an
// *ecdsa.PrivateKey or *rsa.PrivateKey fails against it exactly as it would
// against a real YubiKey.
type tokenSigner struct {
	inner crypto.Signer
}

func (t *tokenSigner) Public() crypto.PublicKey { return t.inner.Public() }

func (t *tokenSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.inner.Sign(r, digest, opts)
}

func TestECDSASignatureToRawRS(t *testing.T) {
	// A short r or s must be left-padded to the curve width. Getting this
	// wrong produces a signature the TPM rejects, and only for the small
	// fraction of signatures where a leading byte happens to be zero — so it
	// would show up as an intermittent failure of the recovery path.
	tests := []struct {
		name    string
		r, s    *big.Int
		byteLen int
		wantR   string
		wantS   string
		wantErr bool
	}{
		{
			name:    "both values need padding",
			r:       big.NewInt(1),
			s:       big.NewInt(0x0102),
			byteLen: 4,
			wantR:   "00000001",
			wantS:   "00000102",
		},
		{
			name:    "full width values are untouched",
			r:       new(big.Int).SetBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD}),
			s:       new(big.Int).SetBytes([]byte{0x11, 0x22, 0x33, 0x44}),
			byteLen: 4,
			wantR:   "aabbccdd",
			wantS:   "11223344",
		},
		{
			name:    "value wider than the curve is rejected",
			r:       new(big.Int).SetBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}),
			s:       big.NewInt(1),
			byteLen: 4,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			der, err := asn1.Marshal(ecdsaDERSignature{R: tc.r, S: tc.s})
			if err != nil {
				t.Fatalf("failed to build test DER: %v", err)
			}

			gotR, gotS, err := ecdsaSignatureToRawRS(der, tc.byteLen)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got r=%x s=%x", gotR, gotS)
				}
				return
			}
			if err != nil {
				t.Fatalf("ecdsaSignatureToRawRS failed: %v", err)
			}

			if got := hexString(gotR); got != tc.wantR {
				t.Errorf("r = %s, want %s", got, tc.wantR)
			}
			if got := hexString(gotS); got != tc.wantS {
				t.Errorf("s = %s, want %s", got, tc.wantS)
			}
		})
	}
}

func TestECDSASignatureToRawRSRejectsGarbage(t *testing.T) {
	if _, _, err := ecdsaSignatureToRawRS([]byte{0x01, 0x02}, 32); err == nil {
		t.Error("expected an error for non-DER input")
	}

	good, err := asn1.Marshal(ecdsaDERSignature{R: big.NewInt(1), S: big.NewInt(2)})
	if err != nil {
		t.Fatalf("failed to build test DER: %v", err)
	}
	if _, _, err := ecdsaSignatureToRawRS(append(good, 0x00), 32); err == nil {
		t.Error("expected an error for trailing bytes after the DER signature")
	}
}

// TestSignForTPMECDSAAcceptsTokenSigner is the regression test for the change
// that made signForTPM dispatch on the public key. The TPM wants raw r||s, and
// a crypto.Signer hands back ASN.1 DER, so a token key must still come out as
// two fixed-width integers that verify against the public key.
func TestSignForTPMECDSAAcceptsTokenSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	digest := sha256.Sum256([]byte("measure point"))

	for _, signer := range []crypto.Signer{key, &tokenSigner{inner: key}} {
		sig, err := signForTPM(signer, digest[:])
		if err != nil {
			t.Fatalf("signForTPM(%T) failed: %v", signer, err)
		}

		if sig.SigAlg != tpm2.TPMAlgECDSA {
			t.Fatalf("SigAlg = %v, want TPMAlgECDSA", sig.SigAlg)
		}

		ecc, err := sig.Signature.ECDSA()
		if err != nil {
			t.Fatalf("failed to read the ECDSA signature back: %v", err)
		}

		if len(ecc.SignatureR.Buffer) != 32 || len(ecc.SignatureS.Buffer) != 32 {
			t.Errorf("r/s widths are %d/%d, want 32/32 for P-256",
				len(ecc.SignatureR.Buffer), len(ecc.SignatureS.Buffer))
		}

		r := new(big.Int).SetBytes(ecc.SignatureR.Buffer)
		s := new(big.Int).SetBytes(ecc.SignatureS.Buffer)
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			t.Errorf("signature from %T does not verify against the public key", signer)
		}
	}
}

func TestSignForTPMRSAAcceptsTokenSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	digest := sha256.Sum256([]byte("measure point"))

	for _, signer := range []crypto.Signer{key, &tokenSigner{inner: key}} {
		sig, err := signForTPM(signer, digest[:])
		if err != nil {
			t.Fatalf("signForTPM(%T) failed: %v", signer, err)
		}

		if sig.SigAlg != tpm2.TPMAlgRSASSA {
			t.Fatalf("SigAlg = %v, want TPMAlgRSASSA", sig.SigAlg)
		}

		rsaSig, err := sig.Signature.RSASSA()
		if err != nil {
			t.Fatalf("failed to read the RSA signature back: %v", err)
		}

		// RSASSA is PKCS#1 v1.5, which is what the TPM verifies.
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], rsaSig.Sig.Buffer); err != nil {
			t.Errorf("signature from %T does not verify: %v", signer, err)
		}
	}
}

// TestSignBlobPayloadAcceptsTokenSigner checks the other signing call site: the
// detached blob signature must round-trip through VerifyBlobSignature when the
// key is a token.
func TestSignBlobPayloadAcceptsTokenSigner(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signers := map[string]crypto.Signer{
		"ecdsa file":  ecKey,
		"ecdsa token": &tokenSigner{inner: ecKey},
		"rsa file":    rsaKey,
		"rsa token":   &tokenSigner{inner: rsaKey},
	}

	for name, signer := range signers {
		t.Run(name, func(t *testing.T) {
			blob := &SealedBlob{
				Version: CurrentBlobVersion,
				Payload: SealedBlobPayload{
					AppVersion: "token-test",
					Public:     []byte("pub"),
					Private:    []byte("priv"),
					PCRDigests: []PCRDigestPair{
						{Index: 7, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
					},
					SignedBranchDigest: make([]byte, 32),
				},
			}

			unsigned, err := blob.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			signed, err := SignBlobPayload(unsigned, signer)
			if err != nil {
				t.Fatalf("SignBlobPayload failed: %v", err)
			}

			parsed, err := UnmarshalSealedBlob(signed)
			if err != nil {
				t.Fatalf("UnmarshalSealedBlob failed: %v", err)
			}

			if err := VerifyBlobSignature(signed, parsed, signer.Public()); err != nil {
				t.Errorf("VerifyBlobSignature failed: %v", err)
			}
		})
	}
}

func TestParseKeyRef(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    KeyRef
		wantErr bool
	}{
		{
			name:  "empty is the zero reference",
			input: "",
			want:  KeyRef{},
		},
		{
			name:  "a bare string is a path",
			input: "/var/lib/tpm2-kira/keys/seal.key",
			want:  KeyRef{Kind: KeyRefFile, Path: "/var/lib/tpm2-kira/keys/seal.key"},
		},
		{
			name:  "a relative path is still a path",
			input: "keys/seal.key",
			want:  KeyRef{Kind: KeyRefFile, Path: "keys/seal.key"},
		},
		{
			name:  "bare scheme takes the default slot and any token",
			input: "yubikey:",
			want:  KeyRef{Kind: KeyRefYubiKey, Slot: DefaultPIVSlot},
		},
		{
			name:  "slot only",
			input: "yubikey:slot=9c",
			want:  KeyRef{Kind: KeyRefYubiKey, Slot: 0x9C},
		},
		{
			name:  "serial and slot",
			input: "yubikey:serial=12345678;slot=9a",
			want:  KeyRef{Kind: KeyRefYubiKey, Serial: 12345678, Slot: 0x9A},
		},
		{
			name:  "a retired slot is accepted",
			input: "yubikey:slot=0x82",
			want:  KeyRef{Kind: KeyRefYubiKey, Slot: 0x82},
		},
		{
			name:    "a slot that holds no key is rejected",
			input:   "yubikey:slot=9b",
			wantErr: true,
		},
		{
			name:    "a non-numeric serial is rejected",
			input:   "yubikey:serial=abc",
			wantErr: true,
		},
		{
			name:    "an unknown field is rejected",
			input:   "yubikey:reader=foo",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKeyRef(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKeyRef failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestKeyRefStringRoundTrip(t *testing.T) {
	refs := []KeyRef{
		{Kind: KeyRefFile, Path: "/var/lib/tpm2-kira/keys/seal.key"},
		{Kind: KeyRefYubiKey, Slot: 0x9A},
		{Kind: KeyRefYubiKey, Serial: 12345678, Slot: 0x9C},
	}

	for _, ref := range refs {
		parsed, err := ParseKeyRef(ref.String())
		if err != nil {
			t.Fatalf("ParseKeyRef(%q) failed: %v", ref.String(), err)
		}
		if parsed != ref {
			t.Errorf("round trip of %+v gave %+v (via %q)", ref, parsed, ref.String())
		}
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
