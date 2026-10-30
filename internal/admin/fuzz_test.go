//go:build unit || !integration

package admin

import (
	"testing"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/signing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// The parsers below read data an attacker can supply: the NVRAM blob can be
// replaced by anyone with TPM access and is parsed as root in the initrd.
// Run one with, for example:
//
//	go test ./internal/admin -run '^$' -fuzz FuzzUnmarshalSealedBlob -fuzztime 30s

func FuzzUnmarshalSealedBlob(f *testing.F) {
	sb := &nvslot.SealedBlob{Version: nvslot.CurrentBlobVersion, Payload: nvslot.SealedBlobPayload{
		Public: []byte{1, 2}, Private: []byte{3},
		TOTPAlgorithm: tpm2.TPMAlgSHA1,
		PCRDigests: []nvslot.PCRDigestPair{
			{Index: 0, Source: measure.PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 11, Source: measure.PCRSourceUKI, Command: "/boot/x.efi", Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
		},
		PolicyRef: make([]byte, 32), MeasurePointApplied: true}}
	if b, err := sb.Marshal(); err == nil {
		f.Add(append(b, 2, 0, 1, 2))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		nvslot.PeekBlobVersion(data)
		b, err := nvslot.UnmarshalSealedBlob(data)
		if err != nil {
			return
		}
		b.GetHashAlgo()
		measure.PcrsToBitmapBytes(b.GetPCRIndices())
		measure.PCRSpecsToString(b.GetPCRSpecs())
		b.GetPCRDigestValues()
		b.MeasurePointMode()
		_, _ = b.MarshalJSON()
		if _, err := b.Marshal(); err != nil {
			t.Fatalf("a parsed blob does not marshal again: %v", err)
		}
	})
}

func FuzzParseYubiKeyStub(f *testing.F) {
	f.Add([]byte(`{"backend":"yubikey","version":1,"serial":1,"slot":"9a","algorithm":"ECCP256","pinPolicy":"once","touchPolicy":"never","publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		signing.IsYubiKeyStub(data)
		signing.ParseYubiKeyStub(data)
		signing.ParseSigningPrivateKey(data, "fuzz")
		signing.ParseSigningPublicKeyPEM(data, "fuzz")
	})
}

func FuzzEventlogReplay(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		log, err := attest.ParseEventLog(data)
		if err != nil {
			return
		}
		for _, algo := range []measure.PCRHashAlgo{measure.PCRHashAlgoSHA256, measure.PCRHashAlgoSHA1} {
			calc := measure.NewEventlogPCRCalculator(nil, []int{0, 2, 4, 7, 9, 11}, algo, false)
			calc.ReplayEventLog(log.Events(measure.AttestHash(algo)))
		}
	})
}
