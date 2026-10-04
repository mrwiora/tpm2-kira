//go:build unit || !integration

package cmd

import (
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// The parsers below read data an attacker can supply: the NVRAM blob can be
// replaced by anyone with TPM access and is parsed as root in the initrd.
// Run one with, for example:
//
//	go test ./cmd -run '^$' -fuzz FuzzUnmarshalSealedBlob -fuzztime 30s

func FuzzUnmarshalSealedBlob(f *testing.F) {
	sb := &SealedBlob{Version: CurrentBlobVersion, Payload: SealedBlobPayload{
		AppVersion: "x", Public: []byte{1, 2}, Private: []byte{3},
		PCRDigests: []PCRDigestPair{
			{Index: 0, Source: PCRSourceEventlog, Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
			{Index: 11, Source: PCRSourceUKI, Command: "/boot/x.efi", Digest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}},
		},
		PolicyRef: make([]byte, 32), PublicKeyPath: "/a", PrivateKeyPath: "/b",
		EventlogInfo: &EventlogInfo{EventlogPath: "/p", MeasurePointExtends: "os-separator:0"}}}
	if b, err := sb.Marshal(); err == nil {
		f.Add(append(b, 2, 0, 1, 2))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		PeekBlobVersion(data)
		b, err := UnmarshalSealedBlob(data)
		if err != nil {
			return
		}
		b.GetHashAlgo()
		PcrsToBitmapBytes(b.GetPCRIndices())
		PCRSpecsToString(b.GetPCRSpecs())
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
		isYubiKeyStub(data)
		ParseYubiKeyStub(data)
		parseSigningPrivateKey(data, "fuzz")
		parseSigningPublicKeyPEM(data, "fuzz")
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
		for _, algo := range []PCRHashAlgo{PCRHashAlgoSHA256, PCRHashAlgoSHA1} {
			calc := NewEventlogPCRCalculator(nil, []int{0, 2, 4, 7, 9, 11}, algo, false)
			calc.replayEventLog(log.Events(attestHash(algo)))
		}
	})
}
