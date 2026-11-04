//go:build integration

package admin

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/mrwiora/tpm2-kira/core/attest"
	"github.com/mrwiora/tpm2-kira/core/attest/attesttest"
)

// A real TPM's two quotes, a selection on SHA-1 and sha256:7 beside it, as a firmware that
// extends both banks and logs SHA-256 alone leaves them: on, from the second quote; and from
// the SHA-1 quote alone, with no SHA-1 events, nothing.
func TestSHA1SlotOnATPMWithBothBanks(t *testing.T) {
	s := newSWTPMSetup(t)
	sha1Chain := attesttest.SecureBootChain(attest.AlgSHA1, attest.SecureBootOn)
	sha256Chain := attesttest.SecureBootChain(attest.AlgSHA256, attest.SecureBootOn)
	for i := 0; i*32 < len(sha256Chain); i++ {
		if _, err := (tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(7), Auth: tpm2.PasswordAuth(nil)},
			Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{
				{HashAlg: tpm2.TPMAlgSHA1, Digest: sha1Chain[i*20 : (i+1)*20]},
				{HashAlg: tpm2.TPMAlgSHA256, Digest: sha256Chain[i*32 : (i+1)*32]},
			}},
		}).Execute(s.tpm); err != nil {
			t.Fatal(err)
		}
	}

	qd := bytes.Repeat([]byte{5}, 32)
	sel, _ := attest.NewPCRSelection(attest.AlgSHA1, []int{0, 7})
	q, err := s.be.Quote(qd, sel)
	if err != nil {
		t.Fatal(err)
	}
	var sha1PCR7 []byte
	for _, v := range q.Values {
		if v.Index == 7 {
			sha1PCR7 = v.Digest
		}
	}
	second := attest.QuoteSecureBoot(s.be.Quote, qd, sel)
	if second == nil {
		t.Fatal("no second quote from a TPM with both banks")
	}
	ak, err := attest.ParseAKPublic(s.blob.AKPublic, s.blob.AKName)
	if err != nil {
		t.Fatal(err)
	}
	if got := attest.EstablishSecureBootOf(attest.AlgSHA1, sha1PCR7, nil, ak, qd, second, sha256Chain); got.State != attest.SecureBootOn {
		t.Fatalf("with the second quote: %+v", got)
	}
	if got := attest.EstablishSecureBootOf(attest.AlgSHA1, sha1PCR7, nil, ak, qd, nil, nil); got.State != attest.SecureBootNotEstablished {
		t.Fatalf("with no quote and no SHA-1 events: %+v", got)
	}
	if got := attest.EstablishSecureBootOf(attest.AlgSHA1, sha1PCR7, sha1Chain, ak, qd, nil, nil); got.State != attest.SecureBootOn {
		t.Fatalf("with the SHA-1 events: %+v", got)
	}
}
