package attest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestNoiseVectors replays the published Noise test vectors for the two
// patterns tpm2-kira uses (testdata/noise_vectors.json, from cacophony and
// snow): every handshake and transport message must match byte for byte, and
// so must the handshake hash, which is the channel binding the quote commits to.
func TestNoiseVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/noise_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name          string `json:"protocol_name"`
			Source        string `json:"source"`
			InitPrologue  string `json:"init_prologue"`
			InitStatic    string `json:"init_static"`
			InitEphemeral string `json:"init_ephemeral"`
			InitRemote    string `json:"init_remote_static"`
			RespPrologue  string `json:"resp_prologue"`
			RespStatic    string `json:"resp_static"`
			RespEphemeral string `json:"resp_ephemeral"`
			HandshakeHash string `json:"handshake_hash"`
			Messages      []struct {
				Payload    string `json:"payload"`
				Ciphertext string `json:"ciphertext"`
			} `json:"messages"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 4 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range file.Vectors {
		t.Run(v.Name+" "+v.Source, func(t *testing.T) {
			pattern := PatternXX
			if v.Name == "Noise_IK_25519_ChaChaPoly_SHA256" {
				pattern = PatternIK
			}
			is, err := NoiseKeypairFromPrivate(unhex(v.InitStatic))
			if err != nil {
				t.Fatal(err)
			}
			rs, err := NoiseKeypairFromPrivate(unhex(v.RespStatic))
			if err != nil {
				t.Fatal(err)
			}
			var known []byte
			if pattern == PatternIK {
				known = rs.Public
				if v.InitRemote != "" && !bytes.Equal(known, unhex(v.InitRemote)) {
					t.Fatal("init_remote_static is not the responder's public key")
				}
			}
			ini, err := newHandshake(pattern, true, is, known, nil, unhex(v.InitPrologue))
			if err != nil {
				t.Fatal(err)
			}
			ini.fixedEphemeral = unhex(v.InitEphemeral)
			res, err := newHandshake(pattern, false, rs, nil, nil, unhex(v.RespPrologue))
			if err != nil {
				t.Fatal(err)
			}
			res.fixedEphemeral = unhex(v.RespEphemeral)
			var iSess, rSess *Session
			for i, m := range v.Messages {
				payload, want := unhex(m.Payload), unhex(m.Ciphertext)
				fromInit := i%2 == 0
				if iSess == nil {
					w, r := ini, res
					if !fromInit {
						w, r = res, ini
					}
					got, err := w.WriteMessage(payload)
					if err != nil {
						t.Fatalf("message %d: %v", i, err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("handshake message %d differs:\n got %x\nwant %x", i, got, want)
					}
					pt, err := r.ReadMessage(got)
					if err != nil || !bytes.Equal(pt, payload) {
						t.Fatalf("handshake message %d does not read back: %v", i, err)
					}
					if ini.Complete() && res.Complete() {
						if iSess, err = ini.Session(); err != nil {
							t.Fatal(err)
						}
						if rSess, err = res.Session(); err != nil {
							t.Fatal(err)
						}
						if v.HandshakeHash != "" && !bytes.Equal(iSess.ChannelBinding(), unhex(v.HandshakeHash)) {
							t.Fatalf("handshake hash differs:\n got %x\nwant %s", iSess.ChannelBinding(), v.HandshakeHash)
						}
						if !bytes.Equal(iSess.ChannelBinding(), rSess.ChannelBinding()) {
							t.Fatal("the two sides disagree on the channel binding")
						}
					}
					continue
				}
				w, r := iSess, rSess
				if !fromInit {
					w, r = rSess, iSess
				}
				got, err := w.Seal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("transport message %d differs:\n got %x\nwant %x", i, got, want)
				}
				if pt, err := r.Open(got); err != nil || !bytes.Equal(pt, payload) {
					t.Fatalf("transport message %d does not open: %v", i, err)
				}
			}
			if iSess == nil {
				t.Fatal("handshake never completed")
			}
		})
	}
}
