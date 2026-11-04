package vaultkey

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/vaultproto"
	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/phonegate"
	"github.com/tpm2-trust/tpm2-kira/internal/untrusted"
	"github.com/tpm2-trust/tpm2-kira/internal/wipe"
)

// keyboardWait bounds how long the machine goes on asking the vault after the keys: an operator's
// pepper takes as long as an approval does.
var keyboardWait = 15 * time.Minute

// poster is the part of the vault's client a keyboard session uses.
type poster interface {
	Post(ctx context.Context, path string, in, out any) error
}

// KeyboardSession is the vault's one-time keyboard in this boot: the pad and K, both opened in the
// TPM while the code screen held. It stays usable after the close, which ends the TPM's part: the
// proof and a pepper use K alone.
type KeyboardSession struct {
	mu        sync.Mutex
	client    poster
	requestID string
	deviceID  []byte
	label     string
	pepper    bool
	pad, key  []byte
	salt      []byte // made, once the vault took the keys
	say       func(string)
}

// OpenKeyboard asks the vault for the slot's one-time keyboard and opens it in the TPM, under the
// slot's approval: only this TPM, in a boot the signing key approved, before the close.
func OpenKeyboard(ctx context.Context, tpmDev transport.TPM, vs vaultSlot, say func(string)) (*KeyboardSession, error) {
	v := &vs.Att.Vault
	c, err := NewClient(v.URL, v.Pin)
	if err != nil {
		return nil, err
	}
	rsp, err := fetchRemoteRetrying(ctx, tpmDev, vs, c, say)
	if err != nil {
		return nil, err
	}
	if rsp.Status != vaultproto.StatusKeyboard {
		return nil, errors.New("this keyslot takes a keyboard, and the vault released something else")
	}
	k, err := phonegate.UnwrapFactor(tpmDev, vs.Sealed, vs.Idx, vs.Att, &nvslot.WrappedFactor{Credential: rsp.Keyboard.Key.Credential, EncryptedSecret: rsp.Keyboard.Key.EncryptedSecret})
	if err != nil {
		return nil, fmt.Errorf("the keyboard: %w", err)
	}
	pad, err := vaultproto.OpenKeyboardPad(k, vs.Att.DeviceID, rsp.Keyboard)
	if err != nil {
		wipe.Bytes(k)
		return nil, fmt.Errorf("the keyboard: %w", err)
	}
	return &KeyboardSession{client: c, requestID: rsp.RequestID, deviceID: vs.Att.DeviceID, label: v.Label, pepper: v.Pepper, pad: pad, key: k, say: say}, nil
}

// NeedKeys implements diskkey.KeyboardSession.
func (s *KeyboardSession) NeedKeys() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.salt == nil
}

// From implements diskkey.KeyboardSession.
func (s *KeyboardSession) From() string { return "the vault" }

// Salt implements diskkey.KeyboardSession: what was typed proved to the vault, a pepper waited for
// where the keyslot has one, the salt made. The keys travel nowhere: the proof is an HMAC under K.
func (s *KeyboardSession) Salt(keys []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.salt != nil {
		return append([]byte(nil), s.salt...), nil
	}
	raw, err := attest.KeyboardSaltOf(keys, s.pad)
	if errors.Is(err, attest.ErrKeyboardKeys) {
		return nil, diskkey.ErrWrongKeys
	}
	if err != nil {
		return nil, err
	}
	defer wipe.Bytes(raw)
	ctx, cancel := context.WithTimeout(context.Background(), keyboardWait)
	defer cancel()
	req := vaultproto.KeyboardRequest{RequestID: s.requestID, DeviceID: s.deviceID, Proof: vaultproto.KeyboardProof(s.key, s.requestID, keys)}
	told := false
	for {
		var rsp vaultproto.KeyboardResponse
		err := s.client.Post(ctx, vaultproto.PathKeyboard, req, &rsp)
		if err != nil {
			if !Retryable(err) {
				return nil, err
			}
			rsp = vaultproto.KeyboardResponse{Status: vaultproto.StatusPending, RetryAfter: 2}
		}
		switch rsp.Status {
		case vaultproto.StatusWrongKeys:
			return nil, diskkey.ErrWrongKeys
		case vaultproto.StatusDenied:
			return nil, fmt.Errorf("the vault refused: %s", untrusted.Quote(rsp.Reason))
		case vaultproto.StatusReleased:
			var pepper []byte
			switch {
			case s.pepper && len(rsp.Pepper) == 0:
				return nil, errors.New("the vault released without a pepper, and this keyslot was enrolled with one")
			case !s.pepper && len(rsp.Pepper) != 0:
				return nil, errors.New("the vault sent a pepper, and this keyslot was enrolled without one")
			case s.pepper:
				if pepper, err = vaultproto.OpenKeyboardPepper(s.key, s.deviceID, rsp.Pepper); err != nil {
					return nil, err
				}
				defer wipe.Bytes(pepper)
			}
			s.salt = Salt(raw, s.label, pepper)
			wipe.Bytes(s.pad)
			wipe.Bytes(s.key)
			return append([]byte(nil), s.salt...), nil
		case vaultproto.StatusPending:
			if !told && s.pepper {
				s.say("the keys are right; the vault waits for an operator's approval with the pepper")
				told = true
			}
			wait := time.Duration(rsp.RetryAfter) * time.Second
			if wait < time.Second || wait > 10*time.Second {
				wait = 2 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, errors.New("nothing from the vault in time")
			case <-time.After(wait):
			}
		default:
			return nil, fmt.Errorf("the vault answered %q", untrusted.Quote(rsp.Status))
		}
	}
}
