package attest

import (
	"errors"
	"fmt"
)

// Conn is a reliable, ordered, message-oriented byte pipe. The core defines
// only this interface; BLE (transport/ble) and the in-memory test pipe
// implement it. A record handed to Send arrives as one Recv on the other side.
//
// Implementations enforce their own budgets (bytes, wall clock) and fail
// Recv once a budget is exhausted.
type Conn interface {
	Send(record []byte) error
	Recv() ([]byte, error)
	Close() error
}

// Record kinds: the first byte of every record on a Conn.
const (
	RecordHandshakeXX byte = 0x01 // Noise XX handshake message (enrolment)
	RecordHandshakeIK byte = 0x02 // Noise IK handshake message (attestation)
	RecordTransport   byte = 0x03 // Noise transport message carrying one protocol message
	// RecordPlainError is an unauthenticated, unencrypted Error message, only
	// legal before the handshake completes ("this machine is not in enrolment
	// mode"). It is shown to a user as a hint and never trusted.
	RecordPlainError byte = 0x04
)

// MaxRecordSize is the largest record: a kind byte plus a maximal Noise message.
const MaxRecordSize = 1 + noiseMaxMessage

// Channel is an established Noise session over a Conn, carrying protocol
// messages. It is used by the blocking attester side.
type Channel struct {
	conn Conn
	sess *Session
}

// NewChannel wraps an established session.
func NewChannel(conn Conn, sess *Session) *Channel { return &Channel{conn: conn, sess: sess} }

// Session returns the underlying Noise session.
func (c *Channel) Session() *Session { return c.sess }

// SendMsg encrypts and sends one encoded protocol message.
func (c *Channel) SendMsg(msg []byte) error {
	ct, err := c.sess.Seal(msg)
	if err != nil {
		return err
	}
	return c.conn.Send(append([]byte{RecordTransport}, ct...))
}

// SendError sends an Error message; failures are ignored because the session
// is being torn down anyway.
func (c *Channel) SendError(code uint16, text string) {
	if b, err := (&ErrorMsg{Code: code, Message: text}).Encode(); err == nil {
		_ = c.SendMsg(b)
	}
}

// RecvMsg receives and decodes one protocol message. A peer's Error message
// is returned as an *ErrorMsg error.
func (c *Channel) RecvMsg() (*Decoder, error) {
	rec, err := c.conn.Recv()
	if err != nil {
		return nil, err
	}
	if len(rec) == 0 || rec[0] != RecordTransport {
		return nil, errors.New("attest: expected a transport record")
	}
	pt, err := c.sess.Open(rec[1:])
	if err != nil {
		return nil, err
	}
	d, err := Decode(pt)
	if err != nil {
		return nil, err
	}
	if d.Type == MsgError {
		em, err := DecodeErrorMsg(d)
		if err != nil {
			return nil, err
		}
		return nil, em
	}
	return d, nil
}

// SendPlainError sends an unauthenticated error record before a handshake.
func SendPlainError(conn Conn, code uint16, text string) {
	if b, err := (&ErrorMsg{Code: code, Message: text}).Encode(); err == nil {
		_ = conn.Send(append([]byte{RecordPlainError}, b...))
	}
}

// PlainErrorFromRecord decodes a RecordPlainError record.
func PlainErrorFromRecord(rec []byte) (*ErrorMsg, error) {
	if len(rec) == 0 || rec[0] != RecordPlainError {
		return nil, errors.New("attest: not a plain error record")
	}
	d, err := Decode(rec[1:])
	if err != nil {
		return nil, err
	}
	return DecodeErrorMsg(d)
}

// AcceptHandshake runs the responder side of a handshake on conn. For
// PatternIK, allow is called with the initiator's authenticated static key
// before the second message is written; returning an error aborts the
// handshake without revealing anything about this machine. For PatternXX the
// key is unknown by design and allow may be nil.
func AcceptHandshake(conn Conn, p HandshakePattern, static *NoiseKeypair, allow func(remoteStatic []byte) error) (*Channel, error) {
	kind := RecordHandshakeXX
	if p == PatternIK {
		kind = RecordHandshakeIK
	}
	hs, err := NewHandshake(p, false, static, nil, nil)
	if err != nil {
		return nil, err
	}
	for !hs.Complete() {
		if hs.myTurn() {
			if p == PatternIK && allow != nil {
				if err := allow(hs.rs); err != nil {
					return nil, err
				}
			}
			out, err := hs.WriteMessage(nil)
			if err != nil {
				return nil, err
			}
			if err := conn.Send(append([]byte{kind}, out...)); err != nil {
				return nil, err
			}
			continue
		}
		rec, err := conn.Recv()
		if err != nil {
			return nil, err
		}
		if len(rec) == 0 {
			return nil, errors.New("attest: empty record")
		}
		if rec[0] == RecordPlainError {
			if em, err := PlainErrorFromRecord(rec); err == nil {
				return nil, em
			}
			return nil, errors.New("attest: malformed error record")
		}
		if rec[0] != kind {
			if rec[0] == RecordHandshakeXX || rec[0] == RecordHandshakeIK {
				want := "attestation"
				if p == PatternXX {
					want = "enrolment"
				}
				SendPlainError(conn, ErrCodeProtocol, "this machine is waiting for "+want)
			}
			return nil, fmt.Errorf("attest: unexpected record kind 0x%02x during handshake", rec[0])
		}
		if _, err := hs.ReadMessage(rec[1:]); err != nil {
			return nil, err
		}
	}
	sess, err := hs.Session()
	if err != nil {
		return nil, err
	}
	return NewChannel(conn, sess), nil
}
