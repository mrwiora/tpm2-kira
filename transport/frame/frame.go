// Package frame splits records into link-sized fragments and reassembles
// them (PLAN-BLE.md §4.4). It is pure Go with no device access, compiled into
// both the machine (over BLE) and the phone (through the gomobile binding),
// so the two ends share one implementation.
//
//		Fragment := u16le total_len ‖ u8 flags ‖ u16le seq ‖ payload
//
//	  - total_len is the length of the whole record, repeated in every fragment;
//	  - flags bit 0 (START) marks the first fragment of a record; all other bits
//	    are reserved and must be zero;
//	  - seq counts fragments per direction, starting at 0 for a connection and
//	    wrapping at 65536.
//
// The link is reliable and ordered, so a gap, a repeat or a reordering means
// something is wrong: the reassembler fails and the session must be dropped.
// Nothing is repaired.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderSize is the fragment header length.
const HeaderSize = 5

// FlagStart marks the first fragment of a record.
const FlagStart = 0x01

// MaxRecord is the largest record a fragment header can describe.
const MaxRecord = 0xFFFF

// MinFragment is the smallest usable fragment: ATT_MTU 23 minus the 3-byte
// ATT header leaves 20 bytes, 15 of them payload.
const MinFragment = 20

// Fragmenter splits records for one direction of a connection.
type Fragmenter struct {
	max int
	seq uint16
}

// NewFragmenter creates a fragmenter for fragments of at most maxFragment
// bytes including the header (for BLE: negotiated ATT_MTU - 3).
func NewFragmenter(maxFragment int) (*Fragmenter, error) {
	if maxFragment < MinFragment {
		return nil, fmt.Errorf("frame: fragment size %d below minimum %d", maxFragment, MinFragment)
	}
	return &Fragmenter{max: maxFragment}, nil
}

// SetMax changes the fragment size, e.g. after an MTU exchange. It takes
// effect for the next record.
func (f *Fragmenter) SetMax(maxFragment int) error {
	if maxFragment < MinFragment {
		return fmt.Errorf("frame: fragment size %d below minimum %d", maxFragment, MinFragment)
	}
	f.max = maxFragment
	return nil
}

// Split returns the fragments of one record.
func (f *Fragmenter) Split(record []byte) ([][]byte, error) {
	if len(record) == 0 || len(record) > MaxRecord {
		return nil, fmt.Errorf("frame: record of %d bytes cannot be framed", len(record))
	}
	per := f.max - HeaderSize
	var out [][]byte
	for off := 0; off < len(record); off += per {
		end := off + per
		if end > len(record) {
			end = len(record)
		}
		frag := make([]byte, HeaderSize+end-off)
		binary.LittleEndian.PutUint16(frag[0:], uint16(len(record)))
		if off == 0 {
			frag[2] = FlagStart
		}
		binary.LittleEndian.PutUint16(frag[3:], f.seq)
		f.seq++
		copy(frag[HeaderSize:], record[off:end])
		out = append(out, frag)
	}
	return out, nil
}

// Reassembler rebuilds records for one direction of a connection.
type Reassembler struct {
	maxRecord int
	maxBytes  int64
	seq       uint16
	total     int
	buf       []byte
	received  int64
	failed    error
}

// NewReassembler limits a single record to maxRecord bytes and the whole
// connection to maxBytes (0 means no connection budget).
func NewReassembler(maxRecord int, maxBytes int64) *Reassembler {
	if maxRecord <= 0 || maxRecord > MaxRecord {
		maxRecord = MaxRecord
	}
	return &Reassembler{maxRecord: maxRecord, maxBytes: maxBytes}
}

// ErrBudget is returned once the connection's byte budget is exhausted.
var ErrBudget = errors.New("frame: connection byte budget exhausted")

// Feed consumes one fragment. It returns a complete record when the fragment
// finishes one, nil otherwise. After any error the reassembler stays failed.
func (r *Reassembler) Feed(frag []byte) ([]byte, error) {
	if r.failed != nil {
		return nil, r.failed
	}
	rec, err := r.feed(frag)
	if err != nil {
		r.failed = err
	}
	return rec, err
}

func (r *Reassembler) feed(frag []byte) ([]byte, error) {
	r.received += int64(len(frag))
	if r.maxBytes > 0 && r.received > r.maxBytes {
		return nil, ErrBudget
	}
	if len(frag) <= HeaderSize {
		return nil, errors.New("frame: fragment without payload")
	}
	total := int(binary.LittleEndian.Uint16(frag[0:]))
	flags := frag[2]
	seq := binary.LittleEndian.Uint16(frag[3:])
	payload := frag[HeaderSize:]

	if flags&^FlagStart != 0 {
		return nil, fmt.Errorf("frame: reserved flag bits set (0x%02x)", flags)
	}
	if seq != r.seq {
		return nil, fmt.Errorf("frame: sequence %d, expected %d", seq, r.seq)
	}
	r.seq++

	start := flags&FlagStart != 0
	if start {
		if r.buf != nil {
			return nil, errors.New("frame: new record started before the previous one completed")
		}
		if total == 0 || total > r.maxRecord {
			// Rejected before anything is allocated.
			return nil, fmt.Errorf("frame: record of %d bytes exceeds limit %d", total, r.maxRecord)
		}
		r.total = total
		r.buf = make([]byte, 0, total)
	} else {
		if r.buf == nil {
			return nil, errors.New("frame: continuation without a start fragment")
		}
		if total != r.total {
			return nil, errors.New("frame: record length changed mid-record")
		}
	}
	if len(r.buf)+len(payload) > r.total {
		return nil, errors.New("frame: fragment overruns the declared record length")
	}
	r.buf = append(r.buf, payload...)
	if len(r.buf) == r.total {
		rec := r.buf
		r.buf = nil
		return rec, nil
	}
	return nil, nil
}
