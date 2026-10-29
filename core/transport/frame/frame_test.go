package frame

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func roundTrip(t *testing.T, max int, rec []byte) {
	t.Helper()
	f, err := NewFragmenter(max)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReassembler(MaxRecord, 0)
	frags, err := f.Split(rec)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for i, fr := range frags {
		if len(fr) > max {
			t.Fatalf("fragment %d is %d bytes, max %d", i, len(fr), max)
		}
		out, err := r.Feed(fr)
		if err != nil {
			t.Fatal(err)
		}
		if out != nil {
			if i != len(frags)-1 {
				t.Fatal("record completed early")
			}
			got = out
		}
	}
	if !bytes.Equal(got, rec) {
		t.Fatal("record mismatch")
	}
}

func TestRoundTripSizes(t *testing.T) {
	for _, max := range []int{MinFragment, 182, 514} {
		for _, n := range []int{1, 14, 15, 16, 100, 4096, MaxRecord} {
			rec := make([]byte, n)
			rand.Read(rec)
			roundTrip(t, max, rec)
		}
	}
}

func TestSequenceAcrossRecords(t *testing.T) {
	f, _ := NewFragmenter(MinFragment)
	r := NewReassembler(MaxRecord, 0)
	for i := 0; i < 3; i++ {
		frags, _ := f.Split(bytes.Repeat([]byte{byte(i)}, 40))
		for _, fr := range frags {
			if _, err := r.Feed(fr); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func split(t *testing.T, n int) [][]byte {
	f, _ := NewFragmenter(MinFragment)
	frags, err := f.Split(bytes.Repeat([]byte{7}, n))
	if err != nil {
		t.Fatal(err)
	}
	return frags
}

func feedAll(r *Reassembler, frags [][]byte) error {
	for _, fr := range frags {
		if _, err := r.Feed(fr); err != nil {
			return err
		}
	}
	return nil
}

func TestRejects(t *testing.T) {
	cases := map[string]func() [][]byte{
		"gap": func() [][]byte { f := split(t, 60); return append(f[:1], f[2:]...) },
		"reorder": func() [][]byte {
			f := split(t, 60)
			f[1], f[2] = f[2], f[1]
			return f
		},
		"repeat":             func() [][]byte { f := split(t, 60); return append(f[:2], f[1:]...) },
		"continuation first": func() [][]byte { f := split(t, 60); f[0][2] = 0; return f },
		"reserved flag":      func() [][]byte { f := split(t, 60); f[0][2] |= 0x80; return f },
		"length change": func() [][]byte {
			f := split(t, 60)
			binary.LittleEndian.PutUint16(f[1], 61)
			return f
		},
		"overrun": func() [][]byte {
			f := split(t, 20) // 2 fragments: 15 + 5
			f[1] = append(f[1], 1, 2, 3)
			return f
		},
		"empty payload": func() [][]byte { return [][]byte{{1, 0, 1, 0, 0}} },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			if err := feedAll(NewReassembler(MaxRecord, 0), mk()); err == nil {
				t.Fatal("accepted a broken fragment stream")
			}
		})
	}
}

func TestOversizeRejectedBeforeAllocation(t *testing.T) {
	r := NewReassembler(1000, 0)
	frag := []byte{0xE9, 0x03 + 1, FlagStart, 0, 0, 1} // total 1257 > 1000
	if _, err := r.Feed(frag); err == nil {
		t.Fatal("oversize record accepted")
	}
	if r.buf != nil {
		t.Fatal("buffer allocated for a rejected record")
	}
}

func TestByteBudget(t *testing.T) {
	r := NewReassembler(MaxRecord, 100)
	if err := feedAll(r, split(t, 200)); err != ErrBudget {
		t.Fatalf("expected budget error, got %v", err)
	}
	if _, err := r.Feed([]byte{1, 0, 1, 0, 0, 1}); err == nil {
		t.Fatal("reassembler must stay failed")
	}
}

func FuzzReassembler(f *testing.F) {
	for _, fr := range split(&testing.T{}, 60) {
		f.Add(fr)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReassembler(4096, 1<<16)
		for len(data) > 0 {
			n := int(data[0])%40 + 1
			if n > len(data) {
				n = len(data)
			}
			if _, err := r.Feed(data[:n]); err != nil {
				return
			}
			data = data[n:]
		}
	})
}
