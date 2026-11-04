package attest_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/attest/attesttest"
)

func sum(alg uint16, b []byte) []byte {
	if alg == attest.AlgSHA1 {
		d := sha1.Sum(b)
		return d[:]
	}
	d := sha256.Sum256(b)
	return d[:]
}

func chainOf(alg uint16, parts ...string) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, sum(alg, []byte(p))...)
	}
	return c
}

func ukiChain(alg uint16) []byte {
	return chainOf(alg, ".linux\x00", "a kernel", ".cmdline\x00", "a command line", ".initrd\x00", "an initrd", ".sbat\x00", "sbat")
}

func grubChain(alg uint16, command string) []byte {
	return chainOf(alg, "set root=x", "linux /vmlinuz root=/dev/mapper/r", command, "boot")
}

func values(alg uint16, m map[uint8][]byte) []attest.PCRValue {
	var out []attest.PCRValue
	for i := uint8(0); i < 24; i++ {
		if v, ok := m[i]; ok {
			out = append(out, attest.PCRValue{Index: i, Digest: v})
		}
	}
	return out
}

func TestEstablishInitrdStates(t *testing.T) {
	const cmd = "initrd /initrd.img-6.12"
	for _, alg := range []uint16{attest.AlgSHA256, attest.AlgSHA1} {
		size := len(sum(alg, nil))
		zero := make([]byte, size)
		uki := ukiChain(alg)
		ukiPCR := attesttest.ReplayChain(alg, uki)
		grub := grubChain(alg, cmd)
		grubPCR := attesttest.ReplayChain(alg, grub)
		ext := func(v []byte, word string) []byte {
			e, err := attest.ExtendWord(alg, v, word)
			if err != nil {
				t.Fatal(err)
			}
			return e
		}
		booted := ext(ext(ext(ext(ukiPCR, "enter-initrd"), "leave-initrd"), "sysinit"), "ready")
		cases := []struct {
			name string
			sel  []int
			vals map[uint8][]byte
			ev   attest.InitrdEvents
			want string
			pcrs []int
		}{
			{"a UKI, in the initrd", []int{7, 11}, map[uint8][]byte{7: zero, 11: ext(ukiPCR, "enter-initrd")}, attest.InitrdEvents{PCR11Chain: uki}, attest.InitrdCovered, []int{11}},
			{"a UKI, the running system, with PCR 4", []int{4, 7, 11}, map[uint8][]byte{4: zero, 7: zero, 11: booted}, attest.InitrdEvents{PCR11Chain: uki}, attest.InitrdCovered, []int{11, 4}},
			{"GRUB", []int{7, 8, 9}, map[uint8][]byte{7: zero, 8: grubPCR, 9: zero}, attest.InitrdEvents{PCR8Chain: grub, Command: cmd}, attest.InitrdCovered, []int{9}},
			// What a machine says that the quote does not hold up.
			{"no event log", []int{7, 8, 9, 11}, map[uint8][]byte{7: zero, 8: grubPCR, 9: zero, 11: ukiPCR}, attest.InitrdEvents{}, attest.InitrdNotEstablished, nil},
			{"PCR 11 not in the quote", []int{0, 2, 4, 7}, map[uint8][]byte{0: zero, 2: zero, 4: zero, 7: zero}, attest.InitrdEvents{PCR11Chain: uki}, attest.InitrdNotEstablished, nil},
			{"PCR 9 not in the quote", []int{7, 8}, map[uint8][]byte{7: zero, 8: grubPCR}, attest.InitrdEvents{PCR8Chain: grub, Command: cmd}, attest.InitrdNotEstablished, nil},
			{"a UKI's events beside another boot's PCR 11", []int{11}, map[uint8][]byte{11: ext(zero, "other")}, attest.InitrdEvents{PCR11Chain: uki}, attest.InitrdNotEstablished, nil},
			{"a UKI without an initrd section", []int{11}, map[uint8][]byte{11: attesttest.ReplayChain(alg, chainOf(alg, ".linux\x00", "k"))}, attest.InitrdEvents{PCR11Chain: chainOf(alg, ".linux\x00", "k")}, attest.InitrdNotEstablished, nil},
			{"the section's name as the last digest: nothing measured after it", []int{11}, map[uint8][]byte{11: attesttest.ReplayChain(alg, chainOf(alg, ".initrd\x00"))}, attest.InitrdEvents{PCR11Chain: chainOf(alg, ".initrd\x00")}, attest.InitrdNotEstablished, nil},
			{"another command than GRUB ran", []int{8, 9}, map[uint8][]byte{8: grubPCR, 9: zero}, attest.InitrdEvents{PCR8Chain: grub, Command: "initrd /other"}, attest.InitrdNotEstablished, nil},
			{"a command GRUB ran that is no initrd's", []int{8, 9}, map[uint8][]byte{8: grubPCR, 9: zero}, attest.InitrdEvents{PCR8Chain: grub, Command: "boot"}, attest.InitrdNotEstablished, nil},
			{"GRUB's events beside another PCR 8", []int{8, 9}, map[uint8][]byte{8: zero, 9: zero}, attest.InitrdEvents{PCR8Chain: grub, Command: cmd}, attest.InitrdNotEstablished, nil},
			{"a chain of no digest's length", []int{11}, map[uint8][]byte{11: ukiPCR}, attest.InitrdEvents{PCR11Chain: uki[:len(uki)-1]}, attest.InitrdNotEstablished, nil},
		}
		for _, c := range cases {
			sel, err := attest.NewPCRSelection(alg, c.sel)
			if err != nil {
				t.Fatal(err)
			}
			got := attest.EstablishInitrd(sel, values(alg, c.vals), c.ev)
			if got.State != c.want || !equalInts(got.PCRs, c.pcrs) {
				t.Errorf("bank %#x, %s: %+v", alg, c.name, got)
			}
			if c.want == attest.InitrdNotEstablished && got.Detail == "" {
				t.Errorf("bank %#x, %s: no reason", alg, c.name)
			}
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func FuzzEstablishInitrd(f *testing.F) {
	uki := ukiChain(attest.AlgSHA256)
	f.Add(uki, grubChain(attest.AlgSHA256, "initrd /x"), "initrd /x", attesttest.ReplayChain(attest.AlgSHA256, uki))
	f.Fuzz(func(t *testing.T, pcr11, pcr8 []byte, command string, value []byte) {
		sel, err := attest.NewPCRSelection(attest.AlgSHA256, []int{8, 9, 11})
		if err != nil {
			t.Fatal(err)
		}
		got := attest.EstablishInitrd(sel, []attest.PCRValue{{Index: 8, Digest: value}, {Index: 9, Digest: value}, {Index: 11, Digest: value}},
			attest.InitrdEvents{PCR8Chain: pcr8, PCR11Chain: pcr11, Command: command})
		if got.State == attest.InitrdCovered && !bytes.Contains(pcr11, sum(attest.AlgSHA256, []byte(".initrd\x00"))) && !bytes.Contains(pcr8, sum(attest.AlgSHA256, []byte(command))) {
			t.Fatalf("covered with nothing that shows it: %+v", got)
		}
	})
}
