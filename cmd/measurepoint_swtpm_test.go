//go:build integration

package cmd

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// A firmware event log in the TCG 2.0 (crypto-agile) format, SHA-256 bank
// only, carrying one EV_IPL event per entry.
func tcg2Log(entries []struct {
	pcr    int
	digest []byte
}) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	// Spec ID Event03 header, in the SHA-1 (TCG 1.2) event format.
	spec := []byte("Spec ID Event03\x00")
	spec = le.AppendUint32(spec, 0) // platform class
	spec = append(spec, 0, 2, 0, 2) // minor, major, errata, uintn size
	spec = le.AppendUint32(spec, 1) // one algorithm
	spec = le.AppendUint16(spec, 0x000B)
	spec = le.AppendUint16(spec, 32)
	spec = append(spec, 0) // vendor info size
	b.Write(le.AppendUint32(nil, 0))
	b.Write(le.AppendUint32(nil, 0x03)) // EV_NO_ACTION
	b.Write(make([]byte, 20))
	b.Write(le.AppendUint32(nil, uint32(len(spec))))
	b.Write(spec)
	for _, e := range entries {
		b.Write(le.AppendUint32(nil, uint32(e.pcr)))
		b.Write(le.AppendUint32(nil, 0x0D)) // EV_IPL
		b.Write(le.AppendUint32(nil, 1))
		b.Write(le.AppendUint16(nil, 0x000B))
		b.Write(e.digest)
		data := []byte("firmware")
		b.Write(le.AppendUint32(nil, uint32(len(data))))
		b.Write(data)
	}
	return b.Bytes()
}

func extendSHA256(t *testing.T, tpm transport.TPM, pcr int, digest []byte) {
	t.Helper()
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: digest}}},
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
}

// Sealing happens on the booted system, where PCRs 0-7 already carry
// systemd's os-separator, but the display checks the policy before the
// separator runs. So register specs for those PCRs are replayed from the
// event log instead, and the values differ from the registers by exactly
// the separator; after the separator (the gate) and with --measure-point=off
// the registers are used as they are; without a usable log the seal falls
// back to the registers and says so.
func TestSealReadsSeparatorPCRsFromTheLog(t *testing.T) {
	s := newSWTPMSetup(t)
	entries := []struct {
		pcr    int
		digest []byte
	}{
		{0, bytes.Repeat([]byte{0xA1}, 32)},
		{2, bytes.Repeat([]byte{0xB2}, 32)},
		{7, bytes.Repeat([]byte{0xC3}, 32)},
	}
	for _, e := range entries {
		extendSHA256(t, s.tpm, e.pcr, e.digest)
	}
	logPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(logPath, tcg2Log(entries), 0o600); err != nil {
		t.Fatal(err)
	}
	old := DefaultEventlogPath
	DefaultEventlogPath = logPath
	defer func() { DefaultEventlogPath = old }()

	specs, err := ParsePCRSpecs("0,2,7") // register source, as users type it
	if err != nil {
		t.Fatal(err)
	}
	endOfFirmware, err := ReadPCRRegisters(s.tpm, []int{0, 2, 7}, PCRHashAlgoSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	read := func(mode MeasurePointMode, point MeasurePoint) *ReadPCRValuesResult {
		t.Helper()
		res, err := ReadPCRValues(s.tpm, specs, PCRHashAlgoSHA256, mode, point, false)
		if err != nil {
			t.Fatalf("mode %v, %v: %v", mode, point, err)
		}
		return res
	}
	sources := func(res *ReadPCRValuesResult) (out []PCRSource) {
		for _, sp := range res.Specs {
			out = append(out, sp.Source)
		}
		return
	}
	same := func(res *ReadPCRValuesResult, want map[int][]byte) bool {
		for pcr, v := range want {
			if !bytes.Equal(res.Values[pcr], v) {
				return false
			}
		}
		return true
	}
	allEventlog := []PCRSource{PCRSourceEventlog, PCRSourceEventlog, PCRSourceEventlog}
	allRegister := []PCRSource{PCRSourceRegister, PCRSourceRegister, PCRSourceRegister}

	// No separator on this system yet: the replay equals the registers.
	res := read(MeasurePointAuto, MeasurePointBeforeSeparator)
	if !same(res, endOfFirmware) || res.AfterSeparator != "" || !bytes.Equal([]byte(sourcesString(sources(res))), []byte(sourcesString(allEventlog))) {
		t.Fatalf("before any separator: %+v (sources %v)", res.Values, sources(res))
	}

	// systemd-pcrosseparator runs.
	for _, pcr := range []int{0, 2, 7} {
		extendSHA256(t, s.tpm, pcr, DigestOf(PCRHashAlgoSHA256, []byte(OSSeparatorWord)))
	}
	live, _ := ReadPCRRegisters(s.tpm, []int{0, 2, 7}, PCRHashAlgoSHA256, false)

	res = read(MeasurePointAuto, MeasurePointBeforeSeparator)
	if !same(res, endOfFirmware) || res.AfterSeparator != "" {
		t.Fatalf("before the separator: want the end-of-firmware values, got %+v (%q)", res.Values, res.AfterSeparator)
	}
	if res.EventlogInfo == nil || res.EventlogInfo.MeasurePointExtends != "" {
		t.Fatalf("nothing is applied to PCRs 0-7 before the separator: %+v", res.EventlogInfo)
	}
	for _, pcr := range []int{0, 2, 7} {
		if !SeparatorLocked(res.Values[pcr], live[pcr]) {
			t.Fatalf("PCR %d: the live register should be the sealed value plus os-separator", pcr)
		}
	}
	if sourcesString(sources(res)) != sourcesString(allEventlog) {
		t.Fatalf("register specs should have been read from the log: %v", sources(res))
	}

	// The gate quotes after the separator: the registers as they are.
	res = read(MeasurePointAuto, MeasurePointAfterSeparator)
	if !same(res, live) {
		t.Fatalf("after the separator: want the live registers, got %+v", res.Values)
	}

	// --measure-point=off leaves registers alone.
	res = read(MeasurePointOff, MeasurePointBeforeSeparator)
	if !same(res, live) || sourcesString(sources(res)) != sourcesString(allRegister) {
		t.Fatalf("off: %+v %v", res.Values, sources(res))
	}

	// No usable log: the registers after all, flagged.
	DefaultEventlogPath = filepath.Join(t.TempDir(), "missing")
	res = read(MeasurePointAuto, MeasurePointBeforeSeparator)
	if res.AfterSeparator == "" || !same(res, live) || sourcesString(sources(res)) != sourcesString(allRegister) {
		t.Fatalf("no log: %+v %q %v", res.Values, res.AfterSeparator, sources(res))
	}

	// A readable log that describes some other TPM (a CI machine's own
	// firmware log while sealing against a software TPM): the same.
	other := []struct {
		pcr    int
		digest []byte
	}{{0, bytes.Repeat([]byte{0x0F}, 32)}, {2, bytes.Repeat([]byte{0x1F}, 32)}, {7, bytes.Repeat([]byte{0x2F}, 32)}}
	otherLog := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(otherLog, tcg2Log(other), 0o600); err != nil {
		t.Fatal(err)
	}
	DefaultEventlogPath = otherLog
	res = read(MeasurePointAuto, MeasurePointBeforeSeparator)
	if res.AfterSeparator == "" || !same(res, live) || sourcesString(sources(res)) != sourcesString(allRegister) {
		t.Fatalf("foreign log: %+v %q %v", res.Values, res.AfterSeparator, sources(res))
	}
	// An explicitly requested eventlog source still fails on it.
	explicit, _ := ParsePCRSpecs("0e,2e,7e")
	if _, err := ReadPCRValues(s.tpm, explicit, PCRHashAlgoSHA256, MeasurePointAuto, MeasurePointBeforeSeparator, false); err == nil {
		t.Fatal("an explicit eventlog source must not fall back to the registers")
	}
}

// The TPM returns PCR digests in ascending order whatever order they are
// asked for in; the reader must hand each back under its own index. The
// fallback above asks for [23, 0] when sealing on "0,23": with the values
// swapped, a reseal after PCR 23 changed stored the wrong pair and the next
// reveal reported a PCR mismatch.
func TestRegistersAreReadInAnyOrder(t *testing.T) {
	s := newSWTPMSetup(t)
	extendSHA256(t, s.tpm, 23, bytes.Repeat([]byte{0x99}, 32))
	asc, err := ReadPCRRegisters(s.tpm, []int{0, 23}, PCRHashAlgoSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(asc[0], asc[23]) {
		t.Fatal("the test needs PCR 0 and PCR 23 to differ")
	}
	desc, err := ReadPCRRegisters(s.tpm, []int{23, 0}, PCRHashAlgoSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(asc[0], desc[0]) || !bytes.Equal(asc[23], desc[23]) {
		t.Fatalf("values depend on the order asked for: %x/%x vs %x/%x", asc[0][:4], asc[23][:4], desc[0][:4], desc[23][:4])
	}

	// The sealing path for "0,23" without a usable event log.
	old := DefaultEventlogPath
	DefaultEventlogPath = filepath.Join(t.TempDir(), "missing")
	defer func() { DefaultEventlogPath = old }()
	specs, _ := ParsePCRSpecs("0,23")
	res, err := ReadPCRValues(s.tpm, specs, PCRHashAlgoSHA256, MeasurePointAuto, MeasurePointBeforeSeparator, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Values[0], asc[0]) || !bytes.Equal(res.Values[23], asc[23]) {
		t.Fatalf("sealed values do not match the registers: 0=%x 23=%x", res.Values[0][:4], res.Values[23][:4])
	}
}

func sourcesString(s []PCRSource) string {
	var b bytes.Buffer
	for _, x := range s {
		b.WriteString(x.String())
		b.WriteByte(',')
	}
	return b.String()
}
