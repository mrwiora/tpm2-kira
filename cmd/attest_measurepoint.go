package cmd

// The enrolment baseline: which PCR values the phone pins.
//
// The gate quotes inside the initramfs, at tpm2-kira's measure point. The
// enrolment quote is taken in the running system, after systemd has extended
// PCR 11 with its later boot phases (and PCR 9 with NvPCR initialisation), so
// those registers can never match a boot-check quote. The TOTP seal has the
// same problem and solves it by predicting the measure-point values from the
// event log, the unified kernel image and the measure-point extends. The
// enrolment baseline is computed with exactly that code (ReadPCRValues), so
// the first boot after enrolment matches and the phone only reports a change
// when the boot chain really changed.
//
// The prediction is not TPM-signed, so before it is offered it is tied to the
// live registers the way the phone will tie it (attest.CheckMeasurePointValues):
// equal everywhere, and on PCR 11 an earlier state of the register by
// systemd's phase words. A prediction that fails this is not offered.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/matthias/tpm2-kira/attest"
)

// measurePoint is the boot-check prediction for one enrolment: the values,
// a note saying how they were obtained, or the reason there are none.
type measurePoint struct {
	values []attest.PCRValue
	note   string
	err    error
}

// predictMeasurePoint computes the PCR values the boot check will see for
// the attested selection, the way the seal does for its policy.
func predictMeasurePoint(tpmDev transport.TPM, sealed *SealedBlob, sel attest.PCRSelection, debug bool) *measurePoint {
	mode := MeasurePointAuto
	if sealed != nil {
		if sealed.HasEventlogPCRs() {
			// The seal already probed whether systemd's measure-point
			// extends are in effect; the TOTP policy depends on that answer.
			mode = sealed.MeasurePointMode()
		}
	}
	specs := measurePointSpecs(sel.Indices)
	algo := PCRHashAlgoSHA256
	if sel.Alg == attest.AlgSHA1 {
		algo = PCRHashAlgoSHA1
	}
	// The baseline is the state after the OS separator: that is the one the
	// running system's registers can vouch for (CheckMeasurePointValues).
	// The gate quotes before the separator, while the code is shown; the
	// phone takes both for the same boot (attest.SameBootState).
	res, err := ReadPCRValues(tpmDev, specs, algo, mode, MeasurePointAfterSeparator, debug)
	if err != nil {
		return &measurePoint{err: err}
	}
	vals := make([]attest.PCRValue, 0, len(sel.Indices))
	for _, i := range sel.Indices {
		v, ok := res.Values[int(i)]
		if !ok {
			return &measurePoint{err: fmt.Errorf("no value for PCR %d", i)}
		}
		vals = append(vals, attest.PCRValue{Index: i, Digest: v})
	}
	live, err := readPCRBank(tpmDev, sel)
	if err != nil {
		return &measurePoint{err: err}
	}
	if err := attest.CheckMeasurePointValues(sel.Alg, live, vals); err != nil {
		return &measurePoint{err: fmt.Errorf("the prediction does not fit the running system: %w", err)}
	}
	return &measurePoint{values: vals, note: describeMeasurePoint(specs, res)}
}

// measurePointSpecs chooses, per attested PCR, where its boot-check value
// comes from: the event log for PCRs 0-12, which is what the firmware log
// describes, and the register above that. The baseline is about the boot
// that is running, so the seal's unified kernel image (a file that may
// already be newer than the booted one) is deliberately not used; the seal
// contributes its measure-point probe result instead.
func measurePointSpecs(indices []uint8) []PCRSpec {
	specs := make([]PCRSpec, 0, len(indices))
	for _, i := range indices {
		spec := PCRSpec{Index: int(i), Source: PCRSourceRegister}
		if i <= 12 {
			spec.Source = PCRSourceEventlog
		}
		specs = append(specs, spec)
	}
	return specs
}

// describeMeasurePoint says in one line how the baseline was obtained.
func describeMeasurePoint(specs []PCRSpec, res *ReadPCRValuesResult) string {
	by := map[PCRSource][]string{}
	for _, s := range specs {
		by[s.Source] = append(by[s.Source], strconv.Itoa(s.Index))
	}
	var parts []string
	if v := by[PCRSourceEventlog]; len(v) > 0 {
		parts = append(parts, "event log for "+strings.Join(v, ","))
	}
	if v := by[PCRSourceUKI]; len(v) > 0 {
		parts = append(parts, "unified kernel image for "+strings.Join(v, ",")+
			" + "+strings.Join(MeasurePointPhases, " + ")+" on "+strings.Join(v, ","))
	}
	if v := by[PCRSourceRegister]; len(v) > 0 {
		parts = append(parts, "registers for "+strings.Join(v, ","))
	}
	s := strings.Join(parts, "; ")
	if res.EventlogInfo != nil && res.EventlogInfo.MeasurePointExtends != "" {
		// "word:1,2;word:3" from ApplyMeasurePointExtends
		s += " + " + strings.NewReplacer(":", " on ", ";", ", ").Replace(res.EventlogInfo.MeasurePointExtends)
	}
	return "values at the boot check (" + s + ")"
}

// printMeasurePoint reports the baseline in the enrolment header.
func printMeasurePoint(mp *measurePoint, sel attest.PCRSelection) {
	if mp.err == nil {
		fmt.Printf("Baseline:      %s\n", mp.note)
		return
	}
	fmt.Println("Baseline:      live PCR values; the values at the boot check could not be predicted:")
	for _, line := range strings.Split(mp.err.Error(), "\n") {
		fmt.Printf("               %s\n", line)
	}
	for _, i := range sel.Indices {
		if why, ok := IsVolatileAfterMeasurePoint(int(i)); ok {
			fmt.Printf("WARNING: PCR %d changes after the boot check (%s),\n", i, why)
			fmt.Println("         so the first boot will show it as changed. Approve it once on the phone.")
		}
	}
}

// MeasurePointValues implements attest.MeasurePointProvider.
func (b *tpmBackend) MeasurePointValues(sel attest.PCRSelection) ([]attest.PCRValue, error) {
	if b.mp == nil {
		b.mp = predictMeasurePoint(b.tpm, b.sealed, sel, b.debug)
	}
	return b.mp.values, b.mp.err
}
