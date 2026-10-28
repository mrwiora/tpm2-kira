package cmd

// The gate's state for the slot it serves, as the coordinator
// (gate_service.go) keeps it and the code screen shows it.

// GateState is where the gate is in serving a slot.
type GateState string

const (
	GateWaiting     GateState = "waiting"     // advertising, no phone connected
	GateSession     GateState = "session"     // a phone is connected, no verdict yet
	GateAttested    GateState = "attested"    // the phone accepted or approved this boot
	GateRejected    GateState = "rejected"    // the phone rejected this boot
	GateRefused     GateState = "refused"     // the receipt or the enrolment record was not accepted
	GateUnavailable GateState = "unavailable" // no adapter, or the gate gave up
	// GateSessionOver is reported by the radio side when a session that
	// gave a receipt has ended (Bye): nothing more comes from it. Not a
	// state of the slot; it only ends a pending release.
	GateSessionOver GateState = "session-over"
)

// GateStatus is the gate's state for the slot it serves.
type GateStatus struct {
	Slot  int // the TOTP slot number the enrolment belongs to
	State GateState
	// Code is the code of the phone's boot challenge, while its session
	// lasts: the person compares it with what the phone shows.
	Code string
	// Releasing: attested, and the phone's phone salt is expected but
	// not yet taken. The phone sends it one step after the receipt; the
	// boot is not released before it has arrived, the session has ended,
	// or releaseWait has passed.
	Releasing bool
	// SaltTaken: the phone returned the salt and the TPM opened it.
	SaltTaken bool
}

// Released reports whether the boot may go on: the phone has spoken for
// this boot, and whatever it had to hand over has arrived.
func (s GateStatus) Released() bool { return s.State == GateAttested && !s.Releasing }

// Verdict reports whether the phone has spoken, for or against.
func (s GateStatus) Verdict() bool {
	return s.State == GateAttested || s.State == GateRejected || s.State == GateRefused
}

// Asking reports whether a phone can verify the slot right now.
func (s GateStatus) Asking() bool { return s.State == GateWaiting || s.State == GateSession }

// Exit codes of the commands that do not follow the exit-0 rule
// (PLAN-PHONE.md §12.1). They match PLAN-PHONESALT.md §5.2.
const (
	ExitAttested    = 0 // a trusted receipt arrived and verified
	ExitInternal    = 1 // internal error
	ExitUsage       = 2 // usage error
	ExitUnavailable = 3 // no adapter, timeout, nobody in range
	ExitRejected    = 4 // the verifier rejected the attestation
	ExitAnchor      = 5 // receipt not signed by the enrolled phone
	ExitTampered    = 6 // the attestation record was replaced or is not the current one
)
