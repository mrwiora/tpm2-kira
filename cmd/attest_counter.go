package cmd

// The record counter: which signed enrolment record is the current one.
//
// A signature says a record was written by this machine's signing key. It
// cannot say that the record is the latest: an older one, still naming a
// phone that has since been removed, verifies just as well. So every record
// carries a count, and the TPM holds the count of the newest one in an NV
// counter index. A TPM counter only goes up; even deleting the index does
// not help, because the TPM starts a new counter above the highest value a
// deleted one had. The gate accepts a record only while its count equals the
// counter.
//
// Anyone with the owner hierarchy can raise the counter, by incrementing or
// by deleting and recreating it. That makes the genuine record stale and the
// gate refuses it: a denial of service that fails safe, and no more than
// deleting the record itself achieves.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// AttestCounterOffset separates a slot's record counter from its record
// index, like GenerationIndexOffset does for sealed slots.
const AttestCounterOffset = 0x800

// AttestCounterIndex is the NV index of the counter for a record index.
func AttestCounterIndex(recordIndex uint32) uint32 { return recordIndex + AttestCounterOffset }

// ErrNoRecordCounter: the slot has no usable counter. Since a counter
// cannot be turned back, a missing one is never a reason to accept a record.
var ErrNoRecordCounter = errors.New("the record counter is missing or is not a TPM counter")

func attestCounterPublic(index uint32) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			AuthRead:   true, // the gate reads it in the initrd without any key
			NoDA:       true,
			NT:         tpm2.TPMNTCounter,
		},
		DataSize: 8,
	}
}

// readAttestCounter returns the counter's value. It insists on a real
// counter index: an ordinary index at the same handle could hold any number.
func readAttestCounter(tpmDev transport.TPM, index uint32) (uint64, error) {
	nvIndex := tpm2.TPMHandle(index)
	pubRsp, err := tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpmDev)
	if err != nil {
		return 0, ErrNoRecordCounter
	}
	pub, err := pubRsp.NVPublic.Contents()
	if err != nil || pub.Attributes.NT != tpm2.TPMNTCounter || pub.DataSize != 8 {
		return 0, ErrNoRecordCounter
	}
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: nvIndex, Name: pubRsp.NVName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: pubRsp.NVName},
		Size:       8,
	}.Execute(tpmDev)
	if err != nil || len(rsp.Data.Buffer) != 8 {
		// A counter that was never incremented cannot be read.
		return 0, ErrNoRecordCounter
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}

// bumpAttestCounter raises the slot's counter by one, creating it first when
// it is missing or is not a counter, and returns the new value.
func bumpAttestCounter(tpmDev transport.TPM, index uint32) (uint64, error) {
	nvIndex := tpm2.TPMHandle(index)
	want := attestCounterPublic(index)
	if rsp, err := (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(tpmDev); err == nil {
		have, perr := rsp.NVPublic.Contents()
		if perr != nil || have.Attributes.NT != tpm2.TPMNTCounter || have.DataSize != 8 || !have.Attributes.OwnerWrite {
			if _, err := (tpm2.NVUndefineSpace{
				AuthHandle: tpm2.TPMRHOwner,
				NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: rsp.NVName},
			}).Execute(tpmDev); err != nil {
				return 0, fmt.Errorf("failed to replace the record counter 0x%08X: %w", index, err)
			}
		}
	}
	pubRsp, err := tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpmDev)
	if err != nil {
		if _, err := (tpm2.NVDefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			Auth:       tpm2.TPM2BAuth{Buffer: []byte{}},
			PublicInfo: tpm2.New2B(want),
		}).Execute(tpmDev); err != nil {
			return 0, fmt.Errorf("failed to define the record counter 0x%08X: %w", index, err)
		}
		if pubRsp, err = (tpm2.NVReadPublic{NVIndex: nvIndex}).Execute(tpmDev); err != nil {
			return 0, fmt.Errorf("failed to read back the record counter 0x%08X: %w", index, err)
		}
	}
	if _, err := (tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: nvIndex, Name: pubRsp.NVName},
	}).Execute(tpmDev); err != nil {
		return 0, fmt.Errorf("failed to raise the record counter 0x%08X: %w", index, err)
	}
	return readAttestCounter(tpmDev, index)
}
