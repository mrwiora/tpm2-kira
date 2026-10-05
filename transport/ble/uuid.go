// Package ble is a minimal Bluetooth LE peripheral for tpm2-kira, speaking
// directly to the controller over an HCI user channel (PLAN-BLE.md §3.2): no
// BlueZ, no D-Bus, no daemon, no cgo.
//
// It implements exactly what one GATT service with three characteristics
// needs: legacy advertising, ACL fragmentation and flow control, L2CAP basic
// mode on the ATT and signalling channels, and an ATT server with MTU
// exchange, discovery, reads, writes and notifications. There is no security
// manager — the BLE link is an untrusted byte pipe and every pairing request
// is refused (PLAN-BLE.md §5.1); confidentiality and authentication come from
// the Noise session carried inside it.
package ble

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// UUID is a 128-bit Bluetooth UUID in the usual big-endian string order.
type UUID [16]byte

// ParseUUID parses "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
func ParseUUID(s string) (UUID, error) {
	var u UUID
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return u, fmt.Errorf("ble: invalid UUID %q", s)
	}
	copy(u[:], b)
	return u, nil
}

func mustUUID(s string) UUID {
	u, err := ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

// LE returns the UUID in the little-endian byte order used on air.
func (u UUID) LE() []byte {
	out := make([]byte, 16)
	for i := range u {
		out[i] = u[15-i]
	}
	return out
}

func (u UUID) String() string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// The tpm2-kira GATT service. Allocated once for the project from a random
// UUID; never change these.
var (
	ServiceUUID = mustUUID("883f0100-9727-459b-a589-a62200c064c0")
	RXCharUUID  = mustUUID("883f0101-9727-459b-a589-a62200c064c0") // write without response: phone -> machine
	TXCharUUID  = mustUUID("883f0102-9727-459b-a589-a62200c064c0") // notify: machine -> phone
	InfoUUID    = mustUUID("883f0103-9727-459b-a589-a62200c064c0") // read: protocol version and capabilities
)

// 16-bit UUIDs from the Bluetooth assigned numbers.
const (
	uuidPrimaryService = 0x2800
	uuidInclude        = 0x2802
	uuidCharacteristic = 0x2803
	uuidCCCD           = 0x2902
	uuidGAPService     = 0x1800
	uuidDeviceName     = 0x2A00
	uuidAppearance     = 0x2A01
)
