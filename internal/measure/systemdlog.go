package measure

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
)

// SystemdMeasureLog is systemd's own log of what it extends, beside the firmware's.
const SystemdMeasureLog = "/run/log/systemd/tpm2-measure.log"

// maxSystemdLog bounds what is read of it: a boot writes a few KiB.
const maxSystemdLog = 1 << 20

// SystemdEvent is one extend of a PCR as systemd's log records it. Said by the machine: for a
// person looking for what moved a register, never proof of anything.
type SystemdEvent struct {
	Digest []byte
	What   string
}

// SystemdLogEvents is what the log at path records for pcr in the bank algo ("sha1", "sha256"),
// in order. Nil without a log; a record that does not parse is left out.
func SystemdLogEvents(path string, pcr int, algo string) []SystemdEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSystemdLog))
	if err != nil {
		return nil
	}
	var out []SystemdEvent
	for _, line := range strings.Split(string(raw), "\x1e") {
		var rec struct {
			PCR     int `json:"pcr"`
			Digests []struct {
				HashAlg string `json:"hashAlg"`
				Digest  string `json:"digest"`
			} `json:"digests"`
			Content struct {
				String string `json:"string"`
			} `json:"content"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.PCR != pcr {
			continue
		}
		for _, d := range rec.Digests {
			if b, err := hex.DecodeString(d.Digest); err == nil && d.HashAlg == algo {
				out = append(out, SystemdEvent{Digest: b, What: rec.Content.String})
			}
		}
	}
	return out
}
