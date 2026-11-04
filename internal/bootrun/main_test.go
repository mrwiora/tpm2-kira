package bootrun

import (
	"os"
	"testing"
)

// The tests read the narrative from journal.NarrateOut. Under systemd (a CI
// runner's service, say) it would go to journald instead.
func TestMain(m *testing.M) {
	os.Unsetenv("JOURNAL_STREAM")
	os.Exit(m.Run())
}
