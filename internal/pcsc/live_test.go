package pcsc

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestLiveDaemon runs the handshake, context and reader enumeration against a
// real pcscd. It is skipped unless TPM2_KIRA_PCSC_LIVE=1, because CI has no
// daemon. Without root, a daemon can be started in a private namespace:
//
//	unshare -rm sh -c 'mount -t tmpfs none /run && pcscd -f --disable-polkit &
//	    sleep 1; TPM2_KIRA_PCSC_LIVE=1 go test ./internal/pcsc -run Live -v'
func TestLiveDaemon(t *testing.T) {
	if os.Getenv("TPM2_KIRA_PCSC_LIVE") != "1" {
		t.Skip("set TPM2_KIRA_PCSC_LIVE=1 to test against a running pcscd")
	}
	c, err := Dial(2 * time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Logf("negotiated protocol %s", c.ProtocolVersion())

	readers, err := c.Readers()
	if err != nil {
		t.Fatalf("Readers: %v", err)
	}
	for _, r := range readers {
		t.Logf("reader %q card=%v atr=%X", r.Name, r.CardPresent, r.ATR)
	}
	// A connect to a reader that does not exist must fail with pcscd's own
	// error code; a wrong connect_struct layout shows up as a desynced stream.
	_, err = c.Connect("tpm2-kira no such reader 00 00")
	var pe Error
	if !errors.As(err, &pe) || uint32(pe) != 0x80100009 {
		t.Fatalf("Connect to a missing reader: got %v, want unknown reader", err)
	}
	// A further call on the same connection proves the stream stayed in sync.
	if _, err := c.Readers(); err != nil {
		t.Fatalf("second Readers: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
