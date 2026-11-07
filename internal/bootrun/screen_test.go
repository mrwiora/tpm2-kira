package bootrun

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/tpm2-trust/tpm2-kira/internal/diskkey"
	"github.com/tpm2-trust/tpm2-kira/internal/netstate"
	"github.com/tpm2-trust/tpm2-kira/internal/totp"
)

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	w.Close()
	return <-done
}

// With the SSH server the console shows what the session shows - the
// codes and the network's line - and below it where to log in and that
// Enter here continues at the console.
func TestTheConsoleShowsTheScreenWithSSH(t *testing.T) {
	noTPM := func() (transport.TPMCloser, error) { return nil, errors.New("no TPM") }
	slots := []totp.NVRAMSlot{{SlotNumber: 1}}
	codes := map[int]string{1: "123 456"}
	var session string
	bd := &board{
		prompting:  func() bool { return false },
		promptMode: func() []diskkey.Recipe { return nil },
		network: func() netstate.Status {
			return netstate.Status{Mode: "dhcp", Ifaces: []netstate.Iface{{Name: "enp1s0", Carrier: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}}}}
		},
		remote: func(b []byte) { session = string(b) },
		hint:   func() { os.Stdout.WriteString("HINT\n") },
	}
	console := captureStdout(t, func() { showScreen(bd, noTPM, slots, codes, 30*time.Second) })
	for _, want := range []string{"123 456", "Network (DHCP): 192.0.2.10/24 on enp1s0", "HINT", "Enter here: continue to cryptsetup's prompt at this console - the SSH server stops (on its own in 30 s)"} {
		if !strings.Contains(console, want) {
			t.Errorf("the console lacks %q:\n%s", want, console)
		}
	}
	if strings.Index(console, "123 456") > strings.Index(console, "HINT") {
		t.Errorf("the codes come first:\n%s", console)
	}
	for _, want := range []string{"123 456", "Network (DHCP): 192.0.2.10/24 on enp1s0", "asked here (on its own in 30 s); q: leave"} {
		if !strings.Contains(session, want) {
			t.Errorf("the session lacks %q:\n%s", want, session)
		}
	}
	if strings.Contains(session, "HINT") || strings.Contains(session, "SSH server stops") {
		t.Errorf("the console's words in the session:\n%s", session)
	}

	// Without SSH: the console alone, with the network's line.
	bd.remote, bd.hint = nil, nil
	console = captureStdout(t, func() { showScreen(bd, noTPM, slots, codes, 30*time.Second) })
	if !strings.Contains(console, "123 456") || !strings.Contains(console, "192.0.2.10/24") || strings.Contains(console, "SSH") {
		t.Errorf("without SSH:\n%s", console)
	}
}

// The network part says the state at once and again on a change; a
// network that does not come up is said again, and nothing is said after
// the release.
func TestNetPartSaysTheState(t *testing.T) {
	conf := t.TempDir() + "/remote.conf"
	if err := os.WriteFile(conf, []byte("TPM2_KIRA_NET=\"dhcp\"\nTPM2_KIRA_NET_MATCH=\"nosuchif0\"\nTPM2_KIRA_NET_ANNOUNCE=\"off\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer func(p, r time.Duration) { netPoll, netRemind = p, r }(netPoll, netRemind)
	netPoll, netRemind = 10*time.Millisecond, 50*time.Millisecond
	bd := &board{prompting: func() bool { return false }}
	p := &netPart{conf: conf}
	out := captureStdout(t, func() {
		p.start(bd)
		time.Sleep(200 * time.Millisecond)
		p.released(bd, "")
		time.Sleep(100 * time.Millisecond)
		p.end(bd)
	})
	if n := strings.Count(out, "no interface nosuchif0 yet"); n < 2 || n > 6 {
		t.Errorf("said %d times:\n%s", n, out)
	}
	if bd.network == nil || bd.network().Kind() != netstate.NoInterface {
		t.Fatal("the screen's line is not offered")
	}
	after := captureStdout(t, func() { time.Sleep(100 * time.Millisecond) })
	if after != "" {
		t.Errorf("said after the release: %q", after)
	}

	// No network in the image: nothing.
	q := &netPart{conf: t.TempDir() + "/none"}
	bd2 := &board{prompting: func() bool { return false }}
	if out := captureStdout(t, func() { q.start(bd2); q.released(bd2, ""); q.end(bd2) }); out != "" || bd2.network != nil {
		t.Errorf("without settings: %q", out)
	}
}
