package measure

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdLogEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	body := "\x1e{\"pcr\":7,\"digests\":[{\"hashAlg\":\"sha1\",\"digest\":\"0d37\"},{\"hashAlg\":\"sha256\",\"digest\":\"aabb\"}],\"content\":{\"string\":\"os-separator\"}}\n" +
		"\x1e{\"pcr\":15,\"digests\":[{\"hashAlg\":\"sha1\",\"digest\":\"e799\"}],\"content\":{\"string\":\"assh-close\"}}\n" +
		"\x1enot json\n" +
		"\x1e{\"pcr\":7,\"digests\":[{\"hashAlg\":\"sha1\",\"digest\":\"zz\"}]}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := SystemdLogEvents(path, 7, "sha1")
	if len(got) != 1 || got[0].What != "os-separator" || got[0].Digest[0] != 0x0d {
		t.Fatalf("%+v", got)
	}
	if got := SystemdLogEvents(path, 7, "sha256"); len(got) != 1 || got[0].Digest[0] != 0xaa {
		t.Fatalf("%+v", got)
	}
	if got := SystemdLogEvents(filepath.Join(t.TempDir(), "none"), 7, "sha1"); got != nil {
		t.Fatalf("%+v", got)
	}
}
