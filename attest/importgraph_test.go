package attest_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCoreHasNoDeviceDeps enforces PLAN-REMOTEATTESTATION.md §9.1: the
// packages compiled into the phone and the server — the protocol core, the
// framing and the mobile binding — import nothing that reaches a device, the
// filesystem or the network, and never import cmd/ or a transport.
func TestCoreHasNoDeviceDeps(t *testing.T) {
	forbidden := []string{
		"os", "os/exec", "net", "net/http", "syscall", "unsafe",
		"github.com/google/go-tpm/tpm2/transport",
		"github.com/google/go-attestation",
		"golang.org/x/sys",
		"github.com/matthias/tpm2-kira/cmd",
		"github.com/matthias/tpm2-kira/transport/ble",
	}
	pure := []string{".", "../transport/frame", "../mobile/kiracore", "../mobile/kiratest", "attesttest"}
	for _, dir := range pure {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go files in %s", dir)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				for _, bad := range forbidden {
					if path == bad || strings.HasPrefix(path, bad+"/") {
						t.Errorf("%s imports %s, which the pure core must not", f, path)
					}
				}
			}
		}
	}
}
