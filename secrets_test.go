package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// secretCommands are the installed system's commands that handle a passphrase, a
// salt, a derived key, a TOTP key, a signing key's file or a YubiKey's PIN, each with
// the function of internal/admin it comes to. They lock their memory first, and stop
// if they cannot.
var secretCommands = []struct {
	args  []string
	admin string
}{
	{[]string{"control"}, "Control"},
	{[]string{"setup"}, "Setup"},
	{[]string{"slot", "add"}, "SealDefaults"},
	{[]string{"slot", "add", "--pcrs", "7"}, "Seal"},
	{[]string{"slot", "add", "--totp"}, "SealFallback"},
	{[]string{"slot", "approve"}, "ResealCommand"},
	{[]string{"slot", "approve", "--unattended"}, "ResealCommand"},
	{[]string{"slot", "approve", "--if-moved"}, "ResealIfMoved"},
	{[]string{"luks", "derive", "--out", "/dev/shm/tpm2-kira-test-key"}, "DeriveCommand"},
	{[]string{"luks", "enrol", "/dev/null", "--salt", "typed"}, "LuksEnrol"},
	{[]string{"luks", "enroll", "/dev/null", "--salt", "typed"}, "LuksEnrol"},
	{[]string{"luks", "remove", "/dev/null", "--keyslot", "1"}, "LuksRemove"},
	{[]string{"vault", "enrol"}, "VaultEnrol"},
	{[]string{"vault", "enroll"}, "VaultEnrol"},
	{[]string{"vault", "unenrol"}, "VaultUnenrol"},
	{[]string{"vault", "unenroll"}, "VaultUnenrol"},
	{[]string{"phone", "enrol"}, "AttestEnrol"},
	{[]string{"phone", "enroll"}, "AttestEnrol"},
	{[]string{"phone", "unenrol"}, "AttestUnenrol"},
	{[]string{"phone", "unenroll"}, "AttestUnenrol"},
	// A gate started by hand on the running system opens the channel with the signing
	// key (internal/phonegate/gate_radio.go): not internal/admin's.
	{[]string{"phone", "gate"}, ""},
	{[]string{"phone", "salt", "enrol"}, "FactorEnrol"},
	{[]string{"phone", "salt", "enroll"}, "FactorEnrol"},
	{[]string{"phone", "salt", "rotate"}, "FactorEnrol"},
	{[]string{"phone", "salt", "unenrol"}, "FactorUnenrol"},
	{[]string{"phone", "salt", "unenroll"}, "FactorUnenrol"},
}

func TestHoldsSecrets(t *testing.T) {
	for _, c := range secretCommands {
		if !holdsSecrets(c.args[0], c.args[1:]) {
			t.Errorf("%v does not lock its memory", c.args)
		}
	}
	for _, args := range [][]string{{"status"}, {"slot", "info"}, {"reveal"}, {"reveal-plain"}, {"version"}, {"help"}, {"pcrtips"}, {"yubikey", "list"}, {"slot", "list"}, {"slot", "status"}, {"slot", "delete"},
		{"luks", "status"}, {"luks", "mark"}, {"luks", "route"}, {"vault", "status"}, {"phone", "status"}, {"phone", "quote"}, {"phone", "verify"}, {"phone", "ekcert"},
		{"phone", "salt", "status"}, {"phone"}, {"phone", "salt"}, {"slot"}, {"luks"}, {"vault"}, {"initramfs", "plan"}} {
		if holdsSecrets(args[0], args[1:]) {
			t.Errorf("%v locks its memory, and is not in the list", args)
		}
	}
}

// What is secret in internal/admin: the prompts of a passphrase, a salt or a pepper,
// the derivation and the salts it takes; a TOTP key; a signing key's file, read or
// written; a YubiKey's PIN.
var secretFunctions = []string{"terminalPassword", "terminalAsk", "terminalAskExisting", "existingPassphrase", "Combine", "FactorSalt",
	"newTOTPSecret", "showTOTPSecret", "addTOTPKey",
	"LoadCheckedSigningPrivateKey", "LoadSigningPrivateKey", "ReadSigningKeyFile", "WriteSigningKeyFile",
	"StorePIN", "StoredPIN", "VerifyYubiKeyPIN"}

// TestSecretCommandsAreAll finds, by name, every exported function of internal/admin
// that comes to something secret. A new one is a new command to lock.
func TestSecretCommandsAreAll(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("internal/admin/*.go")
	if err != nil {
		t.Fatal(err)
	}
	uses := map[string]map[string]bool{} // a function's name: the names it refers to
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			var body ast.Node
			var fn string
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				body, fn = d.Body, d.Name.Name
			case *ast.GenDecl: // var terminalAsk = terminalPassword
				for _, s := range d.Specs {
					if v, ok := s.(*ast.ValueSpec); ok && len(v.Names) == 1 && len(v.Values) == 1 {
						body, fn = v.Values[0], v.Names[0].Name
						collect(uses, fn, body)
					}
				}
				continue
			}
			collect(uses, fn, body)
		}
	}
	reach := map[string]bool{}
	for _, s := range secretFunctions {
		reach[s] = true
	}
	for changed := true; changed; {
		changed = false
		for fn, names := range uses {
			if reach[fn] {
				continue
			}
			for n := range names {
				if reach[n] {
					reach[fn], changed = true, true
					break
				}
			}
		}
	}
	listed := map[string]bool{}
	for _, c := range secretCommands {
		if c.admin != "" {
			listed[c.admin] = true
		}
	}
	// Not a command of their own: control's way to delete a slot, with its keyslots;
	// what the commands above call. Or reached by a name alone: the search has no types,
	// and these only say Status or Seal of something else.
	parts := []string{"DeleteSlot", "PrintResealSkipped", "Reseal", "LuksMark", "LuksRoute", "LuksStatus", "RouteAdvice", "RouteFindings", "NVRAMDeleteCommand"}
	var missing []string
	for fn := range reach {
		if ast.IsExported(fn) && uses[fn] != nil && !listed[fn] && !slices.Contains(parts, fn) {
			missing = append(missing, fn)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("internal/admin's %v come to a passphrase, a salt or a derived key: holdsSecrets and secretCommands must have the commands that call them", missing)
	}
	for fn := range listed {
		if !reach[fn] {
			t.Errorf("%s no longer comes to anything secret: is it still in the list for a reason?", fn)
		}
	}
}

func collect(uses map[string]map[string]bool, fn string, body ast.Node) {
	if uses[fn] == nil {
		uses[fn] = map[string]bool{}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			uses[fn][x.Name] = true
		case *ast.SelectorExpr:
			uses[fn][x.Sel.Name] = true
		}
		return true
	})
}

// TestRefusedLockStopsBeforeThePrompt: the real binary, as root of a user namespace,
// which is what a container's root is: root by requireRoot, and no CAP_IPC_LOCK where
// the kernel asks. Under a limit on locked memory it stops, and asks nothing.
func TestRefusedLockStopsBeforeThePrompt(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tpm2-kira")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	script := `ulimit -l 64 && exec "$@"`
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "TPM2_KIRA_UNPRIVILEGED=") {
			env = append(env, e)
		}
	}
	run := func(args ...string) (string, error) {
		c := exec.Command("/bin/sh", append([]string{"-c", script, "sh", bin}, args...)...)
		c.Env = env
		c.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}}
		out, err := c.CombinedOutput()
		return string(out), err
	}
	if _, err := run("version"); errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC) {
		t.Skipf("no user namespace here: %v", err)
	} else if err != nil {
		t.Fatal(err)
	}
	for _, c := range secretCommands {
		out, err := run(c.args...)
		if err != nil || !strings.Contains(out, "FAILED: nothing was asked") || !strings.Contains(out, "RLIMIT_MEMLOCK") {
			t.Errorf("%v under a limit: %v\n%s", c.args, err, out)
		}
		for _, prompt := range []string{"Password", "passphrase of", "Salt"} {
			if strings.Contains(out, prompt) {
				t.Errorf("%v asked: %s", c.args, out)
			}
		}
	}
	// Who holds nothing secret is not stopped.
	for _, args := range [][]string{{"luks", "status", "/nonexistent"}, {"slot", "list"}, {"slot", "info"}, {"status"}, {"reveal"}} {
		if out, _ := run(args...); strings.Contains(out, "nothing was asked") {
			t.Errorf("%v: %s", args, out)
		}
	}
}
