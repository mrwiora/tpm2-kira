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

	"github.com/tpm2-trust/tpm2-kira/internal/signing"
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

// notSigning are the commands above that never sign, so take no --pin-fd: setup finds
// a token and writes its key file without a VERIFY; luks derive has no signing key.
var notSigning = map[string]bool{"setup": true, "luks derive": true}

func TestHoldsSecrets(t *testing.T) {
	for _, c := range secretCommands {
		if !holdsSecrets(c.args[0], c.args[1:]) {
			t.Errorf("%v does not lock its memory", c.args)
		}
	}
	for _, args := range [][]string{{"status"}, {"slot", "info"}, {"version"}, {"help"}, {"pcrtips"}, {"yubikey", "list"}, {"slot", "list"}, {"slot", "status"}, {"slot", "delete"},
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
	"StorePIN", "StoredPIN", "PINStored", "VerifyYubiKeyPIN"}

// TestSecretCommandsAreAll finds, by name, every exported function of internal/admin
// that comes to something secret. A new one is a new command to lock.
func TestSecretCommandsAreAll(t *testing.T) {
	uses := adminUses(t)
	reach := reachFrom(uses, secretFunctions)
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

// adminUses is, for each function of internal/admin, the names it refers to.
func adminUses(t *testing.T) map[string]map[string]bool {
	t.Helper()
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
	return uses
}

// reachFrom is every name that comes to one of roots.
func reachFrom(uses map[string]map[string]bool, roots []string) map[string]bool {
	reach := map[string]bool{}
	for _, s := range roots {
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
	return reach
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
	bin := buildAdminBinary(t)
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
	for _, args := range [][]string{{"luks", "status", "/nonexistent"}, {"slot", "list"}, {"slot", "info"}, {"status"}} {
		if out, _ := run(args...); strings.Contains(out, "nothing was asked") {
			t.Errorf("%v: %s", args, out)
		}
	}
}

func buildAdminBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tpm2-kira")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return bin
}

// commandName is a command's words, without its flags and its device.
func commandName(args []string) string {
	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") {
			break
		}
		words = append(words, a)
	}
	return strings.Join(words, " ")
}

// The list of what takes --pin-fd is what may sign, by what the functions come to: a
// command that comes to PrepareSigningKey or a signature without the flag fails here, and
// so does one with the flag that never comes to them.
func TestPINFDIsOnWhatSigns(t *testing.T) {
	reach := reachFrom(adminUses(t), []string{"PrepareSigningKey", "writeAttestBlob", "Sign"})
	for _, c := range secretCommands {
		if c.admin != "" && reach[c.admin] == notSigning[commandName(c.args)] {
			t.Errorf("%v: comes to a signature: %v; listed as not signing: %v", c.args, reach[c.admin], notSigning[commandName(c.args)])
		}
	}
}

// runBinary runs the real binary as the suite's user, with descriptor 3 as given.
func runBinary(bin string, env []string, extra *os.File, args ...string) (string, error) {
	c := exec.Command(bin, args...)
	c.Env = append(append(os.Environ(), "TPM2_KIRA_UNPRIVILEGED=1"), env...)
	if extra != nil {
		c.ExtraFiles = []*os.File{extra}
	}
	out, err := c.CombinedOutput()
	return string(out), err
}

// Every command that may sign takes the flag and fails on a descriptor that is not
// open, before anything else: no prompt, no key, no TPM. What does not sign has no flag.
func TestPINFDOnEveryCommand(t *testing.T) {
	bin := buildAdminBinary(t)
	for _, c := range secretCommands {
		name := commandName(c.args)
		out, err := runBinary(bin, nil, nil, append(slices.Clone(c.args), "--pin-fd", "99")...)
		if notSigning[name] {
			if !strings.Contains(out, "flag provided but not defined: -pin-fd") {
				t.Errorf("%v takes --pin-fd: %v\n%s", c.args, err, out)
			}
			continue
		}
		if !strings.Contains(out, "FAILED: --pin-fd 99: the descriptor is not open") {
			t.Errorf("%v: %v\n%s", c.args, err, out)
		}
		// On every command: a script asked for this source.
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Errorf("%v: %v, want exit status 2", c.args, err)
		}
		if strings.Contains(out, "exit status is 0") {
			t.Errorf("%v says it exits 0:\n%s", c.args, out)
		}
	}
	for _, args := range [][]string{{"status"}, {"slot", "list"}, {"slot", "delete"}, {"luks", "status"}, {"luks", "mark"}, {"vault", "status"}, {"phone", "status"}} {
		if out, _ := runBinary(bin, nil, nil, append(slices.Clone(args), "--pin-fd", "99")...); !strings.Contains(out, "not defined: -pin-fd") {
			t.Errorf("%v takes --pin-fd:\n%s", args, out)
		}
	}
}

// A hook's command, for real, on what a script can get wrong. Each ends in FAILED with
// the descriptor's reason, and asks nothing and looks at no other source. A good one goes
// on to what comes next, here a key file that is not there.
func TestPINFDOfTheRealBinary(t *testing.T) {
	bin := buildAdminBinary(t)
	approve := []string{"slot", "approve", "--unattended", "--privkey", filepath.Join(t.TempDir(), "absent.key"), "--pubkey", filepath.Join(t.TempDir(), "absent.pub"), "--tpm", filepath.Join(t.TempDir(), "absent.sock"), "--nvram", "0"}
	pipe := func(line string) *os.File {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close() })
		w.WriteString(line)
		w.Close()
		return r
	}
	loosePath := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(loosePath, []byte("123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loosePath, 0o644); err != nil {
		t.Fatal(err)
	}
	loose, err := os.Open(loosePath)
	if err != nil {
		t.Fatal(err)
	}
	defer loose.Close()
	for _, c := range []struct {
		name, want string
		extra      *os.File
		fd         string
	}{
		// Descriptor 3 closed: the binary's own runtime may have that number by then.
		{"closed", "FAILED: --pin-fd 3:", nil, "3"},
		{"empty", "FAILED: --pin-fd 3: no PIN on the descriptor", pipe(""), "3"},
		{"too long", "FAILED: --pin-fd 3: more than 8 bytes", pipe("123456789\n"), "3"},
		{"standard input", "FAILED: --pin-fd 0: 3 or above", nil, "0"},
		{"standard error", "FAILED: --pin-fd 2: 3 or above", nil, "2"},
		{"a loose file", "FAILED: --pin-fd 3: the file on it can be read by other users", loose, "3"},
	} {
		out, err := runBinary(bin, nil, c.extra, append(slices.Clone(approve), "--pin-fd", c.fd)...)
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(out, c.want) {
			t.Errorf("%s: %v\n%s", c.name, err, out)
		}
	}
	for _, fd := range []string{"abc", "-1", "1.5"} {
		out, err := runBinary(bin, nil, nil, append(slices.Clone(approve), "--pin-fd="+fd)...)
		if err == nil || !strings.Contains(out, "a descriptor's number") {
			t.Errorf("--pin-fd=%s: %v\n%s", fd, err, out)
		}
	}
	out, err := runBinary(bin, nil, pipe("123456\n"), append(slices.Clone(approve), "--pin-fd", "3")...)
	if err != nil || strings.Contains(out, "--pin-fd") || !strings.Contains(out, "FAILED") {
		t.Errorf("a good descriptor: %v\n%s", err, out)
	}
	if out, err := runBinary(bin, nil, pipe("123456\n"), append(slices.Clone(approve), "--pin-fd", "3", "--pin-fd", "3")...); err == nil || !strings.Contains(out, "given twice") {
		t.Errorf("twice: %v\n%s", err, out)
	}
}

// The old variable set: the command says so once, shows no value, and nothing it starts
// gets it.
func TestThePINVariableIsSaidOnce(t *testing.T) {
	bin := buildAdminBinary(t)
	for _, args := range [][]string{{"version"}, {"status", "--tpm", filepath.Join(t.TempDir(), "absent")}, {"slot", "approve", "--unattended", "--privkey", filepath.Join(t.TempDir(), "absent")}} {
		out, _ := runBinary(bin, []string{"TPM2_KIRA_PIN=secret-1234"}, nil, args...)
		if strings.Count(out, "TPM2_KIRA_PIN is set and ignored") != 1 || strings.Contains(out, "secret-1234") {
			t.Errorf("%v with it set:\n%s", args, out)
		}
		out, _ = runBinary(bin, nil, nil, args...)
		if strings.Contains(out, "TPM2_KIRA_PIN") {
			t.Errorf("%v without it:\n%s", args, out)
		}
	}

	t.Setenv("TPM2_KIRA_PIN", "secret-1234")
	var said strings.Builder
	signing.IgnorePINEnv(&said)
	signing.IgnorePINEnv(&said)
	if strings.Count(said.String(), "WARNING") != 1 {
		t.Errorf("twice in a process:\n%s", said.String())
	}
	if _, set := os.LookupEnv("TPM2_KIRA_PIN"); set {
		t.Error("it stays in the environment of what the command starts")
	}
	if out, _ := exec.Command("/bin/sh", "-c", "echo \"[$TPM2_KIRA_PIN]\"").CombinedOutput(); string(out) != "[]\n" {
		t.Errorf("a child has it: %s", out)
	}
}
