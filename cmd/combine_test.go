package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Combine is hashpwd2: the same password and salt give the same key file,
// so a keyslot enrolled with either opens with the other. The reference
// binary is built from its checkout when one is at hand (HASHPWD2_SRC or
// ../../hashpwd2); without it the shape of the output is still checked.
// cheapCombine makes Combine cheap for the rest of the test, for the tests
// of what happens around the derivation: the key's route, the prompts, the
// modes. The derivation itself is TestCombineIsHashpwd2's.
func cheapCombine(t *testing.T) {
	t.Helper()
	mem, it := combineMemoryKiB, combineIterations
	combineMemoryKiB, combineIterations = 8*1024, 1
	t.Cleanup(func() { combineMemoryKiB, combineIterations = mem, it })
}

func TestCombineIsHashpwd2(t *testing.T) {
	if testing.Short() {
		t.Skip("1 GiB of Argon2id")
	}
	if combineMemoryKiB != 1<<20 || combineIterations != 16 || combineParallelism != 4 {
		t.Fatalf("not hashpwd2's cost: %d KiB, %d passes, %d lanes", combineMemoryKiB, combineIterations, combineParallelism)
	}
	const password, salt = "correct horse battery staple", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key, err := Combine([]byte(password), []byte(salt))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 87 || key[86] != '\n' || bytes.ContainsAny(key[:86], "=\n") {
		t.Fatalf("not hashpwd2's shape (86 base64 characters and a newline): %q", key)
	}

	src := os.Getenv("HASHPWD2_SRC")
	if src == "" {
		src = filepath.Join("..", "..", "hashpwd2")
	}
	if _, err := os.Stat(filepath.Join(src, "main.go")); err != nil {
		t.Logf("no hashpwd2 checkout at %s; shape only", src)
		return
	}
	bin := filepath.Join(t.TempDir(), "hashpwd2")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building hashpwd2: %v\n%s", err, out)
	}
	ref := exec.Command(bin)
	ref.Stdin = strings.NewReader(password + "\n" + salt + "\n")
	out, err := ref.Output()
	if err != nil {
		t.Fatalf("hashpwd2: %v", err)
	}
	if !bytes.Equal(out, key) {
		t.Fatalf("hashpwd2 derives %q, Combine %q", out, key)
	}
}

func TestCombineRefusesEmptyInput(t *testing.T) {
	for _, in := range [][2]string{{"", "salt"}, {"pw", ""}, {"", ""}} {
		if key, err := Combine([]byte(in[0]), []byte(in[1])); err == nil || key != nil {
			t.Errorf("%q: %q %v", in, key, err)
		}
	}
}
