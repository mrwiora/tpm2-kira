package diskkey

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The test cost is one Go build tag away, so that tag must never reach a
// release: these are the rules a release recipe is held to.

const fastKDFTag = "kira_test_fast_kdf"

var repoRoot = filepath.Join("..", "..")

// Every release recipe: no tag and no way to one, in a go build or in GOFLAGS,
// and the check of what it built. Makefile builds for development, and has the
// same first rule.
func TestReleaseRecipesPassNoBuildTag(t *testing.T) {
	recipes := map[string]bool{ // recipe -> it must run the check
		"packaging/aur/PKGBUILD":        true,
		"debian/rules":                  true,
		".github/workflows/release.yml": true,
		"Makefile":                      false,
	}
	build := regexp.MustCompile(`\bgo build\b|\$\(GOBUILD\)|^\s*(export\s+)?GOFLAGS\b`)
	for name, check := range recipes {
		body, err := os.ReadFile(filepath.Join(repoRoot, name))
		if err != nil {
			if os.IsNotExist(err) && strings.HasPrefix(name, ".github") {
				continue // a source archive may leave it out
			}
			t.Fatal(err)
		}
		text := string(body)
		for _, bad := range []string{fastKDFTag, "fast-kdf", "fastkdf"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s names %q", name, bad)
			}
		}
		for _, line := range strings.Split(text, "\n") {
			if build.MatchString(line) && strings.Contains(line, "-tags") {
				t.Errorf("%s builds with a tag: %s", name, line)
			}
		}
		if check != strings.Contains(text, "release-binary-check.sh") {
			t.Errorf("%s: runs the release binary check: %v, want %v", name, !check, check)
		}
	}
}

// build-packages.sh makes a test package by its flag alone, never from its
// environment, and only there edits its copies of the recipes.
func TestBuildPackagesTagOnlyByItsFlag(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot, "packaging", "build-packages.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var set []string
	inFast := 0
	for _, line := range strings.Split(string(body), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(line, "fast_kdf=") {
			set = append(set, trim)
		}
		switch {
		case strings.Contains(trim, "if $fast_kdf") || strings.Contains(trim, `if [ -n "$FAST_MARK" ]`):
			inFast++
		case inFast > 0 && trim == "fi":
			inFast--
		case inFast == 0 && strings.Contains(trim, fastKDFTag):
			t.Errorf("the tag outside a --fast-kdf branch: %s", trim)
		}
	}
	want := "fast_kdf=false\n--fast-kdf) fast_kdf=true ;;"
	if got := strings.Join(set, "\n"); got != want {
		t.Errorf("fast_kdf is set:\n%s\nwant:\n%s", got, want)
	}
}

// A real binary, built as the recipes build: without the tag it says nothing of
// a test build, holds no trace of one and passes the check; with it, it says so
// and the check refuses it.
func TestReleaseCheckTellsTheBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("builds tpm2-kira-boot twice")
	}
	dir := t.TempDir()
	check := filepath.Join(repoRoot, "packaging", "release-binary-check.sh")
	build := func(out string, args ...string) string {
		bin := filepath.Join(dir, out)
		cmd := exec.Command("go", append(append([]string{"build"}, args...), "-trimpath", "-ldflags", "-s -w", "-o", bin, "./cmd/tpm2-kira-boot")...)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build: %v\n%s", err, b)
		}
		return bin
	}
	version := func(bin string) string {
		b, err := exec.Command(bin, "version").CombinedOutput()
		if err != nil {
			t.Fatalf("%s version: %v\n%s", bin, err, b)
		}
		return string(b)
	}

	release := build("release")
	if b, err := exec.Command("sh", check, release).CombinedOutput(); err != nil {
		t.Errorf("the check refuses a build without a tag: %v\n%s", err, b)
	}
	if v := version(release); strings.Contains(v, "TEST BUILD") {
		t.Errorf("a build without the tag says: %s", v)
	}
	body, err := os.ReadFile(release)
	if err != nil {
		t.Fatal(err)
	}
	for _, trace := range []string{fastKDFTag, "TEST BUILD", "combine_cost_fast"} {
		if strings.Contains(string(body), trace) {
			t.Errorf("a build without the tag holds %q", trace)
		}
	}

	tagged := build("tagged", "-tags", fastKDFTag)
	if b, err := exec.Command("sh", check, tagged).CombinedOutput(); err == nil {
		t.Errorf("the check lets a tagged build through:\n%s", b)
	}
	if v := version(tagged); !strings.Contains(v, "TEST BUILD") {
		t.Errorf("a tagged build does not say so: %s", v)
	}
}
