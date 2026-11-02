package bootwait

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const none = "/dev/tpm2-kira-test-none"

func setup(t *testing.T) {
	t.Helper()
	was := Dir
	t.Cleanup(func() { Dir = was })
	Dir = filepath.Join(t.TempDir(), "run")
}

func since(t *testing.T, ago time.Duration) {
	t.Helper()
	now, err := boottime()
	if err != nil {
		t.Fatal(err)
	}
	write(t, strconv.FormatInt(int64(now-ago), 10))
}

func write(t *testing.T, s string) {
	t.Helper()
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir, SinceFile), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The first step waits all it asks for and says when it began.
func TestFirstWaitsItsOwn(t *testing.T) {
	setup(t)
	start := time.Now()
	if Await(none, 30*time.Millisecond) {
		t.Fatal("no device, and it is there")
	}
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("waited %s of 30 ms", d)
	}
	if _, err := readSince(); err != nil {
		t.Fatal(err)
	}
}

// A device that is there costs a healthy boot no file.
func TestThereWritesNothing(t *testing.T) {
	setup(t)
	if !Await("/not-a-device", time.Hour) {
		t.Fatal("a path that is no device's is not waited for")
	}
	if _, err := os.Stat(Dir); !os.IsNotExist(err) {
		t.Fatalf("a file for a device that was there: %v", err)
	}
}

// Without a wait it looks and says nothing: run's close at the end of the code screen.
func TestNoWaitStartsNoClock(t *testing.T) {
	setup(t)
	if Await(none, 0) {
		t.Fatal("no device, and it is there")
	}
	if _, err := os.Stat(Dir); !os.IsNotExist(err) {
		t.Fatalf("the clock started: %v", err)
	}
}

// Later steps wait what is left: machine-id's 5 s are run's, and part of the close's 30 s.
func TestLeftOfTheWait(t *testing.T) {
	setup(t)
	since(t, 5*time.Second)
	if l := left(5 * time.Second); l != 0 {
		t.Fatalf("run waits %s more", l)
	}
	if l := left(30 * time.Second); l > 25*time.Second || l < 24*time.Second {
		t.Fatalf("the close waits %s, not about 25 s", l)
	}
	start := time.Now()
	if Await(none, 5*time.Second) {
		t.Fatal("no device, and it is there")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waited %s again", d)
	}
}

// The first word stays.
func TestFirstWordStays(t *testing.T) {
	setup(t)
	since(t, time.Hour)
	was, _ := readSince()
	writeSince(0)
	if now, _ := readSince(); now != was {
		t.Fatal("a later step moved the start of the wait")
	}
}

// What is no time of this boot counts as no wait so far.
func TestNonsenseWaitsItsOwn(t *testing.T) {
	for name, content := range map[string]string{"junk": "soon\n", "empty": "", "negative": "-5\n", "the future": strconv.FormatInt(int64(1000*time.Hour), 10)} {
		t.Run(name, func(t *testing.T) {
			setup(t)
			write(t, content)
			if l := left(time.Minute); l != time.Minute {
				t.Fatalf("%s left of a minute", l)
			}
		})
	}
}

// A directory that cannot be written: each step waits its own wait.
func TestUnwritableWaitsItsOwn(t *testing.T) {
	setup(t)
	file := filepath.Join(t.TempDir(), "a file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	Dir = filepath.Join(file, "run")
	for range 2 {
		if l := left(time.Minute); l != time.Minute {
			t.Fatalf("%s left of a minute", l)
		}
	}
}
