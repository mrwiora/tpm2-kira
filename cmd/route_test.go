package cmd

import (
	"strings"
	"testing"
)

const routeUUID = "099267cb-957a-4c7f-91cf-c25c450767bb"

// The command line: right, missing, the socket as a second rd.luks.name=
// (seen on the T450s), the socket as the name, another key file, the
// default key, another volume.
func TestAdviseCmdline(t *testing.T) {
	good := "rd.luks.name=" + routeUUID + "=cryptroot rd.luks.key=" + routeUUID + "=/run/tpm2-kira/unlock.sock root=/dev/mapper/cryptroot rw"
	cases := []struct {
		name, line string
		named      bool
		routed     bool
		problem    string
		should     string
	}{
		{"right", good, true, true, "", ""},
		{"missing", "rd.luks.name=" + routeUUID + "=cryptroot root=/dev/mapper/cryptroot rw", true, false, "is missing", good},
		{"twice", "rd.luks.name=" + routeUUID + "=cryptroot rd.luks.name=" + routeUUID + "=/run/tpm2-kira/unlock.sock root=/dev/mapper/cryptroot rw", true, false, "appears 2 times", good},
		{"socket as name", "rd.luks.name=" + routeUUID + "=/run/tpm2-kira/unlock.sock root=/dev/mapper/cryptroot rw", true, false, "a path", good},
		{"other key", "rd.luks.name=" + routeUUID + "=cryptroot rd.luks.key=" + routeUUID + "=/etc/key root=/dev/mapper/cryptroot rw", true, false, "not tpm2-kira's socket", good},
		{"default key", "rd.luks.name=" + routeUUID + "=cryptroot rd.luks.key=/run/tpm2-kira/unlock.sock rw", true, true, "", ""},
		{"no rd. prefix", "luks.name=" + routeUUID + "=cryptroot luks.key=" + routeUUID + "=/run/tpm2-kira/unlock.sock rw", true, true, "", ""},
		{"another volume", "rd.luks.name=11111111-2222-3333-4444-555555555555=other rw", false, false, "", ""},
	}
	for _, c := range cases {
		f, named := AdviseCmdline("/etc/kernel/cmdline", c.line, routeUUID)
		if named != c.named || f.Routed != c.routed || !strings.Contains(f.Problem, c.problem) || (c.should != "" && f.Should != c.should) {
			t.Errorf("%s: named=%v routed=%v problem=%q\n should=%q\n want  =%q", c.name, named, f.Routed, f.Problem, f.Should, c.should)
		}
	}
	// A boot loader entry: its options line.
	entry := "title Arch\nlinux /vmlinuz-linux\noptions rd.luks.name=" + routeUUID + "=cryptroot rw\n"
	if got := cmdlineOf("/boot/loader/entries/arch.conf", []byte(entry)); got != "rd.luks.name="+routeUUID+"=cryptroot rw" {
		t.Errorf("entry options: %q", got)
	}
}

// crypttab, both forms.
func TestAdviseCrypttab(t *testing.T) {
	// Debian: the keyscript.
	f, ok := AdviseCrypttab("/etc/crypttab", []byte("# c\ncryptroot UUID="+routeUUID+" none luks,discard\n"), routeUUID, "/dev/vda3", true)
	if !ok || f.Routed || !strings.Contains(f.Problem, "keyscript") || f.Should != "cryptroot UUID="+routeUUID+" none luks,discard,keyscript=/lib/cryptsetup/scripts/tpm2-kira" {
		t.Errorf("debian without keyscript: %+v", f)
	}
	f, ok = AdviseCrypttab("/etc/crypttab", []byte("cryptroot UUID="+routeUUID+" none luks,keyscript=/lib/cryptsetup/scripts/tpm2-kira\n"), routeUUID, "/dev/vda3", true)
	if !ok || !f.Routed {
		t.Errorf("debian with keyscript: %+v", f)
	}
	// systemd: the socket as the key file, x-initrd.attach.
	f, ok = AdviseCrypttab("/etc/crypttab", []byte("cryptroot UUID="+routeUUID+" none luks\n"), routeUUID, "/dev/vda2", false)
	if !ok || f.Routed || f.Should != "cryptroot UUID="+routeUUID+" /run/tpm2-kira/unlock.sock luks,x-initrd.attach" {
		t.Errorf("systemd without the socket: %+v", f)
	}
	f, ok = AdviseCrypttab("/etc/crypttab", []byte("cryptroot UUID="+routeUUID+" /run/tpm2-kira/unlock.sock luks,x-initrd.attach\n"), routeUUID, "/dev/vda2", false)
	if !ok || !f.Routed {
		t.Errorf("systemd with the socket: %+v", f)
	}
	if _, ok = AdviseCrypttab("/etc/crypttab", []byte("other UUID=1111 none luks\n"), routeUUID, "/dev/vda2", false); ok {
		t.Error("another volume's line taken")
	}
}
