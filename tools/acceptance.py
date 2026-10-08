#!/usr/bin/env python3
"""The acceptance run of tpm2-kira on a machine of one distribution.

    tools/acceptance.py --distro arch   --host 172.17.2.198 --user pix --ask-password
    tools/acceptance.py --distro debian --host 172.17.2.196 --user pix --password-file ~/.vm-pw

It builds the package of the checked-out commit on the target (makepkg on
Arch, dpkg-buildpackage on Debian), installs it, checks what can be checked
over ssh, reboots the machine when you say so, asks you what the console
showed (the codes against your authenticator, the disk unlock), checks the
booted system and its journal, and writes a report with every log in one
directory. Nothing but Python's standard library and ssh are needed here;
the target needs ssh and sudo for the user given.

The attestation by phone (Bluetooth) is not part of this run.
"""

import argparse
import datetime
import fcntl
import getpass
import hashlib
import json
import os
import pty
import re
import select
import shlex
import subprocess
import sys
import tempfile
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- the log

class Log:
    """The run's directory: a transcript and a file per step."""

    def __init__(self, path):
        self.dir = path
        os.makedirs(path, exist_ok=True)
        self.transcript = open(os.path.join(path, "transcript.log"), "a")

    def say(self, text=""):
        print(text, flush=True)
        self.transcript.write(text + "\n")
        self.transcript.flush()

    def head(self, text):
        self.say("")
        self.say("=== " + text)

    def save(self, name, text):
        with open(os.path.join(self.dir, name), "w") as f:
            f.write(text)

    def ask_yes_no(self, question):
        while True:
            answer = input(question + " [y/n] ").strip().lower()
            self.transcript.write(f"{question} -> {answer}\n")
            self.transcript.flush()
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def ask(self, question):
        answer = input(question + " ").strip()
        self.transcript.write(f"{question} -> {answer}\n")
        self.transcript.flush()
        return answer


# ---------------------------------------------------------------- ssh

class Target:
    """A machine over ssh. The password, when there is one, is typed at
    ssh's prompt through a pty; the first connection opens a control
    socket the later ones share, so it is typed once per boot."""

    def __init__(self, host, user, port, password, key, log):
        self.host, self.user, self.port, self.password, self.key, self.log = host, user, port, password, key, log
        self.sockdir = tempfile.mkdtemp(prefix="tpm2-kira-acceptance-")
        self.nopasswd_sudo = None

    def _base(self, scp=False):
        args = ["-o", "BatchMode=" + ("yes" if self.password is None else "no"),
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=15",
                "-o", "ServerAliveInterval=15",
                "-o", "ControlMaster=auto",
                "-o", "ControlPath=" + os.path.join(self.sockdir, "cm-%C"),
                "-o", "ControlPersist=600",
                "-o", "NumberOfPasswordPrompts=1"]
        if self.key:
            args += ["-i", self.key, "-o", "IdentitiesOnly=yes"]
        else:
            # Only the password: ssh would otherwise offer the person's own
            # keys first and wait for a passphrase.
            args += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
        args += ["-P" if scp else "-p", str(self.port)]
        return args

    def _run(self, argv, stdin_text=None, timeout=1800):
        """Runs ssh/scp under a pty, answers the password prompt, returns
        (rc, output). The command's own stdin is a pipe (stdin_text)."""
        out = bytearray()
        pw_sent = False
        scanned = 0
        master, slave = pty.openpty()
        r_in, w_in = os.pipe()
        # ssh asks for the password on its controlling terminal (/dev/tty):
        # the child gets a session of its own with the pty as that terminal,
        # while its stdin stays the pipe the command's input comes from.
        def controlling_tty():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        proc = subprocess.Popen(argv, stdin=r_in, stdout=slave, stderr=slave, close_fds=True,
                                pass_fds=[slave], preexec_fn=controlling_tty)
        os.close(slave)
        os.close(r_in)
        if stdin_text is not None:
            os.write(w_in, stdin_text.encode())
        os.close(w_in)
        deadline = time.time() + timeout
        while True:
            if time.time() > deadline:
                proc.kill()
                raise TimeoutError(" ".join(argv))
            ready, _, _ = select.select([master], [], [], 1.0)
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                out += data
                tail = out[scanned:]
                if not pw_sent and self.password is not None and re.search(rb"[Pp]assword:\s*$", tail):
                    os.write(master, (self.password + "\n").encode())
                    pw_sent = True
                    out += b"\n"
                    scanned = len(out)
                elif re.search(rb"(passphrase for key|[Pp]assword:)\s*$", tail):
                    # A second password prompt, or a key's passphrase: the
                    # credentials do not fit; do not sit at the prompt.
                    proc.kill()
                    proc.wait()
                    os.close(master)
                    raise SystemExit("ssh asks: " + tail.decode("utf-8", "replace").strip().split("\n")[-1]
                                     + "\n(the password is wrong, or an ssh key wants its passphrase)")
            elif proc.poll() is not None:
                break
        rc = proc.wait()
        os.close(master)
        text = out.decode("utf-8", "replace").replace("\r\n", "\n")
        if pw_sent:
            text = re.sub(r"[^\n]*[Pp]assword:[^\n]*\n", "", text, count=1).lstrip("\n")
        return rc, text

    def run(self, cmd, root=False, stdin_text=None, timeout=1800):
        """Runs cmd (a shell command line) on the target."""
        if root:
            if self.nopasswd_sudo is None:
                rc, _ = self.run("sudo -n true")
                self.nopasswd_sudo = rc == 0
            if self.nopasswd_sudo:
                cmd = "sudo -n -- sh -c " + shlex.quote(cmd)
            else:
                if self.password is None:
                    raise SystemExit("sudo on the target needs a password: give one")
                cmd = "sudo -S -p '' -- sh -c " + shlex.quote(cmd)
                stdin_text = self.password + "\n" + (stdin_text or "")
        argv = ["ssh"] + self._base() + [f"{self.user}@{self.host}", cmd]
        return self._run(argv, stdin_text, timeout)

    def copy_to(self, local, remote):
        argv = ["scp", "-q"] + self._base(scp=True) + [local, f"{self.user}@{self.host}:{remote}"]
        rc, out = self._run(argv)
        if rc != 0:
            raise SystemExit(f"scp {local}: {out}")

    def interactive(self, cmd):
        """Hands the terminal to a command on the target (the person types)."""
        argv = ["ssh", "-t"] + self._base() + [f"{self.user}@{self.host}", cmd]
        return subprocess.call(argv)

    def wait_down(self, timeout=180):
        end = time.time() + timeout
        while time.time() < end:
            rc, _ = self.run("true", timeout=20)
            if rc != 0:
                return True
            time.sleep(3)
        return False

    def wait_up(self, timeout=900):
        end = time.time() + timeout
        while time.time() < end:
            try:
                rc, out = self.run("echo up", timeout=30)
                if rc == 0 and "up" in out:
                    return True
            except TimeoutError:
                pass
            time.sleep(5)
        return False


# ---------------------------------------------------------------- the checks

class Report:
    def __init__(self):
        self.checks = []   # (name, status, detail)
        self.answers = []  # (question, answer)
        self.issues = []   # strings

    def check(self, name, ok, detail=""):
        self.checks.append((name, "PASS" if ok else "FAIL", detail))
        return ok

    def skip(self, name, why):
        self.checks.append((name, "SKIP", why))

    def failed(self):
        return [c for c in self.checks if c[1] == "FAIL"] or [a for a in self.answers if a[1] is False]


def git(*args):
    return subprocess.check_output(["git", "-C", REPO] + list(args), text=True).strip()


def pacman_version(rev):
    """pkgver as the PKGBUILD computes it from git describe: 0.5.0_rc1.r74.ge7bcf0f."""
    d = git("describe", "--tags", "--long", rev)
    d = re.sub(r"^v", "", d)
    d = re.sub(r"-(\d+)-g", r".r\1.g", d)
    return d.replace("-", "_")


def build_and_install(t, distro, rev, log, rep):
    short = git("rev-parse", "--short", rev)
    full = git("rev-parse", rev)
    tarball = f"tpm2-kira-{short}.tar.gz"
    local = os.path.join(log.dir, tarball)
    subprocess.check_call(["git", "-C", REPO, "archive", "--format=tar.gz", f"--prefix=tpm2-kira-{short}/",
                           "-o", local, rev])
    digest = hashlib.sha256(open(local, "rb").read()).hexdigest()
    # The user's home by its path: '~' would be root's in the root commands.
    work = t.run("echo $HOME")[1].strip() + "/tpm2-kira-acceptance"
    log.head(f"build {short} on {t.host} ({distro})")
    t.run(f"mkdir -p {work} && rm -rf {work}/tpm2-kira-* {work}/PKGBUILD {work}/src {work}/pkg")
    t.copy_to(local, f"{work}/{tarball}")

    if distro == "arch":
        version = pacman_version(rev)
        rc, out = t.run("pacman -S --needed --noconfirm base-devel go", root=True)
        log.save("build-deps.log", out)
        if rc != 0:
            rep.check("build dependencies", False, out[-500:])
            return None
        pkgbuild = open(os.path.join(REPO, "packaging", "aur", "PKGBUILD")).read()
        pkgbuild = re.sub(r"^_tag=.*\n", "", pkgbuild, flags=re.M)
        pkgbuild = re.sub(r"^pkgver=.*$", f"pkgver={version}", pkgbuild, flags=re.M)
        pkgbuild = re.sub(r"^source=.*$", f'source=("{tarball}")', pkgbuild, flags=re.M)
        pkgbuild = re.sub(r"^sha256sums=.*$", f"sha256sums=('{digest}')", pkgbuild, flags=re.M)
        pkgbuild = re.sub(r"^_srcdir=.*$", f'_srcdir="$pkgname-{short}"', pkgbuild, flags=re.M)
        pb = os.path.join(log.dir, "PKGBUILD")
        open(pb, "w").write(pkgbuild)
        t.copy_to(pb, f"{work}/PKGBUILD")
        rc, out = t.run(f"cd {work} && makepkg -f --nocheck 2>&1")
        log.save("build.log", out)
        if not rep.check("package builds (makepkg)", rc == 0, out[-800:] if rc else ""):
            return None
        rc, pkg = t.run(f"ls {work}/tpm2-kira-{version}-*.pkg.tar.zst | grep -v debug | head -1")
        pkg = pkg.strip()
        rc, out = t.run(f"pacman -U --noconfirm {shlex.quote(pkg)} 2>&1", root=True)
        log.save("install.log", out)
        # pacman's exit is non-zero when a hook (mkinitcpio) reports an
        # error; the package may still be installed. The version decides.
        rc2, installed = t.run("pacman -Q tpm2-kira")
        rep.check("package installs (pacman -U)", rc2 == 0 and version in installed, installed.strip() + ("" if rc == 0 else " (pacman exit %d: see install.log)" % rc))
        if rc != 0:
            rep.issues.append("pacman -U exited %d; a hook reported an error (install.log)" % rc)
        expected = version
    else:
        rc, _ = t.run("dpkg -s build-essential debhelper >/dev/null 2>&1")
        if rc != 0:
            rc, out = t.run("apt-get install -y build-essential debhelper 2>&1", root=True)
            log.save("build-deps.log", out)
            if rc != 0:
                rep.check("build dependencies", False, out[-500:])
                return None
        rc, _ = t.run("test -x /usr/local/go/bin/go")
        if rc != 0:
            log.say("installing Go from go.dev into /usr/local/go")
            rc, out = t.run("set -e; cd /tmp; GO=$(wget -qO- 'https://go.dev/VERSION?m=text' | head -1); "
                            "wget -q \"https://go.dev/dl/${GO}.linux-amd64.tar.gz\"; "
                            "echo \"$(wget -qO- \"https://dl.google.com/go/${GO}.linux-amd64.tar.gz.sha256\")  ${GO}.linux-amd64.tar.gz\" | sha256sum -c -; "
                            "rm -rf /usr/local/go; tar -C /usr/local -xzf \"${GO}.linux-amd64.tar.gz\"", root=True)
            log.save("go-install.log", out)
            if rc != 0:
                rep.check("Go on the target", False, out[-500:])
                return None
        base = git("show", f"{rev}:debian/changelog").split("\n")[0]
        m = re.match(r"\S+ \(([^)]+)\)", base)
        version = f"{m.group(1)}+{short}"
        rc, out = t.run(f"set -e; cd {work} && tar xzf {tarball} && cd tpm2-kira-{short} && "
                        f"sed -i '1s/({m.group(1)})/({version})/' debian/changelog && "
                        # debian/rules caches under the tree, which this run throws
                        # away: the user's cache instead, kept across runs. The unit
                        # tests have their own run; the package build skips them.
                        "mkdir -p $HOME/.cache/go-build && GOCACHE=$HOME/.cache/go-build DEB_BUILD_OPTIONS=nocheck PATH=/usr/local/go/bin:$PATH dpkg-buildpackage -us -uc -b 2>&1")
        log.save("build.log", out)
        if not rep.check("package builds (dpkg-buildpackage)", rc == 0, out[-800:] if rc else ""):
            return None
        deb = f"{work}/tpm2-kira_{version}_amd64.deb"
        rc, out = t.run(f"dpkg -i {deb} 2>&1", root=True)
        log.save("install.log", out)
        rc2, installed = t.run("dpkg-query -W -f='${Version}' tpm2-kira")
        rep.check("package installs (dpkg -i)", rc == 0 and installed.strip() == version, installed.strip())
        expected = version

    # What the install's hook did with the slots.
    if "SKIPPED" in out:
        rep.issues.append("the install's reseal was SKIPPED (install.log)")
    rep.check("install hook resealed", "reseal completed successfully" in out or "Successfully resealed" in out,
              "no reseal in the install output" if "resealed" not in out else "")
    return expected


def check_installed(t, distro, expected, mode_wanted, luks_device, log, rep):
    log.head("checks on the installed system")
    rc, out = t.run("tpm2-kira version")
    rep.check("version is the built commit", rc == 0 and expected in out, out.strip())

    rc, out = t.run("tpm2-kira status 2>&1; echo rc=$?")
    rep.check("root gate: 'status' as a user refuses", "root is needed - sudo tpm2-kira status" in out and "rc=1" in out, out.strip())
    rc, out = t.run("tpm2-kira control </dev/null 2>&1; echo rc=$?")
    rep.check("root gate: 'control' as a user refuses", "root is needed - sudo tpm2-kira control" in out and "rc=1" in out, out.strip())
    rc, out = t.run("tpm2-kira help >/dev/null 2>&1; echo rc=$?")
    rep.check("'help' answers as a user", "rc=0" in out)

    rc, out = t.run("tpm2-kira attest config-check 2>&1", root=True)
    rep.check("control.conf loads (attest config-check)", rc == 0 and ": valid" in out, out.strip())

    rc, out = t.run("tpm2-kira status --json", root=True)
    log.save("status-installed.json", out)
    status = None
    try:
        status = json.loads(out)
    except ValueError:
        rep.check("status --json", False, out[-300:])
    if status:
        rep.check("status: the TPM opens", not status.get("tpm_error"), status.get("tpm_error", ""))
        slots = status.get("slots", [])
        rep.check("status: a slot is sealed", len(slots) > 0)
        rep.check("status: every slot signed by this machine's key", all(s["signed"] for s in slots),
                  "; ".join(f"slot {s['slot_number']}: {s.get('sign_reason', '')}" for s in slots if not s["signed"]))
        rep.check("status: a fallback slot (PCRs 0 and 7)", any(s["fallback"] for s in slots))
        rep.check("status: every slot's generation matches (no reseal due)",
                  all("matches" in s["generation_state"] or "read-locked" in s["generation_state"] for s in slots),
                  "; ".join(f"slot {s['slot_number']}: {s['generation_state']}" for s in slots))
        rep.check("status: no notes", not status.get("notes"), "\n".join(status.get("notes", [])))
        rep.check("status: unlock mode is " + mode_wanted, status.get("unlock_mode") == mode_wanted,
                  f"mode {status.get('unlock_mode')!r} in {status.get('config')}")
        if mode_wanted != "skip":
            marked = [(d["device"], ks["keyslot"]) for d in status.get("devices", [])
                      for ks in d.get("keyslots", []) if ks.get("token") and ks["token"].get("mode") == mode_wanted]
            rep.check(f"a LUKS keyslot is marked {mode_wanted}", bool(marked), str(marked))
    rc, out = t.run("tpm2-kira status", root=True)
    log.save("status-installed.txt", out)
    log.say(out.rstrip())

    # The initramfs: the binary and control.conf in it, the PIN line not.
    log.head("the initramfs")
    if distro == "arch":
        script = r"""
set -e
d=$(mktemp -d); cd "$d"
uki=$(sed -n 's/^default_uki="\(.*\)"/\1/p' /etc/mkinitcpio.d/*.preset | head -1)
if [ -n "$uki" ] && [ -f "$uki" ]; then
  echo "image: $uki"
  objcopy -O binary --only-section=.initrd "$uki" initrd
else
  img=$(ls /boot/initramfs-*.img | grep -v fallback | head -1)
  echo "image: $img"
  cp "$img" initrd
fi
lsinitcpio -x initrd >/dev/null
ls usr/bin/tpm2-kira etc/tpm2-kira/control.conf
echo '--- control.conf in the image:'
cat etc/tpm2-kira/control.conf | grep -v '^#' | grep .
cd /; rm -rf "$d"
"""
    else:
        script = r"""
set -e
d=$(mktemp -d); cd "$d"
img=/boot/initrd.img-$(uname -r)
echo "image: $img"
unmkinitramfs "$img" x
cd x; [ -d main ] && cd main
ls usr/bin/tpm2-kira etc/tpm2-kira/control.conf 2>/dev/null || ls bin/tpm2-kira etc/tpm2-kira/control.conf
echo '--- control.conf in the image:'
cat etc/tpm2-kira/control.conf | grep -v '^#' | grep .
cd /; rm -rf "$d"
"""
    rc, out = t.run(script, root=True)
    log.save("initramfs.log", out)
    log.say(out.rstrip())
    rep.check("initramfs holds tpm2-kira and control.conf", rc == 0, out[-400:] if rc else "")
    rep.check("initramfs copy of control.conf has no PIN line", rc == 0 and "TPM2_KIRA_PIN" not in out)
    rep.check("initramfs copy of control.conf sets the mode", rc == 0 and f"TPM2_KIRA_UNLOCK={mode_wanted}" in out.replace("'", "").replace('"', ""))

    rc, out = t.run("ls -la /etc/tpm2-kira/ /etc/tpm2-kira/keys/ 2>&1; stat -c '%U %a %n' /etc/tpm2-kira/control.conf", root=True)
    log.save("etc-tpm2-kira.log", out)
    if "TPM2_KIRA_PIN" in t.run("cat /etc/tpm2-kira/control.conf", root=True)[1]:
        rep.check("control.conf with a PIN is root's, mode 600", out.strip().endswith("root 600 /etc/tpm2-kira/control.conf"), out.strip().split("\n")[-1])

    # The codes this boot shows, for the comparison after the reboot.
    rc, out = t.run("for s in 0 1; do echo \"slot $s: $(tpm2-kira reveal-plain --nvram $s 2>&1 | tail -1)\"; done", root=True)
    log.save("codes-before-reboot.txt", out)
    log.say("codes now (read-locked after boot is expected: 'cap' ran):")
    log.say(out.rstrip())


def ensure_luks(t, mode_wanted, luks_device, log, rep):
    """A keyslot for the mode, enrolled by the person at the terminal when
    there is none; then the mode in control.conf through control's step."""
    if mode_wanted == "skip" or not luks_device:
        return
    rc, out = t.run("tpm2-kira status --json", root=True)
    status = json.loads(out) if rc == 0 else {}
    marked = [ks for d in status.get("devices", []) if d["device"] == luks_device
              for ks in d.get("keyslots", []) if ks.get("token") and ks["token"].get("mode") == mode_wanted]
    if not marked:
        log.head(f"luks enrol {luks_device} --mode {mode_wanted}")
        log.say("No keyslot of tpm2-kira's with that mode. The enrolment asks for the device's")
        log.say("passphrase, then the password and the salt the boot will ask for. Your terminal now:")
        rc = t.interactive(f"sudo tpm2-kira luks enrol {shlex.quote(luks_device)} --mode {mode_wanted}")
        rep.check(f"luks enrol {luks_device} --mode {mode_wanted}", rc == 0, f"exit {rc}")
    if status.get("unlock_mode") != mode_wanted:
        log.head(f"TPM2_KIRA_UNLOCK={mode_wanted}")
        log.say("control sets the mode (its 'Unlock at boot' step): your terminal now. Pick")
        log.say("'Unlock at boot', confirm, then Leave.")
        t.interactive("sudo tpm2-kira control")
        rc, out = t.run("tpm2-kira status --json", root=True)
        mode = json.loads(out).get("unlock_mode") if rc == 0 else None
        rep.check(f"control set TPM2_KIRA_UNLOCK={mode_wanted}", mode == mode_wanted, f"mode {mode!r}")
        if mode == mode_wanted:
            rc, out = t.run("if [ -x /usr/bin/mkinitcpio ]; then mkinitcpio -P; else update-initramfs -u; fi 2>&1", root=True)
            log.save("initramfs-rebuild.log", out)
            rep.check("initramfs rebuilt with the mode", rc == 0 and "SKIPPED" not in out, out[-400:] if rc else "")


def reboot_and_ask(t, mode_wanted, log, rep):
    log.head("reboot")
    log.say("At the console the machine will show its code screen. Have your authenticator ready;")
    if mode_wanted != "skip":
        log.say(f"the disk unlock then asks for the password and the salt ({mode_wanted}).")
    if not log.ask_yes_no(f"Reboot {t.host} now and watch its console?"):
        rep.skip("reboot", "declined")
        return False
    t.run("systemctl reboot", root=True)
    log.say("rebooting; waiting for the machine to go down ...")
    if not t.wait_down():
        rep.issues.append("the machine did not go down within three minutes")
    log.say("down. Waiting for ssh to come back (your turn at the console) ...")
    if not t.wait_up():
        rep.check("the machine comes back after the reboot", False, "no ssh within 15 minutes")
        return False
    rep.check("the machine comes back after the reboot", True)
    log.say("back.")
    log.head("what the console showed")
    a = log.ask_yes_no("Did the code screen show slot 0's code, and did it match your authenticator?")
    rep.answers.append(("slot 0's code matched the authenticator", a))
    a = log.ask_yes_no("Did the fallback slot's code (slot 1) match its authenticator entry?")
    rep.answers.append(("slot 1's code matched the authenticator", a))
    if mode_wanted != "skip":
        a = log.ask_yes_no(f"Did the disk unlock at tpm2-kira's prompt with the password and the salt ({mode_wanted})?")
        rep.answers.append((f"the disk unlocked with {mode_wanted}", a))
    note = log.ask("Anything else you saw (empty for nothing)?")
    if note:
        rep.answers.append(("note", note))
    return True


def check_booted(t, distro, expected, mode_wanted, log, rep):
    log.head("checks on the booted system")
    t.nopasswd_sudo = None
    rc, out = t.run("tpm2-kira status --json", root=True)
    log.save("status-booted.json", out)
    try:
        status = json.loads(out)
    except ValueError:
        rep.check("status --json after boot", False, out[-300:])
        status = {}
    if status:
        slots = status.get("slots", [])
        rep.check("after boot: slot 0 is read-locked (cap ran at the code screen)",
                  any(s["slot_number"] == 0 and "read-locked" in s["generation_state"] for s in slots),
                  "; ".join(f"slot {s['slot_number']}: {s['generation_state']}" for s in slots))
        rep.check("after boot: no slot needs a reseal", not any("NOT" in s["generation_state"] or "unavailable" in s["generation_state"] for s in slots))
        rep.check("after boot: no notes", not status.get("notes"), "\n".join(status.get("notes", [])))
    rc, out = t.run("tpm2-kira status", root=True)
    log.save("status-booted.txt", out)
    log.say(out.rstrip())

    units = "tpm2-kira.service tpm2-kira-cap.service tpm2-kira-unlock.socket tpm2-kira-unlock.service tpm2-kira-attest.service"
    rc, out = t.run(f"journalctl -b -o short-iso --no-pager -t tpm2-kira $(for u in {units}; do echo -u $u; done) 2>&1", root=True)
    log.save("journal-tpm2-kira.log", out)
    rc, errs = t.run("journalctl -b -o short-iso --no-pager -p err 2>&1", root=True)
    log.save("journal-errors.log", errs)
    rc, cs = t.run("journalctl -b -o short-iso --no-pager -u 'systemd-cryptsetup@*' 2>&1", root=True)
    log.save("journal-cryptsetup.log", cs)
    rc, units_out = t.run(f"systemctl --no-pager --no-legend list-units --all '{'tpm2-kira*'}' 2>&1; systemctl --failed --no-legend --no-pager", root=True)
    log.save("units.log", units_out)

    # The analysis: what the boot's journal says against tpm2-kira.
    bad = re.compile(r"FAILED|SKIPPED|mismatch|cannot|refused|unavailable|error", re.I)
    for line in out.split("\n"):
        if bad.search(line) and "tpm2-kira" in line:
            rep.issues.append("journal: " + line.strip())
    for line in errs.split("\n"):
        if "tpm2-kira" in line or "cryptsetup" in line:
            rep.issues.append("journal (err): " + line.strip())
    for line in units_out.split("\n"):
        if "failed" in line and "tpm2-kira" in line:
            rep.issues.append("unit: " + line.strip())
    rep.check("the boot's journal has no tpm2-kira failure", not any(i.startswith("journal") for i in rep.issues))
    rep.check("the code screen ran (tpm2-kira.service in the journal)", "tpm2-kira.service" in out or "KIRA" in out,
              "" if "tpm2-kira" in out else "nothing from tpm2-kira in this boot's journal")
    if mode_wanted != "skip":
        rep.check("the unlock socket served the boot", "tpm2-kira-unlock" in out and "cryptsetup" in cs.lower(),
                  "" if "tpm2-kira-unlock" in out else "no tpm2-kira-unlock lines in the journal")
    rc, out = t.run("tpm2-kira version")
    rep.check("after boot: the version is the built commit", expected in out, out.strip())


def write_report(log, rep, args, expected):
    lines = [f"tpm2-kira acceptance: {args.distro} on {args.host}, package {expected}",
             datetime.datetime.now().isoformat(timespec="seconds"), ""]
    for name, status, detail in rep.checks:
        lines.append(f"[{status}] {name}" + (f" - {detail}" if detail and status != "PASS" else ""))
    if rep.answers:
        lines += ["", "Your answers:"]
        for q, a in rep.answers:
            lines.append(f"  {q}: {'yes' if a is True else 'NO' if a is False else a}")
    lines += ["", "Issues from the logs:" if rep.issues else "No issues in the logs."]
    lines += ["  - " + i for i in rep.issues]
    failed = rep.failed()
    lines += ["", ("RESULT: FAIL (%d)" % len(failed)) if failed else "RESULT: PASS", f"logs: {log.dir}"]
    text = "\n".join(lines) + "\n"
    log.save("report.txt", text)
    log.say("")
    log.say(text.rstrip())
    return not failed


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--distro", choices=["arch", "debian"], required=True)
    p.add_argument("--host", required=True, help="the target's address")
    p.add_argument("--user", default=getpass.getuser())
    p.add_argument("--port", type=int, default=22)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--password", help="the user's password (prefer --ask-password or --password-file)")
    g.add_argument("--password-file", help="a file holding the password")
    g.add_argument("--ask-password", action="store_true", help="ask for the password at the start")
    p.add_argument("--key", help="an ssh key instead of a password")
    p.add_argument("--rev", default="HEAD", help="the commit to build (default HEAD)")
    p.add_argument("--mode", default=None, choices=["skip", "password+salt", "password+remotesalt"],
                   help="the unlock mode the boot is expected in (default: what the target has)")
    p.add_argument("--luks", metavar="DEVICE", help="the LUKS device to enrol a keyslot on when --mode needs one and none is there")
    p.add_argument("--no-build", action="store_true", help="test what is installed; no package")
    p.add_argument("--no-reboot", action="store_true", help="stop before the reboot")
    p.add_argument("--log-dir", help="where the run's logs go (default: ./acceptance-<distro>-<host>-<time>)")
    args = p.parse_args()

    password = args.password
    if args.password_file:
        password = open(os.path.expanduser(args.password_file)).read().strip()
    elif args.ask_password:
        password = getpass.getpass(f"password for {args.user}@{args.host}: ")
    if password is None and not args.key:
        print("a password (--ask-password, --password-file) or a key (--key) is needed", file=sys.stderr)
        return 2

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log = Log(args.log_dir or os.path.join(os.getcwd(), f"acceptance-{args.distro}-{args.host}-{stamp}"))
    rep = Report()
    t = Target(args.host, args.user, args.port, password, args.key, log)

    log.head(f"target {args.user}@{args.host}")
    rc, out = t.run(". /etc/os-release && echo \"$ID $VERSION_ID\"; uname -r; uname -n")
    if rc != 0:
        log.say(out)
        return 2
    log.say(out.rstrip())
    osid = out.split("\n")[0].split(" ")[0]
    if not rep.check("the target runs the distribution", osid == args.distro, f"os-release ID {osid!r}"):
        write_report(log, rep, args, "-")
        return 1
    rc, out = t.run("true", root=True)
    if not rep.check("sudo works for the user", rc == 0, out.strip()):
        write_report(log, rep, args, "-")
        return 1
    # The build fetches modules: Go's own resolver reads /etc/resolv.conf
    # (an empty one fails where getent, through nss, still answers). A
    # defect of the machine is reported, not repaired.
    if not args.no_build:
        rc, out = t.run("grep -q '^nameserver' /etc/resolv.conf && getent hosts proxy.golang.org >/dev/null && echo ok")
        if not rep.check("the target resolves names (a nameserver in /etc/resolv.conf)", "ok" in out,
                         "fix the machine's resolver first (systemd-resolved: /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf)"):
            write_report(log, rep, args, "-")
            return 1

    if args.no_build:
        rc, out = t.run("tpm2-kira version")
        expected = out.strip().split(" ")[-1] if rc == 0 else "-"
    else:
        expected = build_and_install(t, args.distro, args.rev, log, rep)
        if expected is None:
            write_report(log, rep, args, "-")
            return 1

    rc, out = t.run("tpm2-kira status --json", root=True)
    mode_now = json.loads(out).get("unlock_mode", "skip") if rc == 0 else "skip"
    mode_wanted = args.mode or mode_now
    ensure_luks(t, mode_wanted, args.luks, log, rep)
    check_installed(t, args.distro, expected, mode_wanted, args.luks, log, rep)

    if not args.no_reboot and reboot_and_ask(t, mode_wanted, log, rep):
        check_booted(t, args.distro, expected, mode_wanted, log, rep)
    elif args.no_reboot:
        rep.skip("reboot", "--no-reboot")
    return 0 if write_report(log, rep, args, expected) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
