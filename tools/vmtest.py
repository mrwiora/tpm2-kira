#!/usr/bin/env python3
"""The VM test: tpm2-kira's whole life on a fresh, encrypted test VM.

    tools/vmtest.py --target both              # or arch, or debian
    tools/vmtest.py --target both --cycles 3 --no-vault

It runs with nobody at the keyboard and ends with ALL PASS (exit 0) or
FAILED. Before the machines are touched it builds the packages of the
committed state (packaging/build-packages.sh: HEAD, aSSH as pinned) and
installs exactly those - never a package of another commit; --no-build
takes the ones of HEAD already in build/packages.

The machines are described in tools/vmtest.conf (an address, a user with
sudo, the LUKS device's passphrase, and how to reset it; see
vmtest.conf.example). Each is put back into its defined state first: the
machine's `reset` command (going back to its snapshot on the hypervisor,
for example) runs, and the run waits for its ssh. Fresh means: tpm2-kira
not installed, /etc/tpm2-kira absent, a LUKS-encrypted root whose
passphrase is known, a TPM, and an ssh server for the user; a machine
that is not is refused. Without a `reset` command (or with --no-reset)
the machine must be fresh already. The run changes the machine
(packages, slots in its TPM, an SSH CA in an EFI variable, a keyslot, the
boot image).

What it does, each step a check in the report:

  1. the package from build/packages (dpkg -i, pacman -U) - never built on
     the target - and the root gates
  2. setup --local, slot add; the TPM's code against the one computed from
     the secret slot add shows (the person's authenticator)
  3. the commands that read: status, slot info/list/status, phone ekcert,
     luks status, initramfs plan, help
  4. luks enrol --mode password+salt (a password, a salt, the passphrase)
  5. control, as a person would answer it (ACCESSIBLE=1, line by line):
     the boot chain's adoptions, the boot image's network (DHCP), the SSH
     server at boot with its SSH CA, debug at boot, the image rebuilt; the
     key that may log in at boot is a test key made here
  6. the image: tpm2-kira-boot and its plan, no tpm2-kira, no control.conf
  7. --cycles reboots: the boot SSH server, its host key checked against
     the SSH CA (StrictHostKeyChecking), the codes of both slots against the
     computed ones, Enter, the password and the salt typed in the session;
     after each boot: the cap ran, the key was answered, no tpm2-kira error
  8. remote attestation over TLS, the vault: tpm2-kira-vault runs here, in
     a container with a software TPM of its own (tools/vmtest-vault/),
     published on the [vault] port; luks enrol --mode tpm+vault with a
     token it made; the image rebuilt with the vault; a boot that nobody
     touches, unlocked by the vault's release to the TPM's quote; a boot
     with the device revoked on the vault, where the password+salt keyslot
     is the fallback, typed over SSH
  9. a slot's life: approve, add slot 2, delete it whole
 10. removal: control switches SSH off and asks before it removes the SSH
     CA (No keeps it); slot delete --yes takes everything of tpm2-kira -
     no index of its range left in the TPM, no KIRAasshCA variable, no
     ssh_ca.pub

Nothing but Python's standard library and ssh are needed here. Reports and
every session's transcript land in the run's directory.
"""

import argparse
import base64
import configparser
import datetime
import glob
import hashlib
import hmac
import importlib.util
import json
import os
import pty
import re
import select
import shlex
import struct
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("acceptance", os.path.join(REPO, "tools", "acceptance.py"))
acceptance = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acceptance)

ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\r")

# The answers the test gives where a person would type: the disk's
# password+salt keyslot it enrols, and the boot SSH server's settings.
TEST_PASSWORD = "kira-vmtest-pw"
TEST_SALT = "kira-vmtest-salt"
SSH_PORT = 2222
SSH_HOLD = 600


def clean(data):
    return ANSI.sub(b"", data).decode("utf-8", "replace")


def totp(secret, at):
    key = base64.b32decode(secret)
    mac = hmac.new(key, struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
    o = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def code_matches(secret, code, at):
    """The code of the window at, or of the one before or after (a screen
    drawn at a window's edge)."""
    return any(totp(secret, at + d) == code for d in (-30, 0, 30))


class Fail(Exception):
    pass


class Session:
    """An interactive ssh session in a pty: expect text, send keys. The
    password prompts of ssh and sudo are answered by themselves; every
    other prompt is the test's to answer."""

    def __init__(self, argv, log_path, password=None):
        self.password = password
        self.log = open(log_path, "ab", buffering=0)
        self.buf = b""
        self.mark = 0      # expect looks at what came after it
        self.answered = 0  # the password prompts are looked for after it
        self.closed = False
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp(argv[0], argv)

    def _pump(self, timeout):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            data = b""
        if not data:
            self.closed = True
            return
        self.log.write(data)
        self.buf += data
        tail = self.buf[self.answered:][-300:]
        if self.password and (re.search(rb"'s password: ?$", tail) or re.search(rb"\[sudo\] password for [^:]*: ?$", tail)):
            os.write(self.fd, (self.password + "\n").encode())
            self.answered = len(self.buf)

    def text(self):
        return clean(self.buf[self.mark:])

    def expect(self, pattern, timeout=60):
        """Waits until pattern shows in what came since the last expect;
        returns that text up to the match's end and moves the mark there."""
        deadline = time.time() + timeout
        rx = re.compile(pattern, re.M)
        while True:
            raw = self.buf[self.mark:]
            m = rx.search(clean(raw))
            if m:
                # move the mark to the raw end of the match: clean text and
                # raw bytes differ, so take the shortest raw prefix that
                # cleans to past the match
                cut = len(raw)
                for i in range(len(raw) + 1):
                    if len(clean(raw[:i])) >= m.end():
                        cut = i
                        break
                text = clean(raw[:cut])
                self.mark += cut
                return text, m
            if self.closed or time.time() > deadline:
                raise Fail(f"waited {timeout} s for /{pattern}/; the session showed:\n" + clean(raw)[-1500:])
            self._pump(min(1.0, max(0.0, deadline - time.time())))

    def send(self, s):
        os.write(self.fd, s.encode())

    def wait_end(self, timeout=600):
        deadline = time.time() + timeout
        while not self.closed and time.time() < deadline:
            self._pump(1.0)
        if not self.closed:
            raise Fail(f"the session did not end within {timeout} s:\n" + self.text()[-1500:])
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        return self.text()

    def close(self):
        if not self.closed:
            try:
                os.kill(self.pid, 9)
                os.waitpid(self.pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass


def menu_options(text):
    """The options of the last numbered menu in text: (number, line)."""
    lines = [l for l in text.splitlines() if l.strip()]
    if lines and lines[-1].lstrip().startswith("Enter a number"):
        lines = lines[:-1]
    opts = []
    for line in reversed(lines):
        m = re.match(r"\s*(\d+)\. (.*)", line)
        if not m:
            break
        opts.insert(0, (m.group(1), m.group(2)))
    return opts


class Vault:
    """tpm2-kira-vault for the run: built from the vault's source, in a
    container with swtpm (tools/vmtest-vault), its port published on this
    machine, created fresh for the run and removed after it."""

    NAME = "tpm2-kira-vmtest-vault"

    def __init__(self, src, url, port, run_dir):
        self.src, self.url, self.port = src, url, port
        self.dir = os.path.join(run_dir, "vault")
        os.makedirs(self.dir, exist_ok=True)
        self.lock = threading.Lock()

    def _sh(self, args, check=True):
        p = subprocess.run(args, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise Fail(f"{' '.join(args[:3])}: {p.stderr.strip() or p.stdout.strip()}"[-800:])
        return p.stdout + p.stderr

    def start(self):
        ctx = os.path.join(self.dir, "build")
        os.makedirs(ctx, exist_ok=True)
        for f in ("Dockerfile", "entrypoint.sh"):
            subprocess.run(["cp", "-p", os.path.join(REPO, "tools", "vmtest-vault", f), ctx], check=True)
        env = dict(os.environ, CGO_ENABLED="0")
        p = subprocess.run(["go", "build", "-o", os.path.join(ctx, "tpm2-kira-vault"), "."], cwd=self.src, env=env, capture_output=True, text=True)
        if p.returncode != 0:
            raise Fail("building tpm2-kira-vault: " + p.stderr[-800:])
        # Host networking for the build: name resolution inside a build
        # container is the host's to get right, and is not always.
        self._sh(["docker", "build", "--network", "host", "-q", "-t", self.NAME, ctx])
        self._sh(["docker", "rm", "-f", self.NAME], check=False)
        self._sh(["docker", "run", "-d", "--name", self.NAME, "-p", f"{self.port}:8443", "-e", f"VAULT_URL={self.url}", self.NAME])
        deadline = time.time() + 60
        while time.time() < deadline:
            if "serving " in self._sh(["docker", "logs", self.NAME], check=False):
                break
            time.sleep(1)
        else:
            raise Fail("the vault does not serve:\n" + self._sh(["docker", "logs", self.NAME], check=False)[-800:])

    def admin(self, *args):
        with self.lock:
            return self._sh(["docker", "exec", self.NAME, "tpm2-kira-vault"] + list(args))

    def stop(self):
        with open(os.path.join(self.dir, "vault.log"), "w") as f:
            f.write(self._sh(["docker", "logs", self.NAME], check=False))
            f.write("\n--- audit\n" + self._sh(["docker", "exec", self.NAME, "tpm2-kira-vault", "audit"], check=False))
        self._sh(["docker", "rm", "-f", self.NAME], check=False)


class Machine:
    def __init__(self, name, distro, host, user, password, luks_pass, run_dir, cycles):
        self.name, self.distro, self.host, self.user = name, distro, host, user
        self.password, self.luks_pass, self.cycles = password, luks_pass, cycles
        self.dir = os.path.join(run_dir, name)
        os.makedirs(self.dir, exist_ok=True)
        self.log = acceptance.Log(self.dir)
        self.rep = acceptance.Report()
        self.t = acceptance.Target(host, user, 22, password, None, self.log)
        self.secrets = []
        self.sessions = 0

    # -- helpers ------------------------------------------------------------

    def run(self, cmd, root=True, save=None):
        rc, out = self.t.run(cmd, root=root)
        if save:
            self.log.save(save, out)
        return rc, out

    def check(self, name, ok, detail=""):
        return self.rep.check(name, ok, detail if not ok else "")

    def session(self, remote_cmd, name):
        self.sessions += 1
        argv = ["ssh", "-tt", "-o", "StrictHostKeyChecking=accept-new", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                f"{self.user}@{self.host}", remote_cmd]
        return Session(argv, os.path.join(self.dir, f"session-{self.sessions:02d}-{name}.log"), self.password)

    def boot_session(self, n):
        argv = ["ssh", "-tt", "-p", str(SSH_PORT), "-i", os.path.join(self.dir, "bootkey"),
                "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + os.path.join(self.dir, "known_hosts_boot"),
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", f"root@{self.host}"]
        return Session(argv, os.path.join(self.dir, f"boot-{n}.log"))

    def port_open(self, port):
        import socket
        try:
            with socket.create_connection((self.host, port), timeout=2):
                return True
        except OSError:
            return False

    def wait_port(self, port, up, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.port_open(port) == up:
                return True
            time.sleep(2)
        return False

    # -- the steps ------------------------------------------------------------

    def reset(self, command):
        """Puts the machine back into its defined state: the configured
        command (VMTEST_NAME and VMTEST_HOST in its environment), then the
        machine must go away and come back on ssh."""
        self.log.head("reset: " + command)
        env = dict(os.environ, VMTEST_NAME=self.name, VMTEST_HOST=self.host)
        r = subprocess.run(command, shell=True, env=env, capture_output=True, text=True, timeout=900)
        self.log.save("reset.log", r.stdout + r.stderr)
        if not self.check("the reset command succeeds", r.returncode == 0, (r.stdout + r.stderr)[-500:]):
            raise Fail("reset failed")

    def preflight(self):
        self.log.head("preflight")
        # A machine just reset may still be starting.
        if not self.check("the machine answers on ssh", self.wait_port(22, True, 300), f"{self.host}:22 does not answer within 300 s"):
            raise Fail("unreachable")
        rc, out = self.run(". /etc/os-release && echo ID=$ID", root=False)
        if not self.check("the target runs " + self.distro, rc == 0 and f"ID={self.distro}" in out.split(), out.strip()):
            raise Fail("not the distribution")
        rc, out = self.run("test ! -e /etc/tpm2-kira && ! command -v tpm2-kira && echo fresh")
        if not self.check("the machine is fresh (no tpm2-kira, no /etc/tpm2-kira)", "fresh" in out, out.strip()):
            raise Fail("not fresh: go back to the snapshot")
        rc, out = self.run("test -c /dev/tpmrm0 && echo tpm")
        if not self.check("a TPM (/dev/tpmrm0)", "tpm" in out):
            raise Fail("no TPM")
        rc, out = self.run("lsblk -nrpo NAME,FSTYPE | awk '$2==\"crypto_LUKS\"{print $1}' | head -1")
        self.luks_dev = out.strip()
        if not self.check("a LUKS device", self.luks_dev.startswith("/dev/"), out.strip()):
            raise Fail("no LUKS device")
        rc, out = self.run(f"printf %s {shlex.quote(self.luks_pass)} | cryptsetup open --test-passphrase --key-file - {self.luks_dev} && echo opens")
        if not self.check(f"the LUKS passphrase opens {self.luks_dev}", "opens" in out):
            raise Fail("the configured LUKS passphrase does not open the device")

    def install(self, package):
        self.log.head("install " + os.path.basename(package))
        remote = "/tmp/" + os.path.basename(package)
        self.t.copy_to(package, remote)
        if self.distro == "debian":
            rc, out = self.run(f"dpkg -i {shlex.quote(remote)} 2>&1", save="install.log")
            rc2, ver = self.run("dpkg-query -W -f='${Version}' tpm2-kira", root=False)
            self.check("the package installs (dpkg -i)", rc == 0 and ver.strip() != "", out[-500:])
        else:
            rc, out = self.run(f"pacman -U --noconfirm {shlex.quote(remote)} 2>&1", save="install.log")
            rc2, ver = self.run("pacman -Q tpm2-kira", root=False)
            self.check("the package installs (pacman -U)", rc2 == 0, out[-500:])
            if rc != 0:
                self.rep.issues.append("pacman -U exited %d: a hook reported an error (install.log; on the test VM mkinitcpio's own fsck hook does)" % rc)
        self.version = ver.strip().split()[-1] if ver.strip() else "-"
        rc, out = self.run("tpm2-kira version; tpm2-kira-boot version", root=False)
        vers = re.findall(r"^tpm2-kira(?:-boot)? version (\S+)$", out, re.M)
        self.check("tpm2-kira and tpm2-kira-boot, of one version", len(vers) == 2 and vers[0] == vers[1], out.strip())
        rc, out = self.run("tpm2-kira status 2>&1; echo rc=$?", root=False)
        self.check("root gate: 'status' as a user refuses", "root is needed" in out and "rc=1" in out, out.strip())
        rc, out = self.run("tpm2-kira help >/dev/null 2>&1; echo rc=$?", root=False)
        self.check("'help' answers as a user", "rc=0" in out)

    def seal(self):
        self.log.head("setup and slot add")
        rc, out = self.run("tpm2-kira setup --local 2>&1", save="setup.log")
        self.check("setup --local makes the signing key", "Setup Complete" in out, out[-400:])
        rc, out = self.run("tpm2-kira slot add 2>&1", save="slot-add.log")
        self.secrets = re.findall(r"^Secret: ([A-Z2-7]+)", out, re.M)
        if not self.check("slot add seals slots 0 and 1, each with its secret", len(self.secrets) == 2, out[-600:]):
            raise Fail("no slots")
        rc, out = self.run("tpm2-kira reveal-plain --nvram 1 2>&1 | tail -1", save="reveal.log")
        at = time.time()
        m = re.search(r"\b(\d{6})\b", out)
        if m:
            self.check("slot 1's code is the authenticator's (computed from its secret)", code_matches(self.secrets[1], m.group(1), at), out.strip())
        else:
            # With systemd's measure point the running system is past the
            # OS separator: no code until the next boot, by design.
            self.check("slot 1: a code, or locked until the next boot (past the OS separator)", "Locked until the next boot" in out, out.strip())

    def inspect(self):
        self.log.head("the commands that read")
        cmds = {
            "status": ("tpm2-kira status 2>&1", r"slot 0 .*signed by this machine's key"),
            "slot info": ("tpm2-kira slot info --nvram 1 2>&1", r"Signature: valid"),
            "slot list": ("tpm2-kira slot list 2>&1", r"slot #0"),
            "slot status": ("tpm2-kira slot status --nvram 0 2>&1", r"Index: 0x01803010"),
            "phone ekcert": ("tpm2-kira phone ekcert 2>&1", r"EK certificate:"),
            "luks status": ("tpm2-kira luks status 2>&1", re.escape(self.luks_dev)),
            "initramfs plan": ("tpm2-kira initramfs plan 2>&1", r"in\s+TOTP codes"),
            "help slot": ("tpm2-kira help slot 2>&1", r"tpm2-kira slot add"),
            "help run (the boot binary's page)": ("tpm2-kira help run 2>&1", r"tpm2-kira-boot run"),
        }
        for name, (cmd, want) in cmds.items():
            rc, out = self.run(cmd, save="cmd-" + name.split(" (")[0].replace(" ", "-") + ".log")
            self.check(f"'{name}' answers", re.search(want, out) is not None, out[-400:])

    def enrol(self):
        self.log.head(f"luks enrol {self.luks_dev} --mode password+salt")
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --mode password+salt", "luks-enrol")
        try:
            s.expect(r"^Password: ?$", 60); s.send(TEST_PASSWORD + "\n")
            s.expect(r"The same password again: ?$"); s.send(TEST_PASSWORD + "\n")
            s.expect(r"Salt \(asked for at boot the same way\): ?$"); s.send(TEST_SALT + "\n")
            t0 = time.time()
            s.expect(r"to authorise: ?$", 900); s.send(self.luks_pass + "\n")
            self.log.say(f"Argon2id took {time.time() - t0:.0f} s here")
            text, _ = s.expect(r"keyslot (\d+) added: tpm2-kira, password\+salt", 300)
            out = s.wait_end(120)
            self.check("luks enrol adds a password+salt keyslot", True)
        except Fail as e:
            self.check("luks enrol adds a password+salt keyslot", False, str(e))
            raise
        finally:
            s.close()

    def control(self):
        self.log.head("control, answered line by line")
        s = self.session("sudo ACCESSIBLE=1 tpm2-kira control", "control")
        menu = r"Enter a number between 1 and \d+: ?$"
        try:
            # Step 1: every open adoption, written when asked; then on.
            for _ in range(10):
                text, _ = s.expect(menu, 120)
                opts = menu_options(text)
                pick = next((o for o in opts if o[1].startswith("•") and "adoption" in o[1]), None)
                if pick:
                    s.send(pick[0] + "\n")
                    s.expect(r"\[(y/N|Y/n)\] ?$"); s.send("y\n")
                    continue
                nxt = next((o for o in opts if "Continue to step 2" in o[1]), None)
                if not nxt or not nxt[1].startswith("•"):
                    raise Fail("step 1 does not offer step 2:\n" + text[-1200:])
                s.send(nxt[0] + "\n")
                break
            self.check("control step 1: the boot chain adopted (hook, route)", True)

            def pick(rx, timeout=120):
                text, _ = s.expect(menu, timeout)
                o = next((o for o in menu_options(text) if re.search(rx, o[1])), None)
                if not o:
                    raise Fail(f"no option /{rx}/ in:\n" + text[-1200:])
                s.send(o[0] + "\n")
                return text

            pick(r"Network and SSH at boot")
            pick(r"Network in the boot image")
            text = pick(r"^DHCP$")
            mac = re.findall(r"DHCP on ([0-9a-f:]{17})", text)
            if not mac:
                raise Fail("control proposes no interface:\n" + text[-800:])
            s.expect(r"Interface: its MAC address, or its name ?$"); s.send(mac[-1] + "\n")
            self.check("control: the boot image's network, DHCP on " + mac[-1], True)

            pick(r"SSH server at boot")
            s.expect(r"Start the SSH server with the code screen\? \[y/N\] ?$"); s.send("y\n")
            s.expect(r"SSH port ?$"); s.send(f"{SSH_PORT}\n")
            s.expect(r"Seconds the boot waits for the confirmation.*$"); s.send(f"{SSH_HOLD}\n")
            text, m = s.expect(r"(Create the SSH CA again, for this signing key\? \[Y/n\]|Create the SSH CA in the TPM) ?$", 300)
            if "again" in m.group(1):
                self.rep.issues.append("an SSH CA of an earlier installation was in the EFI variable; control made it again")
                s.send("y\n")
            pick(r"ECDSA P-256", 300)
            text, m = s.expect(r"@cert-authority \* (\S+ \S+)", 300)
            ca = m.group(1)
            with open(os.path.join(self.dir, "known_hosts_boot"), "w") as f:
                f.write(f"@cert-authority {self.host} {ca}\n")
            # What control asks the person to do: the key that may log in.
            key = os.path.join(self.dir, "bootkey")
            if not os.path.exists(key):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "tpm2-kira vmtest", "-f", key], check=True)
            pub = open(key + ".pub").read().strip()
            rc, out = self.run(f"umask 077; printf '%s\\n' {shlex.quote(pub)} > /etc/tpm2-kira/authorized_keys")
            self.check("control: the SSH server at boot with an SSH CA in the TPM", rc == 0, out)

            pick(r"Back to step 2")
            pick(r"Debug at boot")
            s.expect(r"Switch debug at boot on\? \[y/N\] ?$"); s.send("y\n")
            pick(r"^\s*Quit$")
            s.expect(r"Run (mkinitcpio -P|update-initramfs -u) now\? \[Y/n\] ?$", 120); s.send("y\n")
            out = s.wait_end(900)
            self.log.save("control-rebuild.log", out)
            self.check("control rebuilds the image, and the hook approves the new boot state",
                       "approved the boot state" in out or "approval completed successfully" in out, out[-800:])
        except Fail as e:
            self.check("control, answered line by line", False, str(e))
            raise
        finally:
            s.close()

    def image(self):
        self.log.head("the boot image")
        if self.distro == "debian":
            listing = "unmkinitramfs /boot/initrd.img-$(uname -r) x >/dev/null && cd x && { [ -d main ] && cd main; true; }"
        else:
            listing = ("uki=$(sed -n 's/^default_uki=\"\\(.*\\)\"/\\1/p' /etc/mkinitcpio.d/*.preset | head -1); "
                       "objcopy -O binary --only-section=.initrd \"$uki\" initrd && lsinitcpio -x initrd >/dev/null")
        rc, out = self.run(f"set -e; d=$(mktemp -d); cd $d; {listing}; ls usr/bin | grep kira; "
                           "find etc/tpm2-kira -maxdepth 2 | sort; ls etc/tpm2-kira/control.conf 2>&1 || true; "
                           "grep -rlE 'tpm2-kira-boot gate|tpm2-kira-attest' etc usr/lib/systemd scripts 2>/dev/null | sed 's/^/STARTS-GATE /'; "
                           "cd /; rm -rf $d", save="image.log")
        bins = [l for l in out.split("\n") if l.strip().startswith("tpm2-kira")]
        self.check("the image carries tpm2-kira-boot", "tpm2-kira-boot" in bins, out[-500:])
        self.check("the image carries no tpm2-kira (the administration)", "tpm2-kira" not in bins, str(bins))
        self.check("the image carries no control.conf", "No such file" in out or "cannot access" in out, out[-300:])
        self.check("no unit or script of the image starts a gate: run starts its children itself", "STARTS-GATE" not in out, out[-300:])
        for part in ("unlock", "codes", "net", "ssh", "tpm"):
            self.check(f"the image's plan names '{part}'", f"etc/tpm2-kira/plan/{part}" in out, out[-500:])

    def cycle(self, n):
        self.log.head(f"reboot {n}: the code screen over SSH, unlocked there")
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        if not self.check(f"boot {n}: the boot SSH server answers (port {SSH_PORT})", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server: the console shows why")
        s = self.boot_session(n)
        try:
            text, _ = s.expect(r"Does the code match your authenticator\?.*$", 60)
            at = time.time()
            codes = dict(re.findall(r"^#(\d+): (\d{6})$", text, re.M))
            self.check(f"boot {n}: the host key is certified by the SSH CA (strict known_hosts)", True)
            for slot in (0, 1):
                self.check(f"boot {n}: slot {slot}'s code is the authenticator's", str(slot) in codes and code_matches(self.secrets[slot], codes[str(slot)], at), text[-500:])
            self.check(f"boot {n}: the screen names tpm2-kira's password and salt prompt", "continue to the password and salt prompt" in text, text[-300:])
            s.send("\r")
            s.expect(r"Password for disk \S+: ?$", 120); s.send(TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(TEST_SALT + "\r")
            # The session ends when the system leaves the initrd, after the
            # server's last line (the checks after the boot say whether the
            # key was answered).
            rest = s.wait_end(600)
            self.check(f"boot {n}: the session ends with the server's last line ('The machine boots; ...')",
                       "The machine boots; the SSH server stops." in rest, rest[-300:])
        except Fail as e:
            self.check(f"boot {n}: the code screen over SSH", False, str(e))
            raise
        finally:
            s.close()
        if not self.check(f"boot {n}: the system comes up (ssh)", self.wait_port(22, True, 300)):
            raise Fail("the system does not come up")
        time.sleep(5)
        rc, out = self.run("tpm2-kira status --json", save=f"status-boot{n}.json")
        try:
            slots = json.loads(out).get("slots", [])
        except ValueError:
            slots = []
        self.check(f"boot {n}: the cap ran (every slot read-locked)", slots and all("read-locked" in s["generation_state"] for s in slots), out[-300:])
        log = ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
               "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service -u tpm2-kira-cap.service")
        rc, out = self.run(log + " 2>&1", save=f"boot{n}-tpm2-kira.log")
        self.check(f"boot {n}: the key was answered", re.search(r"unlock: answered for", out) is not None, out[-500:])
        confined = re.search(r"ssh-child \(pid \d+\) runs with uid 65534, .*no new privileges, no executable memory, Landlock ABI \d+: no file access, \d+ system calls refused", out)
        self.check(f"boot {n}: ssh-child ran confined (nobody, no new privileges, no executable memory, Landlock, seccomp)", confined is not None, out[-500:])
        bad = [l for l in out.split("\n") if re.search(r"ERROR|FAILED|does not answer|cannot", l)]
        self.check(f"boot {n}: no tpm2-kira error in the boot's log", not bad, "\n".join(bad[:5]))

    def rebuild(self):
        cmd = "update-initramfs -u" if self.distro == "debian" else "mkinitcpio -P"
        rc, out = self.run(cmd + " 2>&1", save="rebuild.log")
        return out

    def vault(self, vault):
        self.log.head("remote attestation over TLS: the vault")
        out = vault.admin("token", "create", "--name", self.name)
        self.log.save("vault-token.log", out)
        m = re.search(r"--url (\S+) --pin (\S+) --token (\S+)", out)
        if not self.check("the vault makes an enrolment token", m is not None, out[-400:]):
            raise Fail("no token")
        url, pin, token = m.groups()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --mode tpm+vault --url {url} --pin {pin} --token {token} --name {self.name}", "luks-enrol-vault")
        try:
            s.expect(r"to authorise: ?$", 300); s.send(self.luks_pass + "\n")
            s.expect(r"keyslot (\d+) added: tpm2-kira, tpm\+vault", 300)
            s.wait_end(120)
            self.check("luks enrol --mode tpm+vault: the vault knows the device, a keyslot is added", True)
        except Fail as e:
            self.check("luks enrol --mode tpm+vault", False, str(e))
            raise
        finally:
            s.close()
        out = vault.admin("devices")
        self.check("the vault lists the device", self.name in out, out[-400:])
        out = self.rebuild()
        self.check("the image is rebuilt with the vault in its plan", re.search(r"Vault:\s+in", out) is not None, out[-800:])

        # A boot nobody touches: the vault releases its part to the TPM's
        # quote of the approved boot state, the key ends the hold by itself.
        self.log.head("a boot unlocked by the vault alone")
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        up = self.wait_port(22, True, 420)
        if not self.check("the vault's boot: the system comes up with nobody at the console or in SSH", up):
            raise Fail("the vault's boot did not come up")
        time.sleep(5)
        log = ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
               "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service")
        rc, out = self.run(log + " 2>&1", save="boot-vault-tpm2-kira.log")
        self.check("the vault released the remote part; the key was made", "released; the key is made" in out, out[-600:])
        self.check("the key was answered", "unlock: answered for" in out, out[-600:])
        out = vault.admin("devices")
        self.log.save("vault-devices.log", out)

        # Revoked: no release; the typed keyslot is the fallback, over SSH.
        self.log.head("a boot with the device revoked on the vault")
        vault.admin("device", "revoke", self.name)
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        if not self.check("revoked: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server")
        s = self.boot_session("revoked")
        try:
            text, _ = s.expect(r"Does the code match your authenticator\?.*$", 120)
            self.check("revoked: the screen names the fallback", "the password and salt prompt if the vault gives no key" in text, text[-400:])
            s.send("\r")
            text, _ = s.expect(r"Password for disk \S+: ?$", 300)
            self.check("revoked: tpm2-kira says the vault gave no key and asks the typed keyslot", "no key from the vault" in text and "revoked" in text, text[-500:])
            s.send(TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(TEST_SALT + "\r")
            s.wait_end(600)
        except Fail as e:
            self.check("revoked: the fallback over SSH", False, str(e))
            raise
        finally:
            s.close()
        up = self.wait_port(22, True, 300)
        self.check("revoked: the disk unlocks with the password and the salt", up)
        time.sleep(5)
        rc, out = self.run(log + " 2>&1", save="boot-revoked-tpm2-kira.log")
        self.check("revoked: the vault refused, the key was answered from the typed keyslot", "the device is revoked" in out and "unlock: answered for" in out, out[-600:])
        vault.admin("device", "unrevoke", self.name)

    def slot_life(self):
        self.log.head("a slot's life")
        rc, out = self.run("tpm2-kira slot approve --nvram 1 2>&1", save="slot-approve.log")
        self.check("slot approve raises the generation", "Successfully approved the boot state" in out, out[-400:])
        rc, out = self.run("tpm2-kira slot add --nvram 2 --pcrs 0,7 2>&1 | grep -v '^Secret'", save="slot-add-2.log")
        rc, info = self.run("tpm2-kira slot info --nvram 2 2>&1")
        self.check("slot add --nvram 2", "0x01803012" in info, info[-300:])
        rc, out = self.run("tpm2-kira slot delete --nvram 2 2>&1", save="slot-delete.log")
        self.check("slot delete --nvram 2", "Successfully deleted" in out, out[-400:])
        rc, out = self.run("tpm2-kira slot list 2>&1", save="slot-list-after-delete.log")
        self.check("slot 2 is gone whole (its blob and its generation index)", "0x01803012" not in out and "0x01803812" not in out, out[-500:])

    def removal(self):
        """What tpm2-kira keeps outside the disk goes when asked, and only
        then: control asks before it removes the SSH CA when SSH is switched
        off (No keeps it); slot delete without --nvram takes everything -
        the slots, the boot settings, the SSH CA's EFI variable and its
        public key."""
        self.log.head("removing what tpm2-kira keeps in the TPM and the EFI variables")
        ca_var = "/sys/firmware/efi/efivars/KIRAasshCA-24415b90-39be-45c0-a9a3-d547ebe28ea0"
        there = lambda path: "yes" in self.run(f"test -e {path} && echo yes")[1]
        s = self.session("sudo ACCESSIBLE=1 tpm2-kira control", "control-ssh-off")
        menu = r"Enter a number between 1 and \d+: ?$"

        def pick(rx, timeout=120):
            for _ in range(4):
                text, _ = s.expect(menu, timeout)
                opts = menu_options(text)
                o = next((o for o in opts if re.search(rx, o[1])), None)
                if o:
                    s.send(o[0] + "\n")
                    return text
                nxt = next((o for o in opts if "Continue to step 2" in o[1]), None)
                if not nxt:
                    raise Fail(f"no option /{rx}/ in:\n" + text[-1200:])
                s.send(nxt[0] + "\n")
            raise Fail(f"no option /{rx}/")

        try:
            pick(r"Network and SSH at boot")
            pick(r"SSH server at boot")
            s.expect(r"Start the SSH server with the code screen\? \[(y/N|Y/n)\] ?$"); s.send("n\n")
            s.expect(r"Remove the SSH CA too\? \[y/N\] ?$", 60); s.send("n\n")
            self.check("control asks before it removes the SSH CA when SSH is switched off", True)
            pick(r"Back to step 2")
            pick(r"^\s*Quit$")
            # A part switched off is no reason of its own to rebuild (the
            # next build leaves it out): control may end without asking.
            text, m = s.expect(r"(Run (mkinitcpio -P|update-initramfs -u) now\? \[Y/n\] ?$|Connection to \S+ closed)", 120)
            if m.group(1).startswith("Run"):
                s.send("y\n")
                text = s.wait_end(900)
            self.log.save("control-ssh-off-end.log", text)
        except Fail as e:
            self.check("control: SSH off, the SSH CA kept on No", False, str(e))
            raise
        finally:
            s.close()
        self.removal_all()

    CA_VAR = "/sys/firmware/efi/efivars/KIRAasshCA-24415b90-39be-45c0-a9a3-d547ebe28ea0"

    def removal_all(self):
        """The SSH CA kept, then slot delete --yes: everything goes."""
        ca_var = self.CA_VAR
        there = lambda path: "yes" in self.run(f"test -e {path} && echo yes")[1]
        self.check("No keeps the SSH CA: its EFI variable and ssh_ca.pub", there(ca_var) and there("/etc/tpm2-kira/ssh_ca.pub"))
        rc, out = self.run("tpm2-kira slot delete --yes 2>&1", save="slot-delete-all.log")
        self.check("slot delete without --nvram names the SSH CA and deletes everything",
                   "Found the SSH CA efi:KIRAasshCA" in out and "item(s) deleted successfully" in out, out[-800:])
        rc, out = self.run("tpm2-kira slot list 2>&1", save="slot-list-after-delete-all.log")
        left = re.findall(r"0x01803[0-9A-Fa-f]{3}", out)
        self.check("no index of tpm2-kira's is left in the TPM (slots, generations, counters, boot settings)", not left, ", ".join(sorted(set(left))))
        self.check("the SSH CA's EFI variable is gone", not there(ca_var))
        self.check("its public key /etc/tpm2-kira/ssh_ca.pub is gone", not there("/etc/tpm2-kira/ssh_ca.pub"))
        rc, out = self.run("tpm2-kira slot delete --yes 2>&1")
        self.check("slot delete again: nothing of tpm2-kira is found", "nothing of tpm2-kira found" in out, out[-300:])

    def all(self, package, vault=None, reset=None):
        try:
            if reset:
                self.reset(reset)
            self.preflight()
            self.install(package)
            self.seal()
            self.inspect()
            self.enrol()
            self.control()
            self.image()
            for n in range(1, self.cycles + 1):
                self.cycle(n)
            if vault:
                self.vault(vault)
            self.slot_life()
            self.removal()
        except Fail as e:
            self.rep.issues.append("stopped: " + str(e).split("\n")[0])
        except Exception as e:  # a defect of the test, reported as such
            self.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        return self.report()

    def report(self):
        lines = [f"tpm2-kira vmtest: {self.name} ({self.distro}) on {self.host}", datetime.datetime.now().isoformat(timespec="seconds"), ""]
        for name, status, detail in self.rep.checks:
            lines.append(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
        lines += ["", "Issues:" if self.rep.issues else "No issues."] + ["  - " + i for i in self.rep.issues]
        failed = self.rep.failed() or any(i.startswith(("stopped", "the test failed")) for i in self.rep.issues)
        lines += ["", "RESULT: FAIL" if failed else "RESULT: PASS", f"logs: {self.dir}"]
        text = "\n".join(lines) + "\n"
        self.log.save("report.txt", text)
        return not failed, text


def head_packages(directory):
    """The packages of HEAD in directory: the Arch package names the commit
    as .g<short>-, the Debian one as +<n>.g<short>_."""
    short = subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    pick = lambda pattern: (sorted(glob.glob(os.path.join(directory, pattern)), key=os.path.getmtime) or [None])[-1]
    return short, {"debian": pick(f"tpm2-kira_*.g{short}_amd64.deb"),
                   "arch": pick(f"tpm2-kira-*.g{short}-*-x86_64.pkg.tar.zst")}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["arch", "debian", "both"], required=True)
    p.add_argument("--config", default=os.path.join(REPO, "tools", "vmtest.conf"))
    p.add_argument("--packages", default=os.path.join(REPO, "build", "packages"), help="where the built .deb and .pkg.tar.zst are")
    p.add_argument("--password-file", help="the VMs' user password (default: the config's password_file, or $VMTEST_PASSWORD)")
    p.add_argument("--cycles", type=int, default=2, help="reboots, each unlocked over the boot SSH server (default 2)")
    p.add_argument("--run-dir", help="default: ./vmtest-<time>")
    p.add_argument("--no-vault", action="store_true", help="leave out remote attestation over TLS (the vault)")
    p.add_argument("--no-build", action="store_true", help="take HEAD's packages already in --packages instead of building them")
    p.add_argument("--no-reset", action="store_true", help="do not run the machines' reset commands: they must be fresh already")
    args = p.parse_args()

    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        print(f"no {args.config}: copy tools/vmtest.conf.example and fill it in", file=sys.stderr)
        return 2
    pwfile = args.password_file or cfg.get("defaults", "password_file", fallback=None)
    password = os.environ.get("VMTEST_PASSWORD") or (open(os.path.expanduser(pwfile)).read().strip() if pwfile else None)
    if not password:
        print("the VMs' password: --password-file, password_file in the config, or VMTEST_PASSWORD", file=sys.stderr)
        return 2
    run_dir = args.run_dir or os.path.join(os.getcwd(), "vmtest-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    names = ["arch", "debian"] if args.target == "both" else [args.target]
    if subprocess.run(["git", "-C", REPO, "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True).stdout.strip():
        print("note: uncommitted changes are not tested: the packages are HEAD's", file=sys.stderr)
    if not args.no_build:
        os.makedirs(run_dir, exist_ok=True)
        targets = ["arch" if n == "arch" else "deb" for n in names]
        print(f"building the packages of HEAD ({' '.join(targets)}), log: {run_dir}/build-packages.log", flush=True)
        with open(os.path.join(run_dir, "build-packages.log"), "w") as log:
            if subprocess.run([os.path.join(REPO, "packaging", "build-packages.sh")] + targets, cwd=REPO, stdout=log, stderr=subprocess.STDOUT).returncode != 0:
                print(f"the packages do not build: {run_dir}/build-packages.log", file=sys.stderr)
                return 1
    short, packages = head_packages(args.packages)
    machines, resets = [], {}
    for name in names:
        if not packages[name]:
            print(f"no {name} package of HEAD ({short}) in {args.packages} (leave out --no-build)", file=sys.stderr)
            return 2
        sec = cfg[name]
        luks = sec.get("luks_passphrase") or os.environ.get("VMTEST_LUKS_PASSPHRASE") or password
        machines.append(Machine(name, name, sec["host"], sec.get("user", "pix"), password, luks, run_dir, args.cycles))
        if not args.no_reset and sec.get("reset"):
            resets[name] = sec["reset"]
    vault = None
    if not args.no_vault:
        vc = cfg["vault"] if cfg.has_section("vault") else {}
        vault = Vault(os.path.abspath(os.path.join(REPO, vc.get("src", "../tpm2-kira-vault"))),
                      vc.get("url", "https://172.17.2.174"), int(vc.get("port", "443")), run_dir)
        try:
            vault.start()
        except Fail as e:
            print("the vault does not start:", e, file=sys.stderr)
            return 1
    results = {}
    print(f"tpm2-kira {short}: " + ", ".join(f"{m.name} {os.path.basename(packages[m.name])}" + (" (reset)" if m.name in resets else "") for m in machines), flush=True)
    threads = [threading.Thread(target=lambda m=m: results.__setitem__(m.name, m.all(packages[m.name], vault, resets.get(m.name)))) for m in machines]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    if vault:
        vault.stop()
    ok = True
    for m in machines:
        passed, text = results[m.name]
        print(text)
        ok = ok and passed
    print("ALL PASS" if ok else "FAILED", "- logs:", run_dir)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
