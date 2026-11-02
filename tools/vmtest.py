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
  4. luks enrol --salt typed, the recovery recipe 0x1100 (a password, a
     salt, the passphrase)
  5. control, as a person would answer it (ACCESSIBLE=1, line by line):
     the boot chain's adoptions, the boot image's network (DHCP), the SSH
     server at boot with its SSH CA, debug at boot, the image rebuilt; the
     key that may log in at boot is a test key made here
  6. the image: tpm2-kira-boot and its plan, no tpm2-kira, no control.conf
  7. --cycles reboots: the boot SSH server, its host key checked against
     the SSH CA (StrictHostKeyChecking), the codes of both slots against the
     computed ones, Enter, the password and the salt typed in the session;
     after each boot: the key was answered, no tpm2-kira error; the boot is
     closed (PCR 15 extended, run's close in the log, Arch's close unit
     ran), every slot closed and slot 0's TOTP key refusing; no cap unit;
     one PCR rule: the slots and the SSH CA's are PCR 7 and the image, slot 0
     with 0, 2 and 4 (Debian's GRUB: a PCR 0,7 slot refused; Arch: PCR 11
     signed by the PCR key), and PCR 4 as approved before this boot is PCR 4
     as this boot measured it
  7a. Arch: an image the hook did not approve, signed by the PCR key: slot 1's
     code and the SSH CA through slot 1, slot 0 out; slot approve brings it back
  7b. the salt in this TPM (0x1200): luks enrol --salt tpm, luks status and
     luksDump name the recipe, the plan takes the part; a boot asks the
     password alone over SSH (the TPM opened the salt during the hold);
     luks remove takes the keyslot again
 8. remote attestation over TLS, the vault (verified against its own root,
    from 'tpm2-kira-vault tls root', then its pin): an enrolment without a
    root refused; the root brought to the machine, luks enrol --ca puts it
    into /etc/tpm2-kira/vault-ca.pem; tpm2-kira-vault runs here, in
     a container with a software TPM of its own (tools/vmtest-vault/),
     published on the [vault] port; luks enrol --password tpm --salt vault with a
     token it made; the image rebuilt with the vault; a boot that nobody
     touches, unlocked by the vault's release to the TPM's quote; a boot
     with the device revoked on the vault, where the recovery recipe's keyslot
     is the fallback, typed over SSH; the keyslot enrolled again with
     --pepper, and a boot that waits for an operator: approved first with a
     wrong pepper (refused by the machine's pepper check, a new approval
     asked) - on the vault's CLI (request approve, the pepper on stdin) -,
     then with the right one, over the operator interface (curl, the
     vault's key pinned) - the pepper travels wrapped for the TPM; then
     the vault's salt with a typed password and a pepper (0x1401): an
     operator answers the queue on the vault's CLI (requests answer)
     while the code screen holds, and the password alone is asked
  9. a slot's life: approve, add slot 2, delete it whole
 10. removal: control switches SSH off and asks before it removes the SSH
     CA (No keeps it); slot delete --yes takes everything of tpm2-kira -
     no index of its range left in the TPM, no KIRAasshCA variable, no
     ssh_ca.pub

Iterating (a run from the reset is what a final proof is): on the machines of
tools/localvm.py, --save-setup makes steps 1-6 once, keeps the state after them
in the snapshot "setup" and ends; --from-setup starts from it, at the first
reboot, and its report says it is no final proof. hibernatetest.py's setup
takes the same snapshot. A change to the product wants a new --save-setup;
--drop-setup removes it. "fresh" and "export" are never written.

--fast-kdf runs on a TEST package: Argon2id at a test's cost, by a Go build tag
(packaging/build-packages.sh --fast-kdf, build/packages-fastkdf). The whole
typed-recipe path runs, the real cost does not: such a run is NO FINAL PROOF, and
its report's first line says so. A final proof runs without it.

Nothing but Python's standard library and ssh are needed here. Reports and
every session's transcript land in the run's directory.
"""

import argparse
import urllib.parse
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
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("acceptance", os.path.join(REPO, "tools", "acceptance.py"))
acceptance = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acceptance)

ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\r")

# The answers the test gives where a person would type: the disk's
# recovery recipe's keyslot it enrols, and the boot SSH server's settings.
TEST_PASSWORD = "kira-vmtest-pw"
TEST_SALT = "kira-vmtest-salt"
TPM_SALT_PASSWORD = "kira-vmtest-tpm-salt-pw"
VAULT_PASSWORD = "kira-vmtest-vault-pw"
SSH_PORT = 2222
SSH_HOLD = 600
# The state after the steps up to the first reboot: the same in this test and
# the hibernate test, which keeps its own after that (hib-setup).
SETUP_SNAPSHOT = "setup"
FROM_SETUP_NOTE = "NOT A FINAL PROOF: started from a saved setup, not from the snapshot fresh."
FAST_KDF_NOTE = "NOT A FINAL PROOF: a --fast-kdf TEST build, Argon2id at a test's cost, not the production's."


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


class Timing:
    """The seconds of every step of a run, and of the laps inside one: what a
    run spends its time on, in its output and its report."""

    def __init__(self, label, say):
        self.label, self.say = label, say
        self.steps = []  # [name, seconds, [(lap, seconds)]]
        self.start = None
        self.first = time.monotonic()

    def _close(self, now):
        if self.start is None:
            return
        self.steps[-1][1] = now - self.start
        self.say(f"[{self.label}] {self.steps[-1][1]:.1f} s: {self.steps[-1][0]}")
        self.start = None

    def step(self, name):
        now = time.monotonic()
        self._close(now)
        self.steps.append([name, 0.0, []])
        self.start = self.last = now

    def lap(self, name):
        """The time since the step's start or its last lap, under name."""
        if self.start is None:
            return
        now = time.monotonic()
        self.steps[-1][2].append((name, now - self.last))
        self.last = now

    def finish(self):
        self._close(time.monotonic())

    def total(self):
        return sum(s[1] for s in self.steps)

    def slowest(self, n):
        return sorted(((s[1], s[0]) for s in self.steps), reverse=True)[:n]

    def lines(self, slowest=8):
        out = ["Times (seconds):"]
        for name, secs, laps in self.steps:
            out.append(f"  {secs:7.1f}  {name}")
            out += [f"  {l:7.1f}      - {lap}" for lap, l in laps]
        out.append(f"  {self.total():7.1f}  in all")
        out += ["", f"The slowest {slowest}:"] + [f"  {secs:7.1f}  {name}" for secs, name in self.slowest(slowest)]
        return out

    def as_json(self):
        return json.dumps({"total": self.total(), "steps": [{"name": n, "seconds": round(s, 1), "laps": [[l, round(t, 1)] for l, t in laps]}
                                                             for n, s, laps in self.steps]}, indent=1)


def print_slowest(timings, n=10):
    """The slowest steps of a whole run, over its machines, at its end."""
    rows = sorted(((secs, t.label, name) for t in timings for secs, name in t.slowest(n)), reverse=True)[:n]
    print(f"The slowest {len(rows)} steps of the run (seconds):")
    for secs, label, name in rows:
        print(f"  {secs:7.1f}  [{label}] {name}")
    for t in timings:
        print(f"  {t.total():7.1f}  [{t.label}] in all")


def load_localvm():
    spec = importlib.util.spec_from_file_location("localvm", os.path.join(REPO, "tools", "localvm.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def local_machines(config, names):
    """The machines of tools/localvm.py: what snapshots need. The module and a
    machine per name."""
    localvm = load_localvm()
    cfg = configparser.ConfigParser()
    if not cfg.read(config):
        raise Fail(f"no {config}: a saved setup needs the machines of tools/localvm.py")
    defaults = dict(cfg["defaults"]) if cfg.has_section("defaults") else {}
    return localvm, {n: localvm.Machine(n, cfg[n], defaults) for n in names}


def package_binaries(package, directory):
    """Takes the two binaries out of a package; their paths."""
    if package.endswith(".deb"):
        member = next(m for m in subprocess.run(["ar", "t", package], capture_output=True, text=True, check=True).stdout.split() if m.startswith("data.tar"))
        subprocess.run(["ar", "x", os.path.abspath(package), member], cwd=directory, check=True)
        archive = os.path.join(directory, member)
    else:
        archive = package
    subprocess.run(["tar", "-xf", archive, "-C", directory, "--wildcards", "*usr/bin/tpm2-kira", "*usr/bin/tpm2-kira-boot"], check=True)
    return [os.path.join(directory, "usr", "bin", b) for b in ("tpm2-kira", "tpm2-kira-boot")]


def package_is(package, fast_kdf):
    """Whether a package's binaries are what the run asks for: a release's
    (packaging/release-binary-check.sh: no build tag, no trace of the test
    build), or the test build's (the tag, in what Go recorded of the build).
    Why not, or None."""
    with tempfile.TemporaryDirectory() as d:
        for binary in package_binaries(package, d):
            if fast_kdf:
                info = subprocess.run(["go", "version", "-m", binary], capture_output=True, text=True).stdout
                if "-tags=kira_test_fast_kdf" not in info:
                    return f"{os.path.basename(binary)} is not a test build:\n{info[-400:]}"
            else:
                p = subprocess.run(["sh", os.path.join(REPO, "packaging", "release-binary-check.sh"), binary], capture_output=True, text=True)
                if p.returncode != 0:
                    return p.stderr.strip()
    return None


class SavedSetup:
    """A state of a machine kept to start from: the snapshot of the tag (disk,
    EFI variables, TPM) and what the test holds of it, in the machine's directory
    beside the snapshot, root's secrets of a test machine's test slots alone. It
    is good for the commit that made it and those that differ only in tools and
    documentation. A product built with another key derivation cost does not open
    its keyslots."""

    FILES = ("bootkey", "bootkey.pub", "known_hosts_boot")

    def __init__(self, lv, m, tag, fast_kdf=False):
        self.lv, self.m, self.tag, self.fast_kdf = lv, m, tag, fast_kdf

    def path(self):
        return self.lv.path(self.tag + ".json")

    def save(self):
        """Powers the guest off and keeps it; it stays off."""
        self.m.power_off()
        self.lv.snapshot(self.tag)
        commit = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        fd = os.open(self.path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"commit": commit, "fast_kdf": self.fast_kdf, "secrets": self.m.secrets, "luks_dev": getattr(self.m, "luks_dev", None),
                       "version": getattr(self.m, "version", None),
                       "files": {n: open(os.path.join(self.m.dir, n)).read() for n in self.FILES}}, f)

    def problem(self):
        """Why this setup cannot be started from; None if it can."""
        if not os.path.exists(self.path()) or not os.path.isdir(self.lv.path("snap-" + self.tag)):
            return f"{self.lv.name}: no snapshot {self.tag}: --save-setup"
        st = json.load(open(self.path()))
        if st.get("fast_kdf") != self.fast_kdf:
            return f"{self.lv.name}: the snapshot {self.tag} was made with fast_kdf={st.get('fast_kdf')}: its keyslots open with no other build"
        diff = subprocess.run(["git", "-C", REPO, "diff", "--name-only", st["commit"], "HEAD", "--", ".", ":!tools", ":!docs", ":!*.md"],
                              capture_output=True, text=True)
        if diff.returncode != 0 or diff.stdout.strip():
            return f"{self.lv.name}: the snapshot {self.tag} is of {st['commit'][:7]}, and the product changed since: --save-setup again"
        return None

    def restore(self):
        """Back to the snapshot, the machine stopped, what the test holds back."""
        why = self.problem()
        if why:
            raise Fail(why)
        self.lv.revert(self.tag)
        st = json.load(open(self.path()))
        self.m.secrets, self.m.luks_dev, self.m.version = st["secrets"], st["luks_dev"], st["version"]
        for n, body in st["files"].items():
            fd = os.open(os.path.join(self.m.dir, n), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(body)

    def drop(self):
        self.lv.kill()
        self.lv.drop_snapshot(self.tag)
        if os.path.exists(self.path()):
            os.remove(self.path())


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

    def __init__(self, src, url, port, op_port, run_dir):
        self.src, self.url, self.port, self.op_port = src, url, port, op_port
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
        # The operator interface only on this machine's loopback.
        self._sh(["docker", "run", "-d", "--name", self.NAME, "-p", f"{self.port}:8443", "-p", f"127.0.0.1:{self.op_port}:8444",
                  "-e", f"VAULT_URL={self.url}", self.NAME])
        deadline = time.time() + 60
        while time.time() < deadline:
            if "serving " in self._sh(["docker", "logs", self.NAME], check=False):
                break
            time.sleep(0.5)
        else:
            raise Fail("the vault does not serve:\n" + self._sh(["docker", "logs", self.NAME], check=False)[-800:])
        out = self.admin("operator", "add", "vmtest")
        tok = re.search(r"token \(shown this once\):\s+(\S+)", out)
        if not tok or "--cacert" not in out:
            raise Fail("operator add: " + out[-400:])
        self.op_token = tok.group(1)
        # The vault's root: what machines and operators verify it against.
        self.root = self.admin("tls", "root")
        if not self.root.startswith("-----BEGIN CERTIFICATE-----"):
            raise Fail("tls root: " + self.root[-400:])
        self.root_file = os.path.join(self.dir, "vault-ca.pem")
        with open(self.root_file, "w") as f:
            f.write(self.root)

    def approve(self, request_id, pepper):
        """Approves a request with a pepper over the operator interface,
        as an operator does: curl, verifying the vault against its root.
        The leaf is for the vault's address; the operator port is on this
        machine's loopback, so curl is pointed there for that address."""
        host = urllib.parse.urlparse(self.url).hostname
        p = subprocess.run(["curl", "-sS", "--cacert", self.root_file, "--connect-to", f"{host}:{self.op_port}:127.0.0.1:{self.op_port}",
                            "-H", "Authorization: Bearer " + self.op_token,
                            "-H", "Content-Type: application/json", "-X", "POST", "--data-binary", json.dumps({"pepper": pepper}),
                            "-w", "\n%{http_code}", f"https://{host}:{self.op_port}/v1/requests/{request_id}/approve"],
                           capture_output=True, text=True)
        body, _, code = p.stdout.rpartition("\n")
        return code.strip(), body + p.stderr

    def pending(self, name, timeout):
        """The ID of the device's request waiting for an operator."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            m = re.search(r"^(\S+)\s+\S+\s+" + re.escape(name) + r"\s+pending\s", self.admin("requests"), re.M)
            if m:
                return m.group(1)
            time.sleep(1)
        return None

    def admin(self, *args):
        with self.lock:
            return self._sh(["docker", "exec", self.NAME, "tpm2-kira-vault"] + list(args))

    def admin_input(self, text, *args):
        """An admin command answered on its stdin, as an operator at the
        vault's terminal answers it (a pipe: one line per answer)."""
        with self.lock:
            p = subprocess.run(["docker", "exec", "-i", self.NAME, "tpm2-kira-vault"] + list(args),
                               input=text, capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr

    def stop(self):
        with open(os.path.join(self.dir, "vault.log"), "w") as f:
            f.write(self._sh(["docker", "logs", self.NAME], check=False))
            f.write("\n--- audit\n" + self._sh(["docker", "exec", self.NAME, "tpm2-kira-vault", "audit"], check=False))
        self._sh(["docker", "rm", "-f", self.NAME], check=False)


class Machine:
    def __init__(self, name, distro, host, user, password, luks_pass, run_dir, cycles, ssh_port=22, boot_port=SSH_PORT):
        self.name, self.distro, self.host, self.user = name, distro, host, user
        # The ports this side connects to: the machine's own 22 and SSH_PORT,
        # or what a port forward makes of them (tools/localvm.py).
        self.ssh_port, self.boot_port = ssh_port, boot_port
        self.password, self.luks_pass, self.cycles = password, luks_pass, cycles
        self.dir = os.path.join(run_dir, name)
        os.makedirs(self.dir, exist_ok=True)
        self.log = acceptance.Log(self.dir)
        self.rep = acceptance.Report()
        self.t = acceptance.Target(host, user, ssh_port, password, None, self.log)
        self.secrets = []
        self.sessions = 0
        self.slots = [0, 1]  # the TOTP slots slot add makes: 0 and the fallback 1
        self.timing = Timing(name, self.log.say)
        self.notes = []  # the report's first lines: what kind of run this was
        self.fast_kdf = False

    # -- helpers ------------------------------------------------------------

    def head(self, text):
        """A step of the run begins: its heading, and its time from here."""
        self.timing.step(text)
        self.log.head(text)

    def lap(self, name):
        self.timing.lap(name)

    def power_off(self):
        """The guest powered off, the moment the command has returned; a
        machine of tools/localvm.py, whose qemu ends with it."""
        self.when_returned("systemctl poweroff")
        if not self.lv.wait_stopped(180):
            raise Fail("the guest did not power off")

    def run(self, cmd, root=True, save=None):
        rc, out = self.t.run(cmd, root=root)
        if save:
            self.log.save(save, out)
        return rc, out

    def check(self, name, ok, detail=""):
        return self.rep.check(name, ok, detail if not ok else "")

    def secure_boot_warning(self):
        """What a command must say of this machine's Secure Boot state, from its
        variables; None when it must say nothing (the fresh VMs are in Setup Mode)."""
        if not hasattr(self, "_secure_boot"):
            read = lambda name: self.run(f"od -An -tx1 /sys/firmware/efi/efivars/{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>&1 | awk '{{print $NF}}'")[1].strip()
            secure, setup = read("SecureBoot"), read("SetupMode")
            self._secure_boot = ("WARNING: Secure Boot is in Setup Mode" if setup == "01" else
                                 "WARNING: Secure Boot is off" if secure == "00" else
                                 None if secure == "01" and setup == "00" else "WARNING: Secure Boot's state could not be read")
        return self._secure_boot

    def check_secure_boot(self, where, out, least=1, most=1):
        """where says the state, plainly, between least and most times."""
        want = self.secure_boot_warning()
        n = out.count("WARNING: Secure Boot")
        if want is None:
            return self.check(f"{where}: says nothing of Secure Boot, which is on", n == 0, out[-400:])
        return self.check(f"{where}: says {want!r}, {least} time(s)" + ("" if most == least else f" to {most}"), least <= n <= most and (least == 0 or want in out), f"{n} time(s): " + out[-400:])

    def check_control_secure_boot(self, where, text, wants):
        """control judges Secure Boot's state on its own line, in red."""
        state = self.secure_boot_warning()
        if state is None:
            return
        flat = re.sub(r"\s+", " ", re.sub(r"\x1b\[[0-9;]*m", "", text))
        want = next(v for k, v in wants.items() if k in state)
        self.check(f"{where} judges Secure Boot's state: {want!r}", want in flat and "\x1b[0;31m" in text, flat[-800:])

    def session(self, remote_cmd, name):
        self.sessions += 1
        argv = ["ssh", "-tt", "-p", str(self.ssh_port), "-o", "StrictHostKeyChecking=accept-new", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                f"{self.user}@{self.host}", remote_cmd]
        return Session(argv, os.path.join(self.dir, f"session-{self.sessions:02d}-{name}.log"), self.password)

    def boot_session(self, n):
        argv = ["ssh", "-tt", "-p", str(self.boot_port), "-i", os.path.join(self.dir, "bootkey"),
                "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + os.path.join(self.dir, "known_hosts_boot"),
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", f"root@{self.host}"]
        return Session(argv, os.path.join(self.dir, f"boot-{n}.log"))

    def port_open(self, port):
        """Whether an SSH server answers on the machine's port (22 or
        SSH_PORT, as this side reaches it): its banner, not only a
        connection - a port forward accepts one while the machine is down."""
        import socket
        port = {22: self.ssh_port, SSH_PORT: self.boot_port}.get(port, port)
        try:
            with socket.create_connection((self.host, port), timeout=2) as c:
                # A port forward holds the connection while the guest gives no
                # answer: a banner comes at once, or the next try sees it.
                c.settimeout(2)
                return c.recv(8).startswith(b"SSH-")
        except OSError:
            return False

    def wait_port(self, port, up, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.port_open(port) == up:
                return True
            time.sleep(0.5)
        return False

    def wait_login(self, what, timeout=120):
        """A login works: the system is up as far as what the checks read
        (sshd comes after sysinit, and lets a user in once the boot allows it)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            rc, _ = self.run("true")
            if rc == 0:
                return
            time.sleep(1)
        raise Fail(f"{what}: ssh does not let in")

    def booted(self, what):
        """The system is up: logged into, and nothing of this boot, the initrd's
        Argon2id above all, was killed for memory."""
        self.wait_login(what)
        rc, out = self.run("dmesg | grep -E 'Out of memory|oom-kill' | head -3", save=f"oom-{what.replace(' ', '-')}.log")
        self.check(f"{what}: nothing was killed for memory", "Out of memory" not in out and "oom-kill" not in out, out[-400:])

    def swap_counts(self):
        """Pages this boot swapped in and out so far, and the swap there is."""
        rc, out = self.run("awk '/^pswp(in|out) /{print $1, $2}' /proc/vmstat; awk '/^SwapTotal/{print $1, $2}' /proc/meminfo", root=False)
        return dict(l.split(None, 1) for l in out.strip().splitlines() if l.strip())

    def check_no_swap(self, before, what):
        """Argon2id's 1 GiB must not reach swap: guest memory is sized so
        (tools/LOCALVM.md)."""
        after = self.swap_counts()
        self.log.say(f"swap around {what}: {before} -> {after}")
        self.check(f"{what} touched no swap (/proc/vmstat)", before.get("pswpout") == after.get("pswpout") and before.get("pswpin") == after.get("pswpin"), f"{before} -> {after}")

    def when_returned(self, command):
        """Runs a root command that takes the machine away, once this ssh command
        has returned: its shell gone, the background job goes on."""
        self.run(f"nohup sh -c 'while kill -0 $1 2>/dev/null; do sleep 0.1; done; {command}' _ $$ >/dev/null 2>&1 &")

    # -- the steps ------------------------------------------------------------

    def reset(self, command):
        """Puts the machine back into its defined state: the configured
        command (VMTEST_NAME and VMTEST_HOST in its environment), then the
        machine must go away and come back on ssh."""
        self.head("reset: " + command)
        env = dict(os.environ, VMTEST_NAME=self.name, VMTEST_HOST=self.host)
        r = subprocess.run(command, shell=True, env=env, capture_output=True, text=True, timeout=900)
        self.log.save("reset.log", r.stdout + r.stderr)
        if not self.check("the reset command succeeds", r.returncode == 0, (r.stdout + r.stderr)[-500:]):
            raise Fail("reset failed")

    def preflight(self):
        self.head("preflight")
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
        self.head("install " + os.path.basename(package))
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
        says = out.count("TEST BUILD")
        if self.fast_kdf:
            self.check("both binaries say they are a test build, as --fast-kdf asks", says == 2 and ".fastkdf" in self.version, out.strip())
        else:
            self.check("neither binary is a test build: the production cost", says == 0 and "fastkdf" not in self.version, out.strip())
        rc, out = self.run("tpm2-kira status 2>&1; echo rc=$?", root=False)
        self.check("root gate: 'status' as a user refuses", "root is needed" in out and "rc=1" in out, out.strip())
        rc, out = self.run("tpm2-kira help >/dev/null 2>&1; echo rc=$?", root=False)
        self.check("'help' answers as a user", "rc=0" in out)

    def seal(self):
        self.head("setup and slot add")
        rc, out = self.run("tpm2-kira setup --local 2>&1", save="setup.log")
        self.check("setup --local makes the signing key", "Setup Complete" in out, out[-400:])
        rc, out = self.run("tpm2-kira slot add --totp 2>&1", save="slot-add.log")
        self.check_secure_boot("slot add, two slots", out)
        self.secrets = re.findall(r"^Secret: ([A-Z2-7]+)", out, re.M)
        if not self.check("slot add seals slots %s, each with its secret" % " and ".join(map(str, self.slots)), len(self.secrets) == len(self.slots), out[-600:]):
            raise Fail("no slots")
        if self.distro == "arch":
            self.check("UKI: the fallback slot 1 is sealed to 7e,11u", "the fallback, sealed to PCRs 7e,11u alone" in out, out[-600:])
            self.check("UKI: slot 0 is sealed to 0e,2e,4u,7e,11u", "PCRs: 0e,2e,4u,7e,11u" in out, out[-600:])
        if self.distro == "debian":
            self.check("GRUB: the fallback slot 1 is sealed to 7e,8e,9e", "the fallback, sealed to PCRs 7e,8e,9e alone" in out, out[-600:])
            self.check("GRUB: slot 0 is sealed to 0e,2e,4u,7e,8e,9e", "PCRs: 0e,2e,4u,7e,8e,9e" in out, out[-600:])
            rc, refused = self.run("tpm2-kira slot add --totp --nvram 2 --pcrs 0,7 2>&1", save="slot-add-grub-07.log")
            self.check("GRUB: slot add refuses a slot without PCRs 8 and 9", "PCR 8 is not selected: on a GRUB boot" in refused, refused[-400:])
        rc, mid = self.run(f"test -e {self.MID_VAR} && echo sealed")
        self.check("slot 0 seals the machine-id in the EFI variable KIRAmachineID", "sealed" in mid and "Sealed the machine-id" in out, out[-400:])
        last = self.slots[-1]
        rc, out = self.run(f"tpm2-kira reveal-plain --nvram {last} 2>&1 | tail -1", save="reveal.log")
        at = time.time()
        m = re.search(r"\b(\d{6})\b", out)
        if m:
            self.check(f"slot {last}'s code is the authenticator's (computed from its secret)", code_matches(self.secrets[last], m.group(1), at), out.strip())
        else:
            # The running system is closed (PCR 15), or past the OS
            # separator, or the slot's image is predicted for the next boot
            # (an image rebuilt since this one): no code until then, by design.
            self.check(f"slot {last}: a code, or none until the next boot (closed, past the OS separator, or predicted)",
                       "Closed until the next boot" in out or "Locked until the next boot" in out or "PCR Mismatch" in out, out.strip())

    def inspect(self):
        self.head("the commands that read")
        cmds = {
            "status": ("tpm2-kira status 2>&1", r"slot 0 .*signed by this machine's key"),
            "slot info": (f"tpm2-kira slot info --nvram {self.slots[-1]} 2>&1", r"Signature: valid"),
            "slot list": ("tpm2-kira slot list 2>&1", r"slot #0"),
            "slot status": ("tpm2-kira slot status --nvram 0 2>&1", r"Slot 0 \(0x01803010\)\n  Record: EFI variable KIRAslot0-"),
            "phone ekcert": ("tpm2-kira phone ekcert 2>&1", r"EK certificate:"),
            "luks status": ("tpm2-kira luks status 2>&1", re.escape(self.luks_dev)),
            "initramfs plan": ("tpm2-kira initramfs plan 2>&1", r"in\s+TOTP codes"),
            "help slot": ("tpm2-kira help slot 2>&1", r"tpm2-kira slot add"),
            "help run (the boot binary's page)": ("tpm2-kira help run 2>&1", r"tpm2-kira-boot run"),
        }
        for name, (cmd, want) in cmds.items():
            rc, out = self.run(cmd, save="cmd-" + name.split(" (")[0].replace(" ", "-") + ".log")
            self.check(f"'{name}' answers", re.search(want, out) is not None, out[-400:])
        rc, out = self.run("tpm2-kira status 2>&1")
        self.check_secure_boot("status", out)
        rc, out = self.run("tpm2-kira status --json 2>&1")
        self.check("status --json carries Secure Boot's warning", (self.secure_boot_warning() or "secure_boot_warning") in out if self.secure_boot_warning() else "secure_boot_warning" not in out, out[-300:])

    def enrol(self):
        self.head(f"luks enrol {self.luks_dev} --salt typed")
        swap = self.swap_counts()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt typed", "luks-enrol")
        try:
            s.expect(r"^Password: ?$", 60); s.send(TEST_PASSWORD + "\n")
            s.expect(r"The same password again: ?$"); s.send(TEST_PASSWORD + "\n")
            s.expect(r"Salt \(asked for at boot the same way\): ?$"); s.send(TEST_SALT + "\n")
            t0 = time.time()
            s.expect(r"to authorise: ?$", 900); s.send(self.luks_pass + "\n")
            self.log.say(f"Argon2id took {time.time() - t0:.0f} s here")
            self.lap("the prompts and Argon2id")
            text, _ = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1100 ", 300)
            out = s.wait_end(120)
            self.check("luks enrol adds a keyslot of the recovery recipe (0x1100)", True)
            self.check_no_swap(swap, "the enrolment's Argon2id")
        except Fail as e:
            self.check("luks enrol adds a keyslot of the recovery recipe (0x1100)", False, str(e))
            raise
        finally:
            s.close()

    def control(self):
        self.head("control, answered line by line")
        s = self.session("sudo ACCESSIBLE=1 tpm2-kira control", "control")
        menu = r"Enter a number between 1 and \d+: ?$"
        try:
            # Step 1: every open adoption, written when asked; then on.
            first = True
            for _ in range(10):
                text, _ = s.expect(menu, 120)
                if first:
                    first = False
                    self.check_control_secure_boot("control step 1", text, {"Setup Mode": "Setup Mode (risk: nothing checks the boot chain", "off": "disabled (risk: nothing checks", "could": "state unknown,"})
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
                f.write(f"@cert-authority {self.host},[{self.host}]:{self.boot_port} {ca}\n")
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
        self.head("the boot image")
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

    def cycle(self, n, started=False):
        """A boot unlocked over SSH, with its checks; started: the machine was
        started from a saved setup, nothing to reboot."""
        self.head(f"reboot {n}: the code screen over SSH, unlocked there")
        lv = getattr(self, "lv", None)
        console_from = lv.mark if lv else None
        if not started:
            if lv:
                console_from = os.path.getsize(lv.path("serial.log"))
            self.run("systemctl reboot")
            self.wait_port(22, False, 120)
            self.lap("the system going down")
        if not self.check(f"boot {n}: the boot SSH server answers (port {SSH_PORT})", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server: the console shows why")
        self.lap("firmware to the boot SSH server")
        s = self.boot_session(n)
        try:
            text, _ = s.expect(r"Does the code match your authenticator\?.*$", 60)
            at = time.time()
            self.lap("the code screen over SSH")
            codes = dict(re.findall(r"^#(\d+): (\d{6})$", text, re.M))
            self.check(f"boot {n}: the host key is certified by the SSH CA (strict known_hosts)", True)
            for slot in self.slots:
                self.check(f"boot {n}: slot {slot}'s code is the authenticator's", str(slot) in codes and code_matches(self.secrets[slot], codes[str(slot)], at), text[-500:])
            self.check(f"boot {n}: the screen names tpm2-kira's password and salt prompt", "continue to the password and salt prompt" in text, text[-300:])
            self.check_secure_boot(f"boot {n}: the SSH session, at its start", text)
            if lv:
                self.check_secure_boot(f"boot {n}: the console", lv.serial_text(console_from))
            s.send("\r")
            s.expect(r"Password for disk \S+: ?$", 120); s.send(TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(TEST_SALT + "\r")
            self.lap("the prompts")
            # The session ends when the system leaves the initrd, after the
            # server's last line (the checks after the boot say whether the
            # key was answered).
            rest = s.wait_end(600)
            self.lap("salt typed to the initrd's end (Argon2id, the keyslot)")
            self.check(f"boot {n}: the session ends with the server's last line ('The machine boots; ...')",
                       "The machine boots; the SSH server stops." in rest, rest[-300:])
        except Fail as e:
            self.check(f"boot {n}: the code screen over SSH", False, str(e))
            raise
        finally:
            s.close()
        if not self.check(f"boot {n}: the system comes up (ssh)", self.wait_port(22, True, 300)):
            raise Fail("the system does not come up")
        self.lap("the initrd's end to ssh")
        self.booted(f"boot {n}")
        rc, out = self.run("tpm2-kira status --json", save=f"status-boot{n}.json")
        try:
            slots = json.loads(out).get("slots", [])
        except ValueError:
            slots = []
        self.check(f"boot {n}: every slot is closed until the next boot (PCR 15)", slots and all("closed until the next boot" in s["generation_state"] for s in slots), out[-300:])
        if self.distro == "debian":
            self.check(f"boot {n}: GRUB - every slot includes PCRs 8 and 9", slots and not any(s.get("no_grub_pcrs") for s in slots), out[-300:])
        # A slot object refuses in the running system: the TPM computes no
        # code, by the slot's own policy (PCR 15).
        rc, out = self.run("tpm2-kira reveal-plain --nvram 0 2>&1 | tail -2", save=f"boot{n}-reveal.log")
        self.check(f"boot {n}: slot 0's TOTP key refuses after the boot (closed)", "Closed until the next boot" in out and not re.search(r"^\d{6}$", out, re.M), out.strip())
        log = ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
               "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service -u tpm2-kira-machine-id.service")
        rc, out = self.run(log + " 2>&1", save=f"boot{n}-tpm2-kira.log")
        self.check(f"boot {n}: run closed the boot when the code screen was over", "the boot is closed (PCR 15)" in out, out[-500:])
        self.check_secure_boot(f"boot {n}: the boot's log", out)
        self.check(f"boot {n}: the key was answered", re.search(r"unlock: answered for", out) is not None, out[-500:])
        self.check(f"boot {n}: the machine-id was released before the network (slot 0's policy held)",
                   "the machine-id is released" in out, out[-500:])
        # aSSH gives the unprivileged half a uid of its own from its range
        # (sandbox.DefaultUIDs, 0x7FFE0000-0x7FFEFFFF); nobody would mean
        # none was free, which a boot with one ssh-child never is.
        confined = re.search(r"ssh-child \(pid \d+\) runs with uid (\d+), namespaces of its own, no new privileges, not dumpable, no executable memory, Landlock ABI \d+: no file access, \d+ system calls refused", out)
        own_uid = confined is not None and 0x7FFE0000 <= int(confined.group(1)) <= 0x7FFEFFFF
        self.check(f"boot {n}: ssh-child ran confined (a uid of its own, namespaces, no new privileges, not dumpable, no executable memory, Landlock, seccomp)", own_uid, out[-500:])
        bad = [l for l in out.split("\n") if re.search(r"ERROR|FAILED|does not answer|cannot", l)]
        self.check(f"boot {n}: no tpm2-kira error in the boot's log", not bad, "\n".join(bad[:5]))
        # The boot is closed in the running system: PCR 15 extended (the
        # kernel's sysfs view of the TPM's PCRs), by run and the image's
        # close when the code screen was over (Arch: tpm2-kira-close.service).
        rc, out = self.run("cat /sys/class/tpm/tpm0/pcr-sha256/15 2>&1; "
                           + ("true" if self.distro == "debian" else
                              "journalctl -b -o cat --no-pager -u tpm2-kira-close.service 2>&1 | tail -5"),
                           save=f"boot{n}-close.log")
        pcr15 = out.split("\n")[0].strip()
        self.check(f"boot {n}: the boot is closed in the running system (PCR 15 extended)",
                   re.fullmatch(r"[0-9A-Fa-f]{64}", pcr15) is not None and set(pcr15) != {"0"}, out[-300:])
        if self.distro != "debian":
            self.check(f"boot {n}: tpm2-kira-close.service ran in the initrd", "Finished" in out and "Failed" not in out, out[-300:])
        # No cap: PCR 15 closes the slots.
        rc, out = self.run("ls /usr/lib/systemd/system/tpm2-kira-cap.service 2>&1; "
                           "grep -c 'tpm2-kira-boot cap' /usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira 2>&1; true")
        rc2, state = self.run("cat /run/tpm2-kira/close-state; ls /run/tpm2-kira/close-pending 2>&1; systemctl is-active tpm2-kira-late-close.service; ls /sys/firmware/efi/efivars | grep -c KIRAcloseReboot; true", save=f"boot{n}-close-state.log")
        self.check(f"boot {n}: the close is PCR 15's, no late closer, no reboot counted", state.startswith("closed") and "No such file" in state and "inactive" in state and re.search(r"^0$", state, re.M) is not None, state)
        self.check(f"boot {n}: no cap unit or cap step", "No such file" in out.split("\n")[0] and not re.search(r"^[1-9]", out, re.M), out.strip())
        # One rule: PCR 7 and the image; slot 0 with the platform. On a UKI
        # the image is PCR 11, signed by the PCR key.
        slot0, slot1 = ("0,2,4,7,8,9", "7,8,9") if self.distro == "debian" else ("0,2,4,7", "7")
        rc, out = self.run("grep '^ASSH_CA_SLOT_[0-9]' /etc/tpm2-kira/assh.conf 2>&1", save=f"boot{n}-ca-slots.log")
        ok = re.search(rf"^ASSH_CA_SLOT_0={slot0}$", out, re.M) is not None and re.search(rf"^ASSH_CA_SLOT_1={slot1}$", out, re.M) is not None
        if self.distro != "debian":
            ok = ok and "ASSH_CA_SLOT_0_SIGNED=11" in out and "ASSH_CA_SLOT_1_SIGNED=11" in out
        self.check(f"boot {n}: the SSH CA's slots are {slot0} and {slot1}" + ("" if self.distro == "debian" else ", each with PCR 11 signed"), ok, out.strip())
        if self.distro != "debian":
            rc, out = self.run("tpm2-kira slot info --nvram 0 2>&1 | grep -E 'PCR 11 ' | head -2; stat -c '%a %U' /etc/tpm2-kira/pcr.key; grep -c '^Phases=enter-initrd$' /etc/kernel/uki.conf", save=f"boot{n}-pcr11.log")
            self.check(f"boot {n}: slot 0's PCR 11 is signed, the PCR key root's alone, uki.conf signs enter-initrd", "(signed)" in out and "400 root" in out and re.search(r"^1$", out, re.M) is not None, out[-400:])
        # PCR 4 was predicted before this boot, for this boot: the approval
        # holds the prediction, the register what the firmware measured.
        rc, out = self.run("tpm2-kira slot info --nvram 0 2>&1; echo LIVE=$(cat /sys/class/tpm/tpm0/pcr-sha256/4)", save=f"boot{n}-pcr4.log")
        approved = re.search(r"PCR 4\s+\(uki\): ([0-9a-f]{64})", out)
        live = re.search(r"^LIVE=([0-9A-Fa-f]{64})$", out, re.M)
        expected = None
        if approved:
            expected = approved.group(1)
            if self.distro == "arch":
                # systemd-pcrosseparator extended it after the code screen.
                word = hashlib.sha256(b"os-separator").digest()
                expected = hashlib.sha256(bytes.fromhex(expected) + word).hexdigest()
        self.check(f"boot {n}: PCR 4 as predicted before this boot is the register",
                   expected is not None and live is not None and expected == live.group(1).lower(), out[-500:])

    def unapproved_kernel(self):
        """Arch: an image the hooks did not approve, signed by the PCR key
        all the same: PCR 11 needs no approval, so slot 1 shows its code and
        the SSH CA certifies through its slot 1, with slot 0 (PCR 4 moved) out.
        Then slot approve brings slot 0 back."""
        self.head("an image not approved, signed by the PCR key")
        # mkinitcpio -P does not hand --nopost to its presets, and runs every file
        # of the hooks' directory: the hook goes out of it.
        hook = "/usr/lib/initcpio/post/sd-tpm2-kira"
        rc, out = self.run(f"set -e; sed -i '$ s/$/ kiratest=1/' /etc/kernel/cmdline; mv {hook} /root/sd-tpm2-kira.off; "
                           f"mkinitcpio -P 2>&1 | tail -3; mv /root/sd-tpm2-kira.off {hook}", save="unapproved-rebuild.log")
        self.check("unapproved: the hook did not approve it", "approv" not in out, out[-400:])
        self.check("unapproved: an image built without the hook's approval", rc == 0, out[-400:])
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        if not self.check("unapproved: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server on the unapproved image")
        s = self.boot_session("unapproved")
        try:
            text, _ = s.expect(r"Does the code match your authenticator\?.*$", 60)
            at = time.time()
            codes = dict(re.findall(r"^#(\d+): (\d{6})$", text, re.M))
            self.check("unapproved: the host key is certified (slot 1, PCR 11 by its signature; strict known_hosts)", True)
            self.check("unapproved: slot 0 shows no code (PCR 4 moved)", "0" not in codes, text[-500:])
            self.check("unapproved: slot 1's code is the authenticator's", "1" in codes and code_matches(self.secrets[1], codes["1"], at), text[-500:])
            s.send("\r")
            s.expect(r"Password for disk \S+: ?$", 120); s.send(TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(TEST_SALT + "\r")
            s.wait_end(600)
        finally:
            s.close()
        if not self.check("unapproved: the system comes up (ssh)", self.wait_port(22, True, 300)):
            raise Fail("the system does not come up")
        rc, out = self.run("tpm2-kira slot approve 2>&1 | tail -4", save="unapproved-approve.log")
        self.check("unapproved: slot approve brings slot 0 back", "approved" in out, out[-400:])

    def rebuild(self):
        cmd = "update-initramfs -u" if self.distro == "debian" else "mkinitcpio -P"
        rc, out = self.run(cmd + " 2>&1", save="rebuild.log")
        return out

    CA_FILE = "/root/vault-ca.pem"

    def vault(self, vault):
        self.head("remote attestation over TLS: the vault")
        # Without a root of the vault the enrolment is refused before the
        # vault is asked; the root comes over as an operator brings it.
        rc, out = self.run("tpm2-kira luks enrol " + self.luks_dev + " --password tpm --salt vault --url " + vault.url +
                           " --pin sha256:" + "0" * 64 + " --token none 2>&1", save="luks-enrol-vault-no-root.log")
        self.check("luks enrol without a root of the vault is refused, naming --ca", "no root certificate of a vault" in out and "--ca FILE" in out, out[-400:])
        self.run(f"echo {base64.b64encode(vault.root.encode()).decode()} | base64 -d > {self.CA_FILE}")
        out = vault.admin("token", "create", "--name", self.name)
        self.log.save("vault-token.log", out)
        m = re.search(r"--url (\S+) --pin (\S+) --token (\S+)", out)
        if not self.check("the vault makes an enrolment token", m is not None, out[-400:]):
            raise Fail("no token")
        url, pin, token = m.groups()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --password tpm --salt vault --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {self.name}", "luks-enrol-vault")
        try:
            s.expect(r"to authorise: ?$", 300); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x240[01] ", 300)
            self.vault_keyslot = m.group(1)
            s.wait_end(120)
            self.check("luks enrol 0x2400: the vault knows the device, a keyslot is added", True)
        except Fail as e:
            self.check("luks enrol 0x2400", False, str(e))
            raise
        finally:
            s.close()
        out = vault.admin("devices")
        self.check("the vault lists the device", self.name in out, out[-400:])
        rc, out = self.run("cat /etc/tpm2-kira/vault-ca.pem 2>&1")
        self.check("--ca put the vault's root into /etc/tpm2-kira/vault-ca.pem", out.strip() == vault.root.strip(), out[-300:])
        out = self.rebuild()
        self.check("the image is rebuilt with the vault in its plan", re.search(r"Vault:\s+in", out) is not None, out[-800:])

        # A boot nobody touches: the vault releases its part to the TPM's
        # quote of the approved boot state, the key ends the hold by itself.
        self.head("a boot unlocked by the vault alone")
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        self.lap("the system going down")
        up = self.wait_port(22, True, 420)
        self.lap("nobody at the machine, to ssh")
        if not self.check("the vault's boot: the system comes up with nobody at the console or in SSH", up):
            raise Fail("the vault's boot did not come up")
        self.booted("the vault's boot")
        log = ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
               "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service")
        rc, out = self.run(log + " 2>&1", save="boot-vault-tpm2-kira.log")
        self.check("the vault released the remote part; the key was made", "released; the key is made" in out, out[-600:])
        self.check("the key was answered", "unlock: answered for" in out, out[-600:])
        out = vault.admin("devices")
        self.log.save("vault-devices.log", out)

        # Revoked: no release; the typed keyslot is the fallback, over SSH.
        self.head("a boot with the device revoked on the vault")
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
        self.booted("revoked")
        rc, out = self.run(log + " 2>&1", save="boot-revoked-tpm2-kira.log")
        self.check("revoked: the vault refused, the key was answered from the typed keyslot", "the device is revoked" in out and "unlock: answered for" in out, out[-600:])
        vault.admin("device", "unrevoke", self.name)

    PEPPER = "vmtest pepper 7f3a"

    def vault_pepper(self, vault):
        """The keyslot enrolled again with an operator's pepper: a boot
        waits for an approval; a wrong pepper is caught by the slot's pepper
        check and a new approval asked; the right one unlocks. The pepper
        reaches the machine wrapped for its TPM, opened through the slot's
        approval like R."""
        self.head("the vault with an operator's pepper")
        rc, out = self.run("tpm2-kira vault unenrol --nvram 0 2>&1", save="vault-unenrol.log")
        m = re.search(r"tpm2-kira-vault device revoke ([0-9a-f]+)", out)
        if not self.check("vault unenrol: the slot's vault method is gone", m is not None, out[-400:]):
            raise Fail("vault unenrol")
        device = m.group(1)
        s = self.session(f"sudo tpm2-kira luks remove {self.luks_dev} --keyslot {self.vault_keyslot}", "luks-remove-vault")
        try:
            s.expect(r"to authorise: ?$", 120); s.send(self.luks_pass + "\n")
            s.wait_end(120)
        finally:
            s.close()
        # Unenrolled, the slot's attestation part went with the vault: the
        # next enrolment is a new device. The old one is revoked, as the
        # unenrol says, by its ID.
        out = vault.admin("device", "revoke", device)
        self.check("the vault revokes the old device by its ID", "revoked" in out, out[-300:])
        name = self.name + "-pepper"
        out = vault.admin("token", "create", "--name", name)
        self.log.save("vault-token-pepper.log", out)
        m = re.search(r"--url (\S+) --pin (\S+) --token (\S+)", out)
        if not self.check("the vault makes a token for the new device", m is not None, out[-400:]):
            raise Fail("no token")
        url, pin, token = m.groups()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --password tpm --salt vault --pepper --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {name}", "luks-enrol-vault-pepper")
        try:
            s.expect(r"Pepper \(the operator gives it with every approval on the vault\): ?$", 300); s.send(self.PEPPER + "\n")
            s.expect(r"The same pepper again: ?$", 60); s.send(self.PEPPER + "\n")
            s.expect(r"to authorise: ?$", 300); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x240[01] ", 300)
            self.vault_keyslot = m.group(1)
            text = s.wait_end(120)
            self.check("luks enrol --pepper: a keyslot that waits for an operator", "approves it on the vault with the pepper" in text, text[-400:])
        except Fail as e:
            self.check("luks enrol 0x2401 (pepper)", False, str(e))
            raise
        finally:
            s.close()
        out = vault.admin("device", "show", name)
        self.check("the vault's device needs a pepper and waits for approvals", "pepper:          yes" in out and "approve" in out, out[-400:])
        self.rebuild()

        self.head("a boot approved with a wrong pepper, then the right one")
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        rid = vault.pending(name, 300)
        if not self.check("the boot asks the vault and waits for an operator", rid is not None):
            raise Fail("no pending request")
        rc, body = vault.admin_input("not the pepper\n", "request", "approve", rid)
        self.check("an operator approves with a wrong pepper on the vault's CLI (request approve)", rc == 0 and "approved" in body, body[-300:])
        rid2 = None
        deadline = time.time() + 120
        while time.time() < deadline:
            rid2 = vault.pending(name, 10)
            if rid2 and rid2 != rid:
                break
            rid2 = None
        if not self.check("the machine refuses the wrong pepper and asks for a new approval", rid2 is not None):
            raise Fail("no second request")
        code, body = vault.approve(rid2, self.PEPPER)
        self.check("an operator approves with the pepper over the operator interface", code == "200", f"{code} {body[-300:]}")
        up = self.wait_port(22, True, 420)
        if not self.check("the pepper's boot: the system comes up with nobody at the console", up):
            raise Fail("the pepper's boot did not come up")
        self.booted("the pepper's boot")
        log = ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
               "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service")
        rc, out = self.run(log + " 2>&1", save="boot-vault-pepper-tpm2-kira.log")
        self.check("the wrong pepper did not fit the slot's pepper check", "does not fit this keyslot" in out, out[-600:])
        self.check("with the right pepper the key was made and answered", "released; the key is made" in out and "unlock: answered for" in out, out[-600:])
        out = vault.admin("audit")
        self.log.save("vault-audit-pepper.log", out)
        self.check("the vault's audit: released with a pepper, the pepper itself nowhere",
                   "with a pepper" in out and self.PEPPER not in out and "not the pepper" not in out, out[-600:])

    def luks_remove(self, keyslot, name):
        s = self.session(f"sudo tpm2-kira luks remove {self.luks_dev} --keyslot {keyslot}", name)
        try:
            s.expect(r"to authorise: ?$", 120); s.send(self.luks_pass + "\n")
            text = s.wait_end(120)
        finally:
            s.close()
        rc, out = self.run(f"tpm2-kira luks status {self.luks_dev} 2>&1")
        return out

    def typed_boot(self, name, from_words, before_enter=None):
        """A boot whose recipe has a typed password and a device-held salt:
        the code screen over SSH names the password prompt, the prompt says
        where the salt came from and asks the password alone. before_enter
        runs while the code screen holds (an operator's approval)."""
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        if not self.check(f"{name}: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server")
        s = self.boot_session(name.replace(" ", "-"))
        try:
            text, _ = s.expect(r"Does the code match your authenticator\?.*$", 120)
            self.check(f"{name}: the screen names the password prompt", "continue to the password prompt" in text, text[-300:])
            if before_enter:
                before_enter()
            s.send("\r")
            text, _ = s.expect(r"(Password|Salt) for disk \S+: ?$", 300)
            self.check(f"{name}: the password is asked with the salt {from_words}",
                       "Password for disk" in text.split("\n")[-1] and f"the salt {from_words}" in text, text[-500:])
            if "Salt for disk" in text.split("\n")[-1]:
                raise Fail("asked for a typed salt: " + text[-300:])
            return s, text
        except Fail:
            s.close()
            raise

    def boot_log(self, save):
        log = ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
               "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service")
        rc, out = self.run(log + " 2>&1", save=save)
        return out

    def tpm_salt(self):
        """The salt in this TPM (0x1200): enrolled, named by luks status and
        luksDump, the image's plan takes the part; a boot asks the password
        alone - the TPM opened the salt while the code screen held; the
        keyslot removed again."""
        self.head("the salt in this TPM (0x1200)")
        swap = self.swap_counts()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt tpm", "luks-enrol-tpm-salt")
        try:
            s.expect(r"Password \(typed at the machine at every boot\): ?$", 300); s.send(TPM_SALT_PASSWORD + "\n")
            s.expect(r"The same password again: ?$", 60); s.send(TPM_SALT_PASSWORD + "\n")
            s.expect(r"to authorise: ?$", 600); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1200 ", 300)
            keyslot = m.group(1)
            s.wait_end(120)
            self.check("luks enrol --salt tpm: a keyslot of recipe 0x1200", True)
            self.check_no_swap(swap, "the TPM salt enrolment's Argon2id")
        except Fail as e:
            self.check("luks enrol --salt tpm", False, str(e))
            raise
        finally:
            s.close()
        rc, out = self.run(f"tpm2-kira luks status {self.luks_dev} 2>&1", save="luks-status-tpm-salt.log")
        self.check("luks status names the recipe", "0x1200 password typed · salt in this TPM" in out, out[-500:])
        rc, out = self.run(f"cryptsetup luksDump {self.luks_dev} 2>&1")
        self.check("luksDump names it too (token type tpm2-kira-1200)", "tpm2-kira-1200" in out, out[-500:])
        rc, out = self.run("tpm2-kira status --json 2>&1", save="status-tpm-salt.json")
        self.check("status: slot 0 holds a TPM salt", '"tpm_salt": true' in out, out[-400:])
        out = self.rebuild()
        self.check("the image is rebuilt with the TPM salt in its plan", re.search(r"TPM salt:\s+in", out) is not None, out[-800:])
        # The image's hook says it, once per image built; its approval does not again.
        images = out.count("Starting build:") if self.distro == "arch" else 1
        n = len(re.findall(r"Secure Boot (is|'s state)", out))
        self.check(f"the image's hook says Secure Boot's state once per image built ({images})", n == images if self.secure_boot_warning() else n == 0, out[-800:])

        self.head("a boot with the salt in this TPM")
        s, _ = self.typed_boot("TPM salt", "this TPM opened")
        try:
            s.send(TPM_SALT_PASSWORD + "\r")
            s.wait_end(600)
        finally:
            s.close()
        up = self.wait_port(22, True, 300)
        if not self.check("TPM salt: the disk unlocks with the password alone", up):
            raise Fail("the TPM salt's boot did not come up")
        self.booted("TPM salt")
        out = self.boot_log("boot-tpm-salt-tpm2-kira.log")
        self.check("TPM salt: opened while the code screen held, the key answered", "tpm salt: slot 0: opened" in out and "unlock: answered for" in out, out[-600:])
        out = self.luks_remove(keyslot, "luks-remove-tpm-salt")
        self.check("luks remove takes the TPM salt's keyslot", "0x1200" not in out, out[-400:])
        rc, out = self.run("tpm2-kira status --json 2>&1")
        self.check("the TPM salt went with its last keyslot", '"tpm_salt": true' not in out, out[-400:])

    def vault_typed(self, vault):
        """The vault's salt with a typed password and a pepper (0x1401): the
        unattended keyslot goes, the device enrolled again; at boot an
        operator approves on the vault's CLI (requests answer, the pepper on
        its stdin) while the code screen holds, the vault releases the salt,
        and the password alone is asked after the code screen."""
        self.head("the vault's salt with a typed password and a pepper (0x1401)")
        rc, out = self.run("tpm2-kira vault unenrol --nvram 0 2>&1", save="vault-unenrol-typed.log")
        m = re.search(r"tpm2-kira-vault device revoke ([0-9a-f]+)", out)
        if not self.check("vault unenrol before the typed recipe", m is not None, out[-400:]):
            raise Fail("vault unenrol")
        device = m.group(1)
        self.luks_remove(self.vault_keyslot, "luks-remove-vault-pepper")
        out = vault.admin("device", "revoke", device)
        self.check("the vault revokes the pepper device by its ID", "revoked" in out, out[-300:])
        name = self.name + "-typed"
        out = vault.admin("token", "create", "--name", name)
        m = re.search(r"--url (\S+) --pin (\S+) --token (\S+)", out)
        if not self.check("a token for the typed recipe's device", m is not None, out[-400:]):
            raise Fail("no token")
        url, pin, token = m.groups()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt vault --pepper --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {name}", "luks-enrol-vault-typed")
        try:
            s.expect(r"Pepper \(the operator gives it with every approval on the vault\): ?$", 300); s.send(self.PEPPER + "\n")
            s.expect(r"The same pepper again: ?$", 60); s.send(self.PEPPER + "\n")
            s.expect(r"Password \(typed at the machine at every boot\): ?$", 60); s.send(VAULT_PASSWORD + "\n")
            s.expect(r"The same password again: ?$", 60); s.send(VAULT_PASSWORD + "\n")
            s.expect(r"to authorise: ?$", 600); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1401 ", 300)
            self.vault_keyslot = m.group(1)
            s.wait_end(120)
            self.check("luks enrol --salt vault --pepper: a keyslot of recipe 0x1401", True)
        except Fail as e:
            self.check("luks enrol --salt vault --pepper", False, str(e))
            raise
        finally:
            s.close()
        rc, out = self.run("tpm2-kira status 2>&1", save="status-vault-typed.log")
        self.check("status: the vault method is the typed recipe with a pepper", "0x1401 password typed · salt from the vault (pepper)" in out, out[-500:])

        self.head("a boot: the operator approves on the vault's CLI, the password typed after")
        # This device's: the other machine's run shares the vault.
        releases = lambda: sum(1 for l in vault.admin("audit").splitlines() if f"({name})" in l and "TPM reset count" in l)
        released_before = releases()

        def approve():
            rid = vault.pending(name, 300)
            if not self.check("typed vault: the boot waits for an operator", rid is not None):
                raise Fail("no pending request")
            rc, out = vault.admin_input("a\n" + self.PEPPER + "\n", "requests", "answer")
            self.log.save("vault-requests-answer.log", out)
            self.check("the vault's CLI answers the queue (requests answer, the pepper asked)", rc == 0 and name in out and "approved" in out, out[-400:])
            deadline = time.time() + 120
            while time.time() < deadline and releases() <= released_before:
                time.sleep(1)
            self.check("typed vault: the vault released the salt while the code screen held", releases() > released_before)

        s, _ = self.typed_boot("typed vault", "the vault released", before_enter=approve)
        try:
            s.send(VAULT_PASSWORD + "\r")
            s.wait_end(600)
        finally:
            s.close()
        up = self.wait_port(22, True, 300)
        if not self.check("typed vault: the disk unlocks with the password and the vault's salt", up):
            raise Fail("the typed vault's boot did not come up")
        self.booted("typed vault")
        out = self.boot_log("boot-vault-typed-tpm2-kira.log")
        self.check("typed vault: the salt opened during the hold, the key answered", "released; the salt is opened" in out and "unlock: answered for" in out, out[-600:])
        out = vault.admin("audit")
        self.check("the vault's audit holds no pepper", self.PEPPER not in out, out[-300:])

    def slot_life(self):
        self.head("a slot's life")
        rc, out = self.run(f"tpm2-kira slot approve --nvram {self.slots[-1]} 2>&1", save="slot-approve.log")
        self.check("slot approve raises the generation", "Successfully approved the boot state" in out, out[-400:])
        self.check_secure_boot("slot approve", out)
        rc, out = self.run("tpm2-kira slot approve 2>&1", save="slot-approve-all.log")
        self.check_secure_boot("slot approve of every slot", out)
        pcrs = "0,7,8,9" if self.distro == "debian" else "0,7"
        rc, out = self.run(f"tpm2-kira slot add --totp --nvram 2 --pcrs {pcrs} 2>&1 | grep -v '^Secret'", save="slot-add-2.log")
        rc, info = self.run("tpm2-kira slot info --nvram 2 2>&1")
        self.check("slot add --nvram 2: its record is KIRAslot2", "EFI variable: KIRAslot2-" in info, info[-300:])
        self.moved_channel(2)
        rc, out = self.run("tpm2-kira slot delete --nvram 2 2>&1", save="slot-delete.log")
        self.check("slot delete --nvram 2", "Successfully deleted" in out, out[-400:])
        rc, out = self.run("tpm2-kira slot list 2>&1", save="slot-list-after-delete.log")
        self.check("slot 2 is gone whole (its blob and its generation index)", "0x01803012" not in out and "0x01803812" not in out, out[-500:])

    def moved_channel(self, slot):
        """A slot whose phone channel is sealed to another PCR 7 than the next boot's
        (the fixture: no VM has a phone): the real hook scripts and a run with no
        terminal approve the slot and leave the channel, and say so with old, new and
        the real event log's events; no at a terminal leaves it; yes and control seal
        it. A gate is not started here: no radio; that it refuses is swtpm's test."""
        self.head("a moved PCR 7: the phone channel follows a person alone")
        remote = "/tmp/channel-fixture"
        self.t.copy_to(self.channel_fixture, remote)
        self.run(f"chmod 755 {remote}")

        def moved():
            rc, out = self.run("tpm2-kira status --json 2>&1", save=f"status-channel-{self.sessions}.json")
            try:
                s = next(x for x in json.loads(out)["slots"] if x["slot_number"] == slot)
            except (ValueError, StopIteration, KeyError):
                raise Fail("status does not read:\n" + out[-500:])
            return bool(s.get("channel_moved"))

        def fixture():
            rc, out = self.run(f"FIXTURE_SLOT={slot} {remote} -test.run '^TestVMChannelFixture$' 2>&1", save="channel-fixture.log")
            if rc != 0 or not moved():
                raise Fail("the fixture makes no moved channel:\n" + out[-800:])

        left = f"WARNING: slot {slot}'s phone channel was left sealed to the old PCR 7"
        hooks = ["/usr/lib/initcpio/post/sd-tpm2-kira"] if self.distro == "arch" else ["/etc/initramfs/post-update.d/tpm2-kira", "/etc/kernel/postinst.d/zzz-tpm2-kira"]
        fixture()
        for hook in hooks:
            name = os.path.basename(hook)
            rc, out = self.run(f"{hook} 0.0 /boot/nothing 2>&1", save=f"channel-hook-{name}.log")
            self.check(f"{name}: the hook's approval says it left the channel, with the command", left in out and f"sudo tpm2-kira slot approve --nvram {slot}" in out, out[-800:])
            self.check(f"{name}: old and new PCR 7, and what the event log names", re.search(r"PCR 7 sealed: +[0-9a-f]{64}", out) is not None and re.search(r"PCR 7 next boot: +[0-9a-f]{64}", out) is not None and re.search(r"SecureBoot: (on|off)", out) is not None, out[-800:])
            self.check(f"{name}: the channel stays moved", moved())
        rc, out = self.run("tpm2-kira status 2>&1", save="status-channel.log")
        self.check("status: the moved channel is a warning, with the command", f"WARNING: slot {slot}'s phone channel is sealed to another PCR 7" in out and f"slot approve --nvram {slot}" in out, out[-800:])
        rc, out = self.run("tpm2-kira slot approve --if-moved 2>&1", save="channel-if-moved.log")
        self.check("--if-moved never seals it", moved() and "is sealed again" not in out, out[-500:])
        rc, out = self.run(f"tpm2-kira slot approve --nvram {slot} </dev/null 2>&1", save="channel-no-terminal.log")
        self.check("no terminal, no flag: the slot approved, the channel left, and said", moved() and left in out and "Successfully approved the boot state" in out, out[-800:])

        answers = {"n": True, "y": False}
        for answer, stays in answers.items():
            s = self.session(f"sudo tpm2-kira slot approve --nvram {slot}", f"channel-person-{answer}")
            try:
                text, _ = s.expect(r"Seal slot \d+'s phone channel to the next boot's PCR 7\? \[y/N\] ?$", 120)
                self.check(f"at a terminal: old, new and what moved it, before the question ({answer})",
                           re.search(r"PCR 7 sealed: +[0-9a-f]{64}", text) is not None and re.search(r"PCR 7 next boot: +[0-9a-f]{64}", text) is not None and re.search(r"SecureBoot: (on|off)", text) is not None, text[-800:])
                s.send(answer + "\n")
                out = s.wait_end(120)
            finally:
                s.close()
            self.check(f"at a terminal, {answer}: " + ("left, and said" if stays else "sealed"), moved() == stays and ((left in out) if stays else ("is sealed again" in out)), out[-500:])

        fixture()
        s = self.session("sudo ACCESSIBLE=1 tpm2-kira control", "control-channel")
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
            text = pick(r"Signing key and TOTP codes")
            self.check("control: step 2 shows the moved channel", "phone channel" in text, text[-1200:])
            self.check_control_secure_boot("control step 2", text, {"Setup Mode": "Setup Mode (risk: any root user", "off": "disabled (risk: the boot loader", "could": "state unknown,"})
            text = pick(r"Slot \d+'s phone channel")
            text, _ = s.expect(r"Seal slot \d+'s phone channel to the next boot's PCR 7\?.*\[y/N\] ?$", 60)
            self.check("control: old, new and what moved it, before the question", re.search(r"PCR 7 sealed: +[0-9a-f]{64}", text) is not None and re.search(r"SecureBoot: (on|off)", text) is not None, text[-1200:])
            s.send("y\n")
            pick(r"Back to step 2")
            pick(r"^\s*Quit$")
            for _ in range(4):
                text, m = s.expect(r"(\[(y/N|Y/n)\] ?$|Connection to \S+ closed)", 120)
                if m.group(1).startswith("Connection"):
                    break
                s.send("n\n")
        finally:
            s.close()
        self.check("control: picking the line seals it", not moved())
        self.run(f"rm -f {remote}")

    def removal(self):
        """What tpm2-kira keeps outside the disk goes when asked, and only
        then: control asks before it removes the SSH CA when SSH is switched
        off (No keeps it); slot delete without --nvram takes everything -
        the slots, the boot settings, the SSH CA's EFI variable and its
        public key."""
        self.head("removing what tpm2-kira keeps in the TPM and the EFI variables")
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
            # SSH switched off makes the image out of date: the next boot
            # must not start the server.
            text, m = s.expect(r"(Run (mkinitcpio -P|update-initramfs -u) now\? \[Y/n\] ?$|Connection to \S+ closed)", 120)
            self.check("SSH switched off: control offers the rebuild (the next boot without the server)",
                       m.group(1).startswith("Run") and "SSH server: switched off" in text, text[-800:])
            if m.group(1).startswith("Run"):
                s.send("y\n")
                text = s.wait_end(900)
                self.check("the rebuilt image leaves the SSH server out", re.search(r"SSH server:\s+out", text) is not None, text[-800:])
            self.log.save("control-ssh-off-rebuild.log", text)
        except Fail as e:
            self.check("control: SSH off, the SSH CA kept on No", False, str(e))
            raise
        finally:
            s.close()
        self.removal_all()

    CA_VAR = "/sys/firmware/efi/efivars/KIRAasshCA-24415b90-39be-45c0-a9a3-d547ebe28ea0"
    MID_VAR = "/sys/firmware/efi/efivars/KIRAmachineID-67f474ef-94a1-4412-88df-d62349d430a9"

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
        self.check("the sealed machine-id's EFI variable is gone", not there(self.MID_VAR))
        self.check("its public key /etc/tpm2-kira/ssh_ca.pub is gone", not there("/etc/tpm2-kira/ssh_ca.pub"))
        rc, out = self.run("tpm2-kira slot delete --yes 2>&1")
        self.check("slot delete again: nothing of tpm2-kira is found", "nothing of tpm2-kira found" in out, out[-300:])

    def make_setup(self, package, reset=None):
        """The steps up to the first reboot."""
        if reset:
            self.reset(reset)
        self.preflight()
        self.install(package)
        self.seal()
        self.inspect()
        self.enrol()
        self.control()
        self.image()

    def save_setup(self, package, setup, reset=None):
        """--save-setup: the steps up to the first reboot, kept; the run ends."""
        try:
            self.make_setup(package, reset)
            self.head(f"keeping the setup: the snapshot {setup.tag}")
            setup.save()
        except Fail as e:
            self.rep.issues.append("stopped: " + str(e).split("\n")[0])
        except Exception as e:
            self.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        return self.report()

    def all(self, package, vault=None, reset=None, from_setup=None):
        try:
            if from_setup:
                self.notes.append(FROM_SETUP_NOTE)
                self.head(f"back to the setup: the snapshot {from_setup.tag}")
                from_setup.restore()
                self.lv.start(unlock=False)
            else:
                self.make_setup(package, reset)
            for n in range(1, self.cycles + 1):
                self.cycle(n, started=bool(from_setup) and n == 1)
            if self.distro == "arch":
                self.unapproved_kernel()
            self.tpm_salt()
            if vault:
                self.vault(vault)
                self.vault_pepper(vault)
                self.vault_typed(vault)
            self.slot_life()
            self.removal()
        except Fail as e:
            self.rep.issues.append("stopped: " + str(e).split("\n")[0])
        except Exception as e:  # a defect of the test, reported as such
            self.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        return self.report()

    def report(self):
        self.timing.finish()
        self.log.save("times.json", self.timing.as_json())
        lines = list(self.notes) + [f"tpm2-kira vmtest: {self.name} ({self.distro}) on {self.host}", datetime.datetime.now().isoformat(timespec="seconds"), ""]
        for name, status, detail in self.rep.checks:
            lines.append(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
        lines += ["", "Issues:" if self.rep.issues else "No issues."] + ["  - " + i for i in self.rep.issues]
        lines += [""] + self.timing.lines()
        failed = self.rep.failed() or any(i.startswith(("stopped", "the test failed")) for i in self.rep.issues)
        lines += ["", "RESULT: FAIL" if failed else "RESULT: PASS", f"logs: {self.dir}"]
        text = "\n".join(lines) + "\n"
        self.log.save("report.txt", text)
        return not failed, text


def build_channel_fixture(run_dir):
    """A test binary the machines run: internal/admin's TestVMChannelFixture, which
    gives a slot a phone channel sealed to another PCR 7 (no VM has a phone)."""
    path = os.path.join(run_dir, "channel-fixture")
    env = dict(os.environ, CGO_ENABLED="0", GOWORK="off")
    p = subprocess.run(["go", "test", "-c", "-tags", "kira_vm_fixture", "-o", path, "./internal/admin"], cwd=REPO, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise Fail("the channel fixture does not build:\n" + p.stdout + p.stderr)
    return path


def head_packages(directory, fast_kdf=False):
    """The packages of HEAD in directory: the Arch package names the commit
    as .g<short>-, the Debian one as +<n>.g<short>_; a test build's has
    .fastkdf behind it, so that neither is ever taken for the other."""
    mark = ".fastkdf" if fast_kdf else ""
    short = subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    pick = lambda pattern: (sorted(glob.glob(os.path.join(directory, pattern)), key=os.path.getmtime) or [None])[-1]
    return short, {"debian": pick(f"tpm2-kira_*.g{short}{mark}_amd64.deb"),
                   "arch": pick(f"tpm2-kira-*.g{short}{mark}-*-x86_64.pkg.tar.zst")}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["arch", "debian", "both"], required=True)
    p.add_argument("--config", default=os.path.join(REPO, "tools", "vmtest.conf"))
    p.add_argument("--packages", help="where the built .deb and .pkg.tar.zst are (default build/packages, with --fast-kdf build/packages-fastkdf)")
    p.add_argument("--fast-kdf", action="store_true", help="WARNING: NO FINAL PROOF. A test package, built here with Argon2id at a test's cost (a Go build tag), never a release; the whole typed-recipe path runs, the real cost does not. Disks enrolled with one cost do not open with the other")
    p.add_argument("--password-file", help="the VMs' user password (default: the config's password_file, or $VMTEST_PASSWORD)")
    p.add_argument("--cycles", type=int, default=2, help="reboots, each unlocked over the boot SSH server (default 2)")
    p.add_argument("--run-dir", help="default: ./vmtest-<time>")
    p.add_argument("--no-vault", action="store_true", help="leave out remote attestation over TLS (the vault)")
    p.add_argument("--no-build", action="store_true", help="take HEAD's packages already in --packages instead of building them")
    p.add_argument("--no-reset", action="store_true", help="do not run the machines' reset commands: they must be fresh already")
    p.add_argument("--localvm-config", help="the machines' config for the saved setup (default: tools/localvm.py's)")
    p.add_argument("--save-setup", action="store_true", help=f"the steps up to the first reboot, kept in the snapshot {SETUP_SNAPSHOT}; the run ends")
    p.add_argument("--from-setup", action="store_true", help=f"start from the snapshot {SETUP_SNAPSHOT}, without building: no final proof")
    p.add_argument("--drop-setup", action="store_true", help=f"remove the snapshot {SETUP_SNAPSHOT} and end")
    args = p.parse_args()
    if sum((args.save_setup, args.from_setup, args.drop_setup)) > 1:
        p.error("--save-setup, --from-setup and --drop-setup exclude each other")
    args.no_build = args.no_build or args.from_setup or args.drop_setup
    args.packages = args.packages or os.path.join(REPO, "build", "packages-fastkdf" if args.fast_kdf else "packages")
    if args.fast_kdf:
        print(FAST_KDF_NOTE, flush=True)

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
    local = {}
    if args.save_setup or args.from_setup or args.drop_setup:
        localvm, local = local_machines(args.localvm_config or load_localvm().DEFAULT_CONFIG, names)
    if args.drop_setup:
        for lv in local.values():
            SavedSetup(lv, None, SETUP_SNAPSHOT).drop()
        print(f"dropped {SETUP_SNAPSHOT}")
        return 0
    timing = Timing("the run", print)
    os.makedirs(run_dir, exist_ok=True)
    if not args.no_build:
        timing.step("building the packages")
        targets = ["arch" if n == "arch" else "deb" for n in names]
        print(f"building the packages of HEAD ({' '.join(targets)}), log: {run_dir}/build-packages.log", flush=True)
        with open(os.path.join(run_dir, "build-packages.log"), "w") as log:
            if subprocess.run([os.path.join(REPO, "packaging", "build-packages.sh")] + (["--fast-kdf"] if args.fast_kdf else []) + targets, cwd=REPO, stdout=log, stderr=subprocess.STDOUT).returncode != 0:
                print(f"the packages do not build: {run_dir}/build-packages.log", file=sys.stderr)
                return 1
    short, packages = head_packages(args.packages, args.fast_kdf)
    machines, resets = [], {}
    for name in names:
        if not packages[name] and not args.from_setup:
            print(f"no {name} package of HEAD ({short}) in {args.packages} (leave out --no-build)", file=sys.stderr)
            return 2
        sec = cfg[name]
        luks = sec.get("luks_passphrase") or os.environ.get("VMTEST_LUKS_PASSPHRASE") or password
        machines.append(Machine(name, name, sec["host"], sec.get("user", "pix"), password, luks, run_dir, args.cycles,
                                int(sec.get("ssh_port", "22")), int(sec.get("boot_port", str(SSH_PORT)))))
        if not args.no_reset and sec.get("reset"):
            resets[name] = sec["reset"]
        if name in local:
            machines[-1].lv = local[name]
        machines[-1].fast_kdf = args.fast_kdf
        if args.fast_kdf:
            machines[-1].notes.append(FAST_KDF_NOTE)
        if packages[name]:
            why = package_is(packages[name], args.fast_kdf)
            machines[-1].check(f"the package is {'a test build, as --fast-kdf asks' if args.fast_kdf else 'a release build: no Go build tag, no trace of a test build'}", why is None, why or "")
            if why:
                print(f"{os.path.basename(packages[name])}: {why}", file=sys.stderr)
                return 1
    setups = {m.name: SavedSetup(local[m.name], m, SETUP_SNAPSHOT, args.fast_kdf) for m in machines if m.name in local}
    if args.from_setup:
        problems = [why for why in (s.problem() for s in setups.values()) if why]
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 2
        print(FROM_SETUP_NOTE, flush=True)
    vault = None
    if not args.no_vault and not args.save_setup:
        vc = cfg["vault"] if cfg.has_section("vault") else {}
        vault = Vault(os.path.abspath(os.path.join(REPO, vc.get("src", "../tpm2-kira-vault"))),
                      vc.get("url", "https://172.17.2.174"), int(vc.get("port", "443")), int(vc.get("operator_port", "8444")), run_dir)
        timing.step("the vault's container")
        try:
            vault.start()
        except Fail as e:
            print("the vault does not start:", e, file=sys.stderr)
            return 1
    if not args.save_setup:
        timing.step("the channel fixture")
        fixture = build_channel_fixture(run_dir)
        for m in machines:
            m.channel_fixture = fixture
    timing.finish()
    results = {}
    print(f"tpm2-kira {short}: " + ", ".join(f"{m.name} {os.path.basename(packages[m.name] or 'the saved setup')}" + (" (reset)" if m.name in resets else "") for m in machines), flush=True)
    if args.save_setup:
        work = lambda m: m.save_setup(packages[m.name], setups[m.name], resets.get(m.name))
    else:
        work = lambda m: m.all(packages[m.name], vault, resets.get(m.name), setups.get(m.name) if args.from_setup else None)
    threads = [threading.Thread(target=lambda m=m: results.__setitem__(m.name, work(m))) for m in machines]
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
    print_slowest([timing] + [m.timing for m in machines])
    if args.from_setup:
        print(FROM_SETUP_NOTE)
    if args.fast_kdf:
        print(FAST_KDF_NOTE)
    with open(os.path.join(run_dir, "times.json"), "w") as f:
        f.write(timing.as_json())
    print("ALL PASS" if ok else "FAILED", "- logs:", run_dir)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
