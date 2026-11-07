#!/usr/bin/env python3
"""The VM test: tpm2-kira on fresh, encrypted test VMs, scenario by scenario.

    tools/vmtest.py --target both                     # the proof's scenarios, from the snapshot fresh
    tools/vmtest.py --target both --all               # and the rest, before a release (the owner's call)
    tools/vmtest.py --target debian --only tpm-salt   # one scenario, from the snapshot setup

It runs with nobody at the keyboard and ends with ALL PASS (exit 0) or FAILED. The packages of the
committed state are built while the machines go back to their state (packaging/build-packages.sh:
HEAD, aSSH as pinned), and exactly those are installed - never a package of another commit;
--no-build takes the ones of HEAD already in build/packages.

The machines are described in tools/vmtest.conf (an address, a user with sudo, the LUKS device's
passphrase, and how to reset it; see vmtest.conf.example). Each is put back into its defined state
first: the machine's `reset` command runs, and the run waits for its ssh. Fresh means: tpm2-kira not
installed, /etc/tpm2-kira absent, a LUKS-encrypted root whose passphrase is known, a TPM, and an ssh
server for the user; a machine that is not is refused. Without a `reset` command (or with --no-reset)
the machine must be fresh already. The run changes the machine (packages, slots in its TPM, an SSH CA
in an EFI variable, a keyslot, the boot image).

The scenarios are SCENARIOS, in a run's order; docs/TESTING.md says what each one checks, and
report.txt and scenarios.json of a machine give each one's seconds against its budget. Those with a
budget are the proof (tools/proof.py: 15 minutes); those without run under --all, or when named.

Secure Boot: the first part runs in Setup Mode. The scenario secure-boot goes back to fresh, enrols real
keys (tools/secureboot-vm.py), makes a setup of its own; every scenario that talks to a vault runs
there, and firmware-refuses last.

A scenario that fails sends the machine back to the setup, booted, and the next goes on; one that
needs it is not run. A kernel that refuses a hibernated image is "not tested", at once.

Iterating: on the machines of tools/localvm.py, --save-setup makes the setup once, keeps the state
after it in the snapshot "setup" and ends; --only and --from-setup start from it at the first boot,
and their reports say they are no final proof. A change to the product wants a new --save-setup;
--drop-setup removes it. "fresh" and "export" are never written.

--fast-kdf runs on a TEST package: Argon2id at a test's cost, by a Go build tag
(packaging/build-packages.sh --fast-kdf, build/packages-fastkdf). The whole typed-recipe path runs,
the real cost does not: such a run is NO FINAL PROOF, and its report's first line says so.

Nothing but Python's standard library and ssh are needed here. Reports and every session's
transcript land in the run's directory.
"""

import argparse
import urllib.parse
import base64
import configparser
import datetime
import fcntl
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
import termios
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmtestlib import (  # noqa: E402 - the helpers, under the names hibernatetest.py reaches as vmtest.X
    ANSI, Fail, Phone, PhoneStage, Session, Timing, Vault, clean, code_matches, menu_options, print_slowest, totp,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("acceptance", os.path.join(REPO, "tools", "acceptance.py"))
acceptance = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(acceptance)


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
# The same with Secure Boot on: the steps up to the first reboot, from tools/secureboot-vm.py's snapshot.
SECURE_SETUP_SNAPSHOT = "setup-secure"
# A boot's commands read at once: where one's output starts (Machine.batch).
BATCH_MARK = "@@tpm2-kira-vmtest@@"
FROM_SETUP_NOTE = "NOT A FINAL PROOF: started from a saved setup, not from the snapshot fresh."
FAST_KDF_NOTE = "NOT A FINAL PROOF: a --fast-kdf TEST build, Argon2id at a test's cost, not the production's."
PARTIAL_NOTE = "NOT A FINAL PROOF: a part of the run: "
# The snapshot of one hibernation, while a run lasts: every resume starts from it.
HIBERNATED = "hibernated"
# What firmware and systemd-boot say of an image whose signature does not verify (EFI_ACCESS_DENIED).
REFUSED_BY_FIRMWARE = re.compile(r"Access Denied|Security Violation", re.I)


class Scenario:
    """A part of a run. budget: seconds per distribution, measured, when it is in the proof; None
    runs it under --all, or when named. distro: on that one alone. needs: what has to have run on
    the machine before it; hib: on the machines of tools/localvm.py alone; vault: with the run's vault;
    secure: on the machine with Secure Boot really on, from the scenario secure-boot; phone: with the
    emulator's Marify on the simulated Bluetooth (--phone, tools/phone-vm-test.py)."""

    def __init__(self, name, budget=None, distro=None, needs=(), hib=False, vault=False, secure=False, phone=False):
        self.name, self.budget, self.distro, self.needs, self.hib, self.vault, self.secure = name, budget, distro, needs, hib, vault, secure
        self.phone = phone


def budget(arch, debian):
    return {"arch": arch, "debian": debian}


SETUP = "setup"
SECURE_BOOT = "secure-boot"
# A run's order, which spares waits: the hibernation right after a short boot; each state a
# scenario needs from the one before; what breaks the machine last. The machine then goes back to
# fresh, to its setup with Secure Boot on; every scenario that talks to a vault runs there. What
# there breaks the firmware's trust comes last.
SCENARIOS = (
    Scenario(SETUP, budget(175, 202)),
    Scenario("typed-boot", budget(49, 67)),
    Scenario("V6", hib=True),
    Scenario("hibernate", budget(68, 7), hib=True),
    Scenario("debian-resume", distro="debian", hib=True),
    Scenario("V3", distro="arch", hib=True),
    Scenario("unapproved", budget(75, None), distro="arch"),
    Scenario("second-typed-boot"),
    Scenario("slot-life"),
    Scenario("removal"),
    Scenario("no-tpm", hib=True),
    Scenario("V4-reverted", distro="debian", needs=("no-tpm",), hib=True),
    Scenario("silent-tpm", budget(124, 124), hib=True),
    Scenario("V9-long", distro="debian", needs=("silent-tpm",), hib=True),
    Scenario("V8", hib=True),
    Scenario("phone", needs=("typed-boot",), phone=True),
    Scenario(SECURE_BOOT, budget(218, 258), secure=True),
    Scenario("tpm-salt", budget(32, 30), needs=(SECURE_BOOT,), secure=True),
    Scenario("vault-pepper", budget(133, 158), needs=(SECURE_BOOT,), vault=True, secure=True),
    Scenario("revoked", budget(60, 66), needs=("tpm-salt", "vault-pepper"), vault=True, secure=True),
    Scenario("vault-alone", needs=("vault-pepper",), vault=True, secure=True),
    Scenario("typed-vault", needs=("vault-pepper",), vault=True, secure=True),
    Scenario("keyboard-vault", needs=("vault-pepper",), vault=True, secure=True),
    Scenario("firmware-refuses", budget(12, 10), needs=(SECURE_BOOT,), secure=True),
)
ALWAYS = "typed-boot"  # what every scenario of the setup in Setup Mode starts from


def scenario(name):
    return next(s for s in SCENARIOS if s.name == name)


def scenarios_of(only=None, everything=False):
    """The names a run takes: --only with what they need (every scenario after a setup starts from
    its typed boot), --all, or the proof's."""
    if only is None:
        return [s.name for s in SCENARIOS if everything or s.budget]
    wanted, todo = set(), list(only)
    while todo:
        name = todo.pop()
        if name not in wanted:
            wanted.add(name)
            todo += list(scenario(name).needs)
            if name != SETUP and not scenario(name).secure:
                todo.append(ALWAYS)
    return [s.name for s in SCENARIOS if s.name in wanted]














def load_localvm_fail():
    """localvm's own failure, which steps on its machines meet: one module per process."""
    return (load_localvm().Fail,)


def load_localvm():
    if "localvm" not in sys.modules:
        spec = importlib.util.spec_from_file_location("localvm", os.path.join(REPO, "tools", "localvm.py"))
        mod = importlib.util.module_from_spec(spec)
        sys.modules["localvm"] = mod
        spec.loader.exec_module(mod)
    return sys.modules["localvm"]


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
        self.m.secure_boot_warning()
        self.m.power_off()
        self.lv.snapshot(self.tag)
        commit = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        fd = os.open(self.path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"commit": commit, "fast_kdf": self.fast_kdf, "secrets": self.m.secrets, "luks_dev": getattr(self.m, "luks_dev", None),
                       "version": getattr(self.m, "version", None), "secure_boot": self.m.secure_boot_warning(),
                       "files": {n: open(os.path.join(self.m.dir, n)).read() for n in self.FILES}}, f)

    def problem(self):
        """Why this setup cannot be started from; None if it can."""
        if not os.path.exists(self.path()) or not os.path.isdir(self.lv.path("snap-" + self.tag)):
            how = "--save-setup" if self.tag == SETUP_SNAPSHOT else f"--only {SECURE_BOOT} --keep-setup"
            return f"{self.lv.name}: no snapshot {self.tag}: {how}"
        st = json.load(open(self.path()))
        if st.get("fast_kdf") != self.fast_kdf:
            return f"{self.lv.name}: the snapshot {self.tag} was made with fast_kdf={st.get('fast_kdf')}: its keyslots open with no other build"
        diff = subprocess.run(["git", "-C", REPO, "diff", "--name-only", st["commit"], "HEAD", "--", ".", ":!tools", ":!docs", ":!*.md", ":!*_test.go"],
                              capture_output=True, text=True)
        if diff.returncode != 0 or diff.stdout.strip():
            return f"{self.lv.name}: the snapshot {self.tag} is of {st['commit'][:7]}, and the product changed since: make it again"
        return None

    def restore(self):
        """Back to the snapshot, the machine stopped, what the test holds back."""
        why = self.problem()
        if why:
            raise Fail(why)
        self.lv.revert(self.tag)
        st = json.load(open(self.path()))
        self.m.secrets, self.m.luks_dev, self.m.version = st["secrets"], st["luks_dev"], st["version"]
        # Read from the machine at the setup: a boot's code screen comes before its ssh.
        self.m._secure_boot = st["secure_boot"]
        for n, body in st["files"].items():
            fd = os.open(os.path.join(self.m.dir, n), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(body)

    def drop(self):
        self.lv.kill()
        self.lv.drop_snapshot(self.tag)
        self.lv.drop_snapshot(HIBERNATED)
        if os.path.exists(self.path()):
            os.remove(self.path())












class Machine:
    def __init__(self, name, distro, host, user, password, luks_pass, run_dir, ssh_port=22, boot_port=SSH_PORT):
        self.name, self.distro, self.host, self.user = name, distro, host, user
        # The ports this side connects to: the machine's own 22 and SSH_PORT,
        # or what a port forward makes of them (tools/localvm.py).
        self.ssh_port, self.boot_port = ssh_port, boot_port
        self.password, self.luks_pass = password, luks_pass
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
        self.hib = None  # the hibernation steps (tools/hibernatetest.py), on tools/localvm.py's machines; set when a run has one
        self.resumed = False  # V2's resume ran, and no boot since
        self.done = []  # a scenario's name, budget, seconds and result: scenarios.json
        self.tpm_salt_keyslot = None  # the salt in this TPM's keyslot, while enrolled
        self.vault_keyslot = None  # the vault's keyslot now
        self.vault_device = None  # the name the vault knows this machine's device by now
        self.phone = None  # the emulator's Marify (Phone), in a run with --phone

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

    def check_vault_secure_boot(self, vault, name):
        """What the vault shows of this machine's Secure Boot, from the quote of its real
        PCR 7 and the real event log's digests: the state its variables say, read there
        with no word of the machine's. The tables and the audit, red in words where there
        is no colour (the fresh VMs are in Setup Mode)."""
        want = self.secure_boot_warning()
        if want is None:
            word, line = " on\n", "secure boot:     Secure Boot on"
        elif "Setup Mode" in want:
            word, line = "SETUP-MODE", "secure boot:     WARNING: Secure Boot in SETUP MODE"
        elif "off" in want:
            word, line = "OFF", "secure boot:     WARNING: Secure Boot OFF"
        else:
            word, line = "NOT-ESTABLISHED", "secure boot:     WARNING: Secure Boot NOT ESTABLISHED"
        out = vault.admin("devices")
        self.log.save("vault-devices.log", out)
        row = next((l for l in out.splitlines() if re.search(r"\s" + re.escape(name) + r"\s", l)), "")
        self.check(f"the vault's devices: Secure Boot established from the quote and the event log: {word.strip()}", re.search(r"\s" + word.strip() + r"\s*$", row) is not None, out[-400:])
        out = vault.admin("device", "show", name)
        self.log.save("vault-device.log", out)
        self.check(f"the vault's device view: {line.split('     ')[1]}", line in out, out[-400:])
        out = vault.admin("audit")
        self.log.save("vault-audit-secure-boot.log", out)
        rel = [l for l in out.splitlines() if "release" in l and "released" in l and name in l]
        self.check("the vault's audit: the release carries the state", bool(rel) and ("SECURE BOOT " + word.strip().replace("-", " ").upper()) in rel[-1].upper(), (rel or [out])[-1][-400:])

    def check_memory(self, where, out):
        """The process keeps nothing of Argon2id once a key is answered: the keyslot's
        own comes next, in an initrd without swap. What it says is the log of the floor
        (tools/LOCALVM.md, "Memory")."""
        said = re.findall(r"answered for \S+ \(\d+ bytes\); memory: heap (\d+) MiB, resident (\d+) MiB, peak (\d+) MiB, locked (\d+) MiB", out)
        self.log.say(f"{where}: {said}")
        self.check(f"{where}: run locked its memory and said so, once; the lock is on when the key is answered",
                   out.count("memory locked, not dumpable") == 1 and bool(said) and all(int(l) > 0 for _, _, _, l in said), f"{said}: " + out[-300:])
        self.check(f"{where}: the key answered, Argon2id's memory given back (heap and resident below 256 MiB, the peak one derivation's)",
                   bool(said) and all(int(h) < 256 and int(r) < 256 and int(p) < 1536 for h, r, p, _ in said), f"{said}: " + out[-300:])

    def check_secure_boot(self, where, out, least=1, most=1):
        """where says the state, plainly, between least and most times."""
        want = self.secure_boot_warning()
        n = out.count("WARNING: Secure Boot")
        if want is None:
            return self.check(f"{where}: says nothing of Secure Boot, which is on", n == 0, out[-400:])
        return self.check(f"{where}: says {want!r}, {least} time(s)" + ("" if most == least else f" to {most}"), least <= n <= most and (least == 0 or want in out), f"{n} time(s): " + out[-400:])

    def check_control_secure_boot(self, where, text, wants, session):
        """control judges Secure Boot's state on its own line, in red (the text is
        cleaned; the session's raw bytes keep the colour)."""
        state = self.secure_boot_warning()
        if state is None:
            return
        flat = re.sub(r"\s+", " ", re.sub(r"\x1b\[[0-9;]*m", "", text))
        want = next(v for k, v in wants.items() if k in state)
        red = re.search(rb"\x1b\[0;31m[^\n]*" + re.escape(want.split(" (risk")[0].encode()), session.buf) is not None
        self.check(f"{where} judges Secure Boot's state, in red: {want!r}", want in flat and red, flat[-800:])

    def check_control_proof(self, text):
        """The phone's and the vault's check on the running system's real PCR 7 and log: the state
        its variables say. A machine with systemd's OS separator is past it here, in no firmware's
        log (Debian's systemd has none yet)."""
        state = self.secure_boot_warning()
        want = "on: PCR 7" if state is None else "Setup Mode: PCR 7" if "Setup Mode" in state else "off: PCR 7"
        flat = re.sub(r"\s+", " ", re.sub(r"\x1b\[[0-9;]*m", "", text))
        _, log = self.run("grep -c '\"pcr\":7,.*os-separator' /run/log/systemd/tpm2-measure.log 2>/dev/null || true")
        past = log.strip().splitlines()[-1:] == ["1"]
        self.check(f"control: the proof on the running system ({'past' if past else 'no'} OS separator): {want!r}", f"Secure Boot's proof: {want}" in flat, flat[-800:])
        if self.distro == "arch":
            self.check("this machine is past the OS separator, in PCR 7", past, log[-200:])

    def session(self, remote_cmd, name, size=None):
        self.sessions += 1
        argv = ["ssh", "-tt", "-p", str(self.ssh_port), "-o", "StrictHostKeyChecking=accept-new", "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                f"{self.user}@{self.host}", remote_cmd]
        return Session(argv, os.path.join(self.dir, f"session-{self.sessions:02d}-{name}.log"), self.password, size)

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

    def command_status(self):
        """/proc/PID/status of the running tpm2-kira command, in KiB; empty when it is gone."""
        rc, out = self.run("cat /proc/$(pgrep -xn tpm2-kira)/status 2>/dev/null")
        return {k: int(v) for k, v in re.findall(r"^(Vm\w+):\s+(\d+) kB", out, re.M)}

    def check_memory_lock(self):
        """A command that holds a passphrase: what a refused lock does, what is locked,
        and on a machine with swap, at Argon2id's real cost and under memory pressure,
        that nothing of it goes there while other processes' pages do."""
        self.head("the memory of a command that holds a passphrase")
        key = "/run/tpm2-kira-lock-test/key"
        self.run("mkdir -m 700 /run/tpm2-kira-lock-test")
        rc, out = self.run(f"prlimit --memlock=65536:65536 setpriv --bounding-set=-ipc_lock --inh-caps=-ipc_lock tpm2-kira luks derive --out {key} </dev/null 2>&1", save="lock-refused.log")
        self.check("a limit on locked memory without CAP_IPC_LOCK stops the command before it asks",
                   "FAILED: nothing was asked" in out and "RLIMIT_MEMLOCK" in out and "Password" not in out, out[-400:])
        refuse = "prlimit --memlock=65536:65536 setpriv --bounding-set=-ipc_lock --inh-caps=-ipc_lock "
        for command in ("setup --local", "slot add --totp", "slot approve --unattended"):
            rc, out = self.run(f"{refuse}tpm2-kira {command} </dev/null 2>&1", save="lock-refused-" + command.split(" -")[0].replace(" ", "-") + ".log")
            self.check(f"{command}: a refused lock stops it before it reads a key", "FAILED: nothing was asked or read" in out and "RLIMIT_MEMLOCK" in out, out[-400:])
        for command in ("slot info", "status"):
            rc, out = self.run(f"{refuse}tpm2-kira {command} </dev/null 2>&1", save="lock-readers-" + command.replace(" ", "-") + ".log")
            self.check(f"{command} holds no secret: under such a limit it goes on", "nothing was asked" not in out and "RLIMIT_MEMLOCK" not in out, out[-400:])
        hook = "/etc/initramfs/post-update.d/tpm2-kira" if self.distro == "debian" else "/usr/lib/initcpio/post/sd-tpm2-kira"
        rc, out = self.run(f"{refuse}{hook} x x </dev/null 2>&1", save="lock-refused-hook.log")
        self.check("the image's hook under such a limit says the approval did not succeed, and the build would go on", rc == 0 and "RLIMIT_MEMLOCK" in out and "approval did not succeed" in out.lower(), out[-500:])
        swap = self.swap_counts()
        pressure = int(swap.get("SwapTotal:", "0")) > 0 and not self.fast_kdf
        hog = None
        s = self.session(f"sudo tpm2-kira luks derive --out {key}", "luks-derive")
        try:
            s.expect(r"^Password: ?$", 60)
            st = self.command_status()
            self.log.say(f"at the prompt: {st}")
            self.check("at the prompt the whole process is locked (VmLck, VmSize), nothing of it resident beyond what it touched",
                       st.get("VmLck", 0) * 10 >= st.get("VmSize", 1) * 9 and st.get("VmRSS", 1 << 30) < 128 << 10, str(st))
            if pressure:
                # All that is free but 512 MiB: Argon2id's 1 GiB then pushes out what can go.
                avail = int(self.run("awk '/^MemAvailable/{print int($2/1024)}' /proc/meminfo", root=False)[1].strip())
                n = avail - 512
                rc, out = self.run(f"""nohup perl -e '$x = "x"; $x x= {n} * 1048576; sleep 900' >/dev/null 2>&1 & echo $!""", root=False)
                hog = int(out.strip().splitlines()[-1])
                deadline = time.time() + 120
                while int(self.run(f"awk '/^VmRSS/{{print $2}}' /proc/{hog}/status 2>/dev/null || echo 0", root=False)[1].strip() or 0) < (n - 16) << 10:
                    if time.time() > deadline:
                        raise Fail(f"the memory hog of {n} MiB did not fill")
                    time.sleep(0.5)
            s.send(TEST_PASSWORD + "\n")
            s.expect(r"The same password again: ?$"); s.send(TEST_PASSWORD + "\n")
            s.expect(r"Salt \(asked for at boot the same way\): ?$"); s.send(TEST_SALT + "\n")
            samples, deadline = [], time.time() + 900
            while True:
                try:
                    s.expect(r"Key written to", 1)
                    break
                except Fail:
                    if s.closed or time.time() > deadline:
                        raise
                st = self.command_status()
                if st:
                    samples.append(st)
            peak = max((x.get("VmRSS", 0) for x in samples), default=0)
            locked = max((x.get("VmLck", 0) for x in samples), default=0)
            swapped = max((x.get("VmSwap", 0) for x in samples), default=-1)
            self.log.say(f"during Argon2id: {len(samples)} samples, resident {peak >> 10} MiB, locked {locked >> 10} MiB, in swap {swapped} kB")
            # A --fast-kdf derivation can end between two samples.
            if samples or not self.fast_kdf:
                self.check("during Argon2id nothing of the process is in swap (VmSwap, every sample)", bool(samples) and swapped == 0, str(samples[-3:]))
                self.check("during Argon2id the whole process stays locked", bool(samples) and locked * 10 >= samples[-1].get("VmSize", 1) * 9, str(samples[-3:]))
            if not self.fast_kdf:
                self.check("during Argon2id its 1 GiB is resident", peak >= 1000 << 10, f"{peak} kB")
            if pressure:
                after = self.swap_counts()
                self.log.say(f"swap under pressure: {swap} -> {after}")
                self.check("the pressure was real: other pages went to swap meanwhile", int(after["pswpout"]) > int(swap["pswpout"]), f"{swap} -> {after}")
            s.wait_end(120)
        except Fail as e:
            self.check("the locked command's checks ran", False, str(e))
        finally:
            s.close()
            if hog:
                self.run(f"kill {hog}", root=False)
            self.run("rm -rf /run/tpm2-kira-lock-test")
        rc, out = self.run("dmesg | grep -E 'Out of memory|oom-kill' | head -3")
        self.check("nothing was killed for memory by the pressure", "Out of memory" not in out and "oom-kill" not in out, out[-400:])

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

    def seal(self):
        self.head("setup and slot add")
        rc, out = self.run("tpm2-kira setup --local 2>&1", save="setup.log")
        self.check("setup --local makes the signing key", "Setup Complete" in out, out[-400:])
        rc, out = self.run("tpm2-kira slot add --totp 2>&1", save="slot-add.log")
        added_at = time.time()
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
        # slot add shows each new slot's first code while the TPM computes one, in a boot not
        # closed yet: the code an authenticator of its secret shows; otherwise why there is none.
        firsts = re.findall(r"^(?:The slot's code now: (\d{6})|No code in this boot: (.*)\.)", out, re.M)
        last = self.slots[-1]
        if len(firsts) == len(self.slots) and firsts[-1][0]:
            self.check(f"slot add: slot {last}'s first code is the authenticator's (computed from its secret)", code_matches(self.secrets[last], firsts[-1][0], added_at), out[-600:])
        else:
            # The running system is closed (PCR 15), or past the OS separator, or the slot's image
            # is predicted for the next boot (an image rebuilt since this one): no code until then.
            self.check(f"slot add: slot {last}: its first code, or why none until the next boot", len(firsts) == len(self.slots), out[-600:])

    def inspect(self):
        self.head("the commands that read")
        cmds = {
            "slot status": ("tpm2-kira slot status --nvram 0 2>&1", r"Slot 0 \(0x01803010\)\n  Record: EFI variable KIRAslot0-"),
            "phone ekcert": ("tpm2-kira phone ekcert 2>&1", r"EK certificate:"),
            "luks status": ("tpm2-kira luks status 2>&1", re.escape(self.luks_dev)),
        }
        for name, (cmd, want) in cmds.items():
            rc, out = self.run(cmd, save="cmd-" + name.split(" (")[0].replace(" ", "-") + ".log")
            self.check(f"'{name}' answers", re.search(want, out) is not None, out[-400:])
        rc, out = self.run("tpm2-kira status 2>&1")
        self.check_secure_boot("status", out)
        rc, out = self.run(f"tpm2-kira luks enrol {self.luks_dev} --password tpm --salt vault --url https://vault.invalid --pin sha256:{'0' * 64} --token none 2>&1", save="luks-enrol-vault-not-on.log")
        self.check("a vault's keyslot on a machine not on Secure Boot: says the vault releases nothing, and to keep a recovery keyslot", "releases nothing to this machine until Secure Boot is on" in out and "recovery keyslot" in out, out[-500:])
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
            # What the keyslot's own Argon2id takes at boot, after Combine's: for the floor.
            self.run(f"cryptsetup luksDump {self.luks_dev} | grep -E '^  [0-9]+: luks2|Memory:|Time cost|Threads'", save="luks-keyslots.log")
        except Fail as e:
            self.check("luks enrol adds a keyslot of the recovery recipe (0x1100)", False, str(e))
            raise
        finally:
            s.close()

    def control(self):
        self.head("control, answered line by line")
        s = self.session("sudo tpm2-kira control", "control")
        menu = r"Enter a number between 1 and \d+: ?$"
        try:
            # Step 1: every open adoption, written when asked; then on.
            first = True
            for _ in range(10):
                text, _ = s.expect(menu, 120)
                if first:
                    first = False
                    self.check_control_proof(text)
                    self.check_control_secure_boot("control step 1", text, {"Setup Mode": "Setup Mode (risk: nothing checks the boot chain", "off": "disabled (risk: nothing checks", "could": "state unknown,"}, s)
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
            pick(r"^On \(recommended\)$")
            self.check("control: the boot image's network, DHCP on " + mac[-1] + ", announced", True)

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
            if self.distro == "debian":
                self.check("the image's scripts have no ordering loop (tsort, in the image's build)", "input contains a loop" not in out, out[-800:])
            self.check("control rebuilds the image, and the hook approves the new boot state",
                       "approved the boot state" in out or "approval completed successfully" in out, out[-800:])
        except Fail as e:
            self.check("control, answered line by line", False, str(e))
            raise
        finally:
            s.close()

    def control_keys(self):
        """control on a real terminal of 24 rows and 40 columns: its menu by the arrow keys,
        drawn and left in place over ssh, and the terminal given back. The session of
        control() has no size, and so the numbered prompt."""
        self.head("control's menu by the arrow keys")
        s = self.session("sudo tpm2-kira control; stty -a", "control-keys", size=(24, 40))
        menu = r"Enter a number between 1 and \d+: ?$"
        try:
            s.expect(menu, 120)
            s.send("\x1b[B"); s.expect(menu, 10)
            s.send("\x1b[A"); s.expect(menu, 10)
            raw = s.buf
            self.check("control: on a terminal with a size the menu is drawn with the cursor", b"\x1b[7m" in raw and b"\x1b[J" in raw, repr(raw[-400:]))
            s.send("\r")
            out = s.wait_end(60)
            self.log.save("control-keys.log", out)
            self.check("control: Enter takes the entry under the cursor, the default, and the answer stays", re.search(r"^> \d+\.\s+Quit", out, re.M) is not None, out[-600:])
            self.check("control: the terminal is given back after the menu", re.search(r"(?<![-\w])icanon\b", out) is not None and re.search(r"(?<![-\w])echo\b", out) is not None, out[-600:])
        except Fail as e:
            self.check("control's menu by the arrow keys", False, str(e))
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
        order = "sed -n 's#^/scripts/local-top/\\([^ ]*\\) .*#ORDER \\1#p' scripts/local-top/ORDER; " if self.distro == "debian" else (
            "ls usr/lib/systemd/system/cryptsetup-pre.target; "
            "systemd-analyze verify --root=$PWD initrd.target tpm2-kira-close.service tpm2-kira.service tpm2-kira-unlock.socket 2>&1 | grep -i 'cycle' | sed 's/^/CYCLE /' || true; ")
        rc, out = self.run(f"set -e; d=$(mktemp -d); cd $d; {listing}; ls usr/bin | grep kira; "
                           "find etc/tpm2-kira -maxdepth 2 | sort; ls etc/tpm2-kira/control.conf 2>&1 || true; "
                           "grep -rlE 'tpm2-kira-boot gate|tpm2-kira-attest' etc usr/lib/systemd scripts 2>/dev/null | sed 's/^/STARTS-GATE /'; "
                           f"{order}cd /; rm -rf $d", save="image.log")
        bins = [l for l in out.split("\n") if l.strip().startswith("tpm2-kira")]
        self.check("the image carries tpm2-kira-boot", "tpm2-kira-boot" in bins, out[-500:])
        self.check("the image carries no tpm2-kira (the administration)", "tpm2-kira" not in bins, str(bins))
        self.check("the image carries no control.conf", "No such file" in out or "cannot access" in out, out[-300:])
        self.check("no unit or script of the image starts a gate: run starts its children itself", "STARTS-GATE" not in out, out[-300:])
        for part in ("unlock", "codes", "net", "ssh", "tpm"):
            self.check(f"the image's plan names '{part}'", f"etc/tpm2-kira/plan/{part}" in out, out[-500:])
        if self.distro == "debian":
            scripts = re.findall(r"^ORDER (\S+)$", out, re.M)
            self.check("the image's local-top closes before cryptroot, and cryptroot is last",
                       "tpm2-kira-close" in scripts and scripts[-1:] == ["cryptroot"], str(scripts))
        else:
            self.check("the image carries cryptsetup-pre.target", "usr/lib/systemd/system/cryptsetup-pre.target" in out, out[-500:])
            self.check("systemd-analyze verify of the image's units finds no ordering cycle", "CYCLE" not in out, out[-500:])

    def code_screen(self, n, s, console_from, timeout=60):
        """The code screen of a boot's SSH session: certified, each slot's code the
        authenticator's, Secure Boot said once in the session and at the console. Its text."""
        text, _ = s.expect(r"Does the code match your authenticator\?.*$", timeout)
        at = time.time()
        self.lap("the code screen over SSH")
        codes = dict(re.findall(r"^#(\d+): (\d{6})$", text, re.M))
        self.check(f"boot {n}: the host key is certified by the SSH CA (strict known_hosts)", True)
        for slot in self.slots:
            self.check(f"boot {n}: slot {slot}'s code is the authenticator's", str(slot) in codes and code_matches(self.secrets[slot], codes[str(slot)], at), text[-500:])
        self.check_secure_boot(f"boot {n}: the SSH session, at its start", text)
        lv = getattr(self, "lv", None)
        if lv:
            # The console shows the session's screen too: the codes, the
            # network's line, and that Enter there continues at the console.
            want = (r"^#\d+: \d{6}\s*$", r"Network \((DHCP|static)\)[^\n]* on ", r"Enter here: continue to .* at this console")
            console, deadline = "", time.time() + 15
            while time.time() < deadline:
                console = lv.serial_text(console_from)
                if all(re.search(w, console, re.M) for w in want):
                    break
                time.sleep(0.5)
            self.check(f"boot {n}: the console shows the codes, the network's line and Enter there, as the session does",
                       all(re.search(w, console, re.M) for w in want), console[-600:])
            self.check_secure_boot(f"boot {n}: the console", lv.serial_text(console_from))
        return text

    def console_mark(self):
        """Where this boot's text will start on the console."""
        lv = getattr(self, "lv", None)
        return os.path.getsize(lv.path("serial.log")) if lv else 0

    def warm_reboot(self):
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        self.lap("the system going down")

    def cycle(self, n, started=False):
        """A boot unlocked over SSH, with its checks; started: the machine was
        started by the caller, nothing to reboot."""
        self.head(f"reboot {n}: the code screen over SSH, unlocked there")
        lv = getattr(self, "lv", None)
        console_from = getattr(lv, "mark", 0)
        if not started:
            console_from = self.console_mark()
            self.warm_reboot()
        if not self.check(f"boot {n}: the boot SSH server answers (port {SSH_PORT})", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server: the console shows why")
        self.lap("firmware to the boot SSH server")
        s = self.boot_session(n)
        try:
            text = self.code_screen(n, s, console_from)
            self.check(f"boot {n}: the screen names tpm2-kira's password and salt prompt", "continue to the password and salt prompt" in text, text[-300:])
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
        got = self.after_boot(n)
        out = got["log"]
        self.check(f"boot {n}: the boot's log follows the network until it has an address",
                   re.search(r"network: Network \(DHCP\): \S+ on ", out) is not None, out[-500:])
        self.check(f"boot {n}: the address was announced to the neighbours (TPM2_KIRA_NET_ANNOUNCE)",
                   re.search(r"network: announced \S+ on \S+ to the neighbours", out) is not None, out[-500:])

    # PID 1's lines alone: sudo's log of this very command names the words too.
    VOLUME_ORDER = ("journalctl -b -o cat --no-pager -u tpm2-kira-close.service -u 'systemd-cryptsetup@*' | grep -E '^(Starting|Finished) '; "
                    "journalctl -b -o cat --no-pager _PID=1 | grep -iE 'ordering cycle|Found dependency on' | sed 's/^/CYCLE /'; true")

    def check_volume_order(self, where, out):
        """Arch: the close's unit is done before a volume's unit starts, and this boot's systemd
        found no cycle: the journal, in its order, with what the generator wrote too."""
        lines = out.splitlines()
        done = next((i for i, l in enumerate(lines) if l.startswith("Finished tpm2-kira: the boot closed")), None)
        volume = next((i for i, l in enumerate(lines) if l.startswith("Starting Cryptography Setup")), None)
        self.check(f"{where}: the close is done before a volume's unit starts", done is not None and volume is not None and done < volume, out[-600:])
        self.check(f"{where}: no ordering cycle in this boot's journal", "CYCLE " not in out, out[-300:])

    def check_debian_order(self, where, log, run_closed=True):
        """Debian: in the boot's log, run's close, the image's in local-top, the first key
        request: nothing asks before the close, and the close does not come before the code
        screen is over. run_closed: run's close held (a TPM that answers)."""
        close = log.find("the image's close: before any volume")
        key = log.find("keyscript for")
        self.check(f"{where}: the image's close comes before the first key request", 0 <= close < key, log[-600:])
        if run_closed:
            self.check(f"{where}: the image's close comes when the code screen is over, after run's",
                       0 <= log.find("the boot is closed (PCR 15)") < close, log[-600:])

    def boot_log_command(self):
        return ("cat /run/initramfs/tpm2-kira.log" if self.distro == "debian" else
                "journalctl -b -o cat --no-pager -t tpm2-kira -u tpm2-kira.service -u tpm2-kira-machine-id.service")

    def batch(self, commands):
        """Every command of a dict, in one ssh command as root, each one's output and
        error apart: what a boot reads costs one connection. save: the file for a name."""
        script = "; ".join(f"echo {BATCH_MARK}{name}; {{ {cmd.rstrip('; ')}; }} 2>&1" for name, (cmd, _) in commands.items())
        rc, out = self.run(script)
        parts = re.split(rf"^{BATCH_MARK}(\S+)\n", out, flags=re.M)
        got = dict(zip(parts[1::2], parts[2::2]))
        missing = [name for name in commands if name not in got]
        if missing:
            raise Fail(f"the commands of a boot did not run ({', '.join(missing)}):\n" + out[-500:])
        for name, (_, save) in commands.items():
            if save:
                self.log.save(save, got[name])
        return got

    def after_boot(self, n):
        """Everything a boot's running system is checked for, read at once."""
        self.wait_login(f"boot {n}")
        slot0, slot1 = ("0,2,4,7,8,9", "7,8,9") if self.distro == "debian" else ("0,2,4,7", "7")
        commands = {
            "oom": ("dmesg | grep -E 'Out of memory|oom-kill' | head -3", f"oom-boot-{n}.log"),
            "status": ("tpm2-kira status --json", f"status-boot{n}.json"),
            "log": (self.boot_log_command(), f"boot{n}-tpm2-kira.log"),
            # The boot is closed in the running system: PCR 15 extended (the kernel's sysfs
            # view of the TPM's PCRs), by run and the image's close when the code screen was
            # over (Arch: tpm2-kira-close.service).
            "close": ("cat /sys/class/tpm/tpm0/pcr-sha256/15 2>&1; " + ("true" if self.distro == "debian" else
                      "journalctl -b -o cat --no-pager -u tpm2-kira-close.service 2>&1 | tail -5"), f"boot{n}-close.log"),
            "cap": ("ls /usr/lib/systemd/system/tpm2-kira-cap.service 2>&1; grep -c 'tpm2-kira-boot cap' /usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira 2>&1; true", None),
            "state": ("cat /run/tpm2-kira/close-state; ls /run/tpm2-kira/close-pending 2>&1; systemctl is-active tpm2-kira-late-close.service; ls /sys/firmware/efi/efivars | grep -c KIRAcloseReboot; true", f"boot{n}-close-state.log"),
            "ca": ("grep '^ASSH_CA_SLOT_[0-9]' /etc/tpm2-kira/assh.conf 2>&1", f"boot{n}-ca-slots.log"),
            # PCR 4 was predicted before this boot, for this boot: the approval
            # holds the prediction, the register what the firmware measured.
            "pcr4": ("tpm2-kira slot info --nvram 0 2>&1; echo LIVE=$(cat /sys/class/tpm/tpm0/pcr-sha256/4)", f"boot{n}-pcr4.log"),
        }
        if self.distro != "debian":
            commands["volume-order"] = (self.VOLUME_ORDER, f"boot{n}-volume-order.log")
            commands["pcr11"] = ("tpm2-kira slot info --nvram 0 2>&1 | grep -E 'PCR 11 ' | head -2; stat -c '%a %U' /etc/tpm2-kira/pcr.key; grep -c '^Phases=enter-initrd$' /etc/kernel/uki.conf", f"boot{n}-pcr11.log")
        got = self.batch(commands)
        self.lap("what the boot's system is checked for, read")
        self.check(f"boot {n}: nothing was killed for memory", "Out of memory" not in got["oom"] and "oom-kill" not in got["oom"], got["oom"][-400:])
        out = got["status"]
        try:
            slots = json.loads(out).get("slots", [])
        except ValueError:
            slots = []
        self.check(f"boot {n}: every slot is closed until the next boot (PCR 15)", slots and all("closed until the next boot" in s["generation_state"] for s in slots), out[-300:])
        if self.distro == "debian":
            self.check(f"boot {n}: GRUB - every slot includes PCRs 8 and 9", slots and not any(s.get("no_grub_pcrs") for s in slots), out[-300:])
        out = got["log"]
        self.check(f"boot {n}: run closed the boot when the code screen was over", "the boot is closed (PCR 15)" in out, out[-500:])
        self.check_secure_boot(f"boot {n}: the boot's log", out)
        self.check(f"boot {n}: the key was answered", re.search(r"unlock: answered for", out) is not None, out[-500:])
        if self.distro == "debian":
            self.check_debian_order(f"boot {n}", out)
        self.check_memory(f"boot {n}", out)
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
        out = got["close"]
        pcr15 = out.split("\n")[0].strip()
        self.check(f"boot {n}: the boot is closed in the running system (PCR 15 extended)",
                   re.fullmatch(r"[0-9A-Fa-f]{64}", pcr15) is not None and set(pcr15) != {"0"}, out[-300:])
        if self.distro != "debian":
            self.check(f"boot {n}: tpm2-kira-close.service ran in the initrd", "Finished" in out and "Failed" not in out, out[-300:])
            self.check_volume_order(f"boot {n}", got["volume-order"])
        # No cap: PCR 15 closes the slots.
        state, out = got["state"], got["cap"]
        self.check(f"boot {n}: the close is PCR 15's, no late closer, no reboot counted", state.startswith("closed") and "No such file" in state and "inactive" in state and re.search(r"^0$", state, re.M) is not None, state)
        self.check(f"boot {n}: no cap unit or cap step", "No such file" in out.split("\n")[0] and not re.search(r"^[1-9]", out, re.M), out.strip())
        # One rule: PCR 7 and the image; slot 0 with the platform. On a UKI
        # the image is PCR 11, signed by the PCR key.
        out = got["ca"]
        ok = re.search(rf"^ASSH_CA_SLOT_0={slot0}$", out, re.M) is not None and re.search(rf"^ASSH_CA_SLOT_1={slot1}$", out, re.M) is not None
        if self.distro != "debian":
            ok = ok and "ASSH_CA_SLOT_0_SIGNED=11" in out and "ASSH_CA_SLOT_1_SIGNED=11" in out
        self.check(f"boot {n}: the SSH CA's slots are {slot0} and {slot1}" + ("" if self.distro == "debian" else ", each with PCR 11 signed"), ok, out.strip())
        if self.distro != "debian":
            out = got["pcr11"]
            self.check(f"boot {n}: slot 0's PCR 11 is signed, the PCR key root's alone, uki.conf signs enter-initrd", "(signed)" in out and "400 root" in out and re.search(r"^1$", out, re.M) is not None, out[-400:])
        out = got["pcr4"]
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
        return got

    def after_resume_boot(self, text):
        """The first boot after V2's resume, whatever it is for: V7 of the hibernate test."""
        if self.resumed:
            self.resumed = False
            self.check("V7: a normal reboot after the resume: the host key is certified again (strict known_hosts)", "Does the code match" in text, text[-300:])

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
        self.lap("the image built (mkinitcpio -P, without the hook)")
        self.warm_reboot()
        if not self.check("unapproved: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server on the unapproved image")
        s = self.boot_session("unapproved")
        try:
            text, _ = s.expect(r"Does the code match your authenticator\?.*$", 60)
            at = time.time()
            self.after_resume_boot(text)
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

    def vault_root(self, vault):
        """Without a root of the vault the enrolment is refused before the vault is asked; the
        root comes over as an operator brings it."""
        rc, out = self.run("tpm2-kira luks enrol " + self.luks_dev + " --password tpm --salt vault --url " + vault.url +
                           " --pin sha256:" + "0" * 64 + " --token none 2>&1", save="luks-enrol-vault-no-root.log")
        self.check("luks enrol without a root of the vault is refused, naming --ca", "no root certificate of a vault" in out and "--ca FILE" in out, out[-400:])
        self.check("with Secure Boot on it says nothing of a recovery keyslot", "releases nothing" not in out, out[-400:])
        self.run(f"echo {base64.b64encode(vault.root.encode()).decode()} | base64 -d > {self.CA_FILE}")

    def vault_token(self, vault, name):
        out = vault.admin("token", "create", "--name", name)
        self.log.save(f"vault-token-{name}.log", out)
        m = re.search(r"--url (\S+) --pin (\S+) --token (\S+)", out)
        if not self.check("the vault makes an enrolment token", m is not None, out[-400:]):
            raise Fail("no token")
        return m.groups()

    def vault_leave(self, vault):
        """The keyslot the vault has now goes, and its device: unenrolled, the slot's attestation
        part went with the vault, the next enrolment is a new device. The old one is revoked, as
        the unenrol says, by its ID."""
        rc, out = self.run("tpm2-kira vault unenrol --nvram 0 2>&1", save=f"vault-unenrol-{self.vault_device}.log")
        m = re.search(r"tpm2-kira-vault device revoke ([0-9a-f]+)", out)
        if not self.check("vault unenrol: the slot's vault method is gone", m is not None, out[-400:]):
            raise Fail("vault unenrol")
        self.luks_remove(self.vault_keyslot, f"luks-remove-{self.vault_device}")
        out = vault.admin("device", "revoke", m.group(1))
        self.check("the vault revokes the old device by its ID", "revoked" in out, out[-300:])

    def vault_alone(self):
        """The unattended recipe (0x2400): a boot nobody touches, the vault's release to the TPM's
        quote of the approved boot state ends the hold by itself."""
        vault = self.vault_of_run
        self.head("remote attestation over TLS: the vault alone")
        self.vault_leave(vault)
        url, pin, token = self.vault_token(vault, self.name)
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --password tpm --salt vault --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {self.name}", "luks-enrol-vault")
        try:
            s.expect(r"to authorise: ?$", 300); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x240[01] ", 300)
            self.vault_keyslot, self.vault_device = m.group(1), self.name
            s.wait_end(120)
            self.check("luks enrol 0x2400: the vault knows the device, a keyslot is added", True)
        except Fail as e:
            self.check("luks enrol 0x2400", False, str(e))
            raise
        finally:
            s.close()
        out = self.rebuild()
        self.check("the image is rebuilt with the vault in its plan", re.search(r"Vault:\s+in", out) is not None, out[-800:])

        self.head("a boot unlocked by the vault alone")
        self.run("systemctl reboot")
        self.wait_port(22, False, 120)
        self.lap("the system going down")
        up = self.wait_port(22, True, 420)
        self.lap("nobody at the machine, to ssh")
        if not self.check("the vault's boot: the system comes up with nobody at the console or in SSH", up):
            raise Fail("the vault's boot did not come up")
        self.booted("the vault's boot")
        out = self.boot_log("boot-vault-tpm2-kira.log")
        self.check("the vault released the remote part; the key was made", "released; the key is made" in out, out[-600:])
        self.check("the key was answered", "unlock: answered for" in out, out[-600:])

    def revoked(self):
        """The boot after the pepper's, with no image built and nothing approved in between: the
        second real boot of one approval, so boot 2's checks run on it. Its device revoked: no
        release, and what follows the vault in the recipes' order takes over, over SSH: the salt in
        this TPM, opened while the code screen holds, the password alone typed. That keyslot goes after."""
        vault = self.vault_of_run
        self.head("a boot with the device revoked on the vault and the salt in this TPM (boot 2)")
        vault.admin("device", "revoke", self.vault_device)
        console_from = self.console_mark()
        self.warm_reboot()
        if not self.check("revoked: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
            raise Fail("no boot SSH server")
        self.lap("firmware to the boot SSH server")
        s = self.boot_session("revoked")
        try:
            text = self.code_screen(2, s, console_from, 120)
            self.check("revoked: the screen names the fallback", "the password prompt if the vault gives no key" in text, text[-400:])
            self.check("TPM salt: the screen names the password prompt", "continue to the password prompt" in text, text[-300:])
            s.send("\r")
            text, _ = s.expect(r"(Password|Salt) for disk \S+: ?$", 300)
            self.check("revoked: tpm2-kira says the vault gave no key and asks the keyslot after it", "no key from the vault" in text and "revoked" in text, text[-500:])
            self.check("TPM salt: the password is asked with the salt this TPM opened", "Password for disk" in text.split("\n")[-1] and "the salt this TPM opened" in text, text[-500:])
            if "Salt for disk" in text.split("\n")[-1]:
                raise Fail("asked for a typed salt: " + text[-300:])
            s.send(TPM_SALT_PASSWORD + "\r")
            self.lap("the prompt")
            rest = s.wait_end(600)
            self.lap("password typed to the initrd's end (Argon2id, the keyslot)")
            self.check("boot 2: the session ends with the server's last line ('The machine boots; ...')",
                       "The machine boots; the SSH server stops." in rest, rest[-300:])
        except Fail as e:
            self.check("revoked: the fallback over SSH", False, str(e))
            raise
        finally:
            s.close()
        up = self.wait_port(22, True, 300)
        self.check("TPM salt: the disk unlocks with the password alone", up)
        self.check("boot 2: the system comes up (ssh)", up)
        if not up:
            raise Fail("the revoked boot did not come up")
        self.lap("the initrd's end to ssh")
        got = self.after_boot(2)
        out = got["log"]
        self.check("revoked: the vault refused, the key was answered from the keyslot after it", "the device is revoked" in out and "unlock: answered for" in out, out[-600:])
        self.check("TPM salt: opened while the code screen held, the key answered", "tpm salt: slot 0: opened" in out and "unlock: answered for" in out, out[-600:])
        vault.admin("device", "unrevoke", self.vault_device)
        self.tpm_salt_removed()

    PEPPER = "vmtest pepper 7f3a"

    def vault_pepper(self):
        """The first recipe of the vault's: an enrolment without its root refused, then an
        operator's pepper: a boot nobody touches waits for an approval; a wrong pepper is caught by
        the slot's pepper check and a new approval asked; the right one unlocks. The pepper reaches
        the machine wrapped for its TPM, opened through the slot's approval like R."""
        vault = self.vault_of_run
        self.head("the vault with an operator's pepper")
        self.vault_root(vault)
        name = self.name + "-pepper"
        url, pin, token = self.vault_token(vault, name)
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --password tpm --salt vault --pepper --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {name}", "luks-enrol-vault-pepper")
        try:
            s.expect(r"Pepper \(the operator gives it with every approval on the vault\): ?$", 300); s.send(self.PEPPER + "\n")
            s.expect(r"The same pepper again: ?$", 60); s.send(self.PEPPER + "\n")
            s.expect(r"to authorise: ?$", 300); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x240[01] ", 300)
            self.vault_keyslot, self.vault_device = m.group(1), name
            text = s.wait_end(120)
            self.check("luks enrol --pepper: a keyslot that waits for an operator", "approves it on the vault with the pepper" in text, text[-400:])
        except Fail as e:
            self.check("luks enrol 0x2401 (pepper)", False, str(e))
            raise
        finally:
            s.close()
        out = vault.admin("devices")
        self.check("the vault lists the device", name in out, out[-400:])
        rc, out = self.run("cat /etc/tpm2-kira/vault-ca.pem 2>&1")
        self.check("--ca put the vault's root into /etc/tpm2-kira/vault-ca.pem", out.strip() == vault.root.strip(), out[-300:])
        out = vault.admin("device", "show", name)
        self.check("the vault's device needs a pepper and waits for approvals", "pepper:          yes" in out and "approve" in out, out[-400:])
        out = self.rebuild()
        self.check("the image is rebuilt with the vault in its plan", re.search(r"Vault:\s+in", out) is not None, out[-800:])
        if self.tpm_salt_keyslot:
            self.tpm_salt_in_image(out)

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
        out = self.boot_log("boot-vault-pepper-tpm2-kira.log")
        self.check("the wrong pepper did not fit the slot's pepper check", "does not fit this keyslot" in out, out[-600:])
        self.check("with the right pepper the key was made and answered", "released; the key is made" in out and "unlock: answered for" in out, out[-600:])
        self.check_memory("the pepper's boot, two derivations", out)
        out = vault.admin("audit")
        self.log.save("vault-audit-pepper.log", out)
        self.check("the vault's audit: released with a pepper, the pepper itself nowhere",
                   "with a pepper" in out and self.PEPPER not in out and "not the pepper" not in out, out[-600:])
        self.check_vault_secure_boot(vault, name)

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
            self.after_resume_boot(text)
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
        """The salt in this TPM (0x1200): enrolled, named by luks status and luksDump. The image
        that takes it is vault-pepper's, its boot the revoked one, where it goes again."""
        self.head("the salt in this TPM (0x1200)")
        swap = self.swap_counts()
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt tpm", "luks-enrol-tpm-salt")
        try:
            s.expect(r"Password \(typed at the machine at every boot\): ?$", 300); s.send(TPM_SALT_PASSWORD + "\n")
            s.expect(r"The same password again: ?$", 60); s.send(TPM_SALT_PASSWORD + "\n")
            s.expect(r"to authorise: ?$", 600); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1200 ", 300)
            self.tpm_salt_keyslot = m.group(1)
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

    def tpm_salt_in_image(self, out):
        """What a rebuild with the salt in this TPM enrolled says."""
        self.check("the image is rebuilt with the TPM salt in its plan", re.search(r"TPM salt:\s+in", out) is not None, out[-800:])
        # The image's hook says it, once per image built; its approval does not again.
        images = out.count("Starting build:") if self.distro == "arch" else 1
        n = len(re.findall(r"Secure Boot (is|'s state)", out))
        self.check(f"the image's hook says Secure Boot's state once per image built ({images})", n == images if self.secure_boot_warning() else n == 0, out[-800:])

    def tpm_salt_removed(self):
        out = self.luks_remove(self.tpm_salt_keyslot, "luks-remove-tpm-salt")
        self.check("luks remove takes the TPM salt's keyslot", "0x1200" not in out, out[-400:])
        rc, out = self.run("tpm2-kira status --json 2>&1")
        self.check("the TPM salt went with its last keyslot", '"tpm_salt": true' not in out, out[-400:])
        self.tpm_salt_keyslot = None

    def vault_typed(self):
        """The vault's salt with a typed password and a pepper (0x1401): the keyslot the vault has
        goes, the device enrolled again; at boot an operator approves on the vault's CLI (requests
        answer, the pepper on its stdin) while the code screen holds, the vault releases the salt,
        and the password alone is asked after the code screen."""
        vault = self.vault_of_run
        self.head("the vault's salt with a typed password and a pepper (0x1401)")
        self.vault_leave(vault)
        name = self.name + "-typed"
        url, pin, token = self.vault_token(vault, name)
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt vault --pepper --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {name}", "luks-enrol-vault-typed")
        try:
            s.expect(r"Pepper \(the operator gives it with every approval on the vault\): ?$", 300); s.send(self.PEPPER + "\n")
            s.expect(r"The same pepper again: ?$", 60); s.send(self.PEPPER + "\n")
            s.expect(r"Password \(typed at the machine at every boot\): ?$", 60); s.send(VAULT_PASSWORD + "\n")
            s.expect(r"The same password again: ?$", 60); s.send(VAULT_PASSWORD + "\n")
            s.expect(r"to authorise: ?$", 600); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1401 ", 300)
            self.vault_keyslot, self.vault_device = m.group(1), name
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

    KB_PEPPER = "vmtest9pepper"

    def vault_layout(self, vault, name, seen=(), timeout=120):
        """The one-time layout the vault's CLI shows for the latest release of name, none of seen: key
        -> what it types."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = vault.admin("requests")
            at = out.rfind("of " + name + ": type the pepper through this layout")
            if at >= 0:
                layout = {}
                lines = out[at:].splitlines()[1:9]
                for keys, types in zip(lines[0::2], lines[1::2]):
                    k, t = keys.split()[1:], types.split()[1:]
                    if len(k) != len(t) or keys.split()[0] != "key" or types.split()[0] != "types":
                        return None
                    layout.update(zip(k, t))
                if len(layout) != 36:
                    return None
                if layout not in seen:
                    return layout
            time.sleep(1)
        return None

    def vault_keyboard(self):
        """A pepper typed through the vault's one-time keyboard (0x1402): the layout the vault's CLI
        shows, the pepper typed through it at the prompt over SSH; one not of the layout's form is
        asked for again. A second boot's layout is another, and neither layout nor pepper is in the
        audit."""
        vault = self.vault_of_run
        self.head("a pepper typed through the vault's one-time keyboard (0x1402)")
        self.vault_leave(vault)
        name = self.name + "-keyboard"
        url, pin, token = self.vault_token(vault, name)
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt vault --keyboard-pepper --url {url} --pin {pin} --token {token} --ca {self.CA_FILE} --name {name}", "luks-enrol-vault-keyboard")
        try:
            s.expect(r"Password \(typed at the machine at every boot\): ?$", 300); s.send(VAULT_PASSWORD + "\n")
            s.expect(r"The same password again: ?$", 60); s.send(VAULT_PASSWORD + "\n")
            s.expect(r"Pepper: ?$", 60); s.send(self.KB_PEPPER + "\n")
            s.expect(r"The same pepper again: ?$", 60); s.send(self.KB_PEPPER + "\n")
            s.expect(r"to authorise: ?$", 600); s.send(self.luks_pass + "\n")
            _, m = s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1402 ", 300)
            self.vault_keyslot, self.vault_device = m.group(1), name
            s.wait_end(120)
            self.check("luks enrol --salt vault --keyboard-pepper: a keyslot of recipe 0x1402", True)
        except Fail as e:
            self.check("luks enrol --keyboard-pepper", False, str(e))
            raise
        finally:
            s.close()
        rc, out = self.run("tpm2-kira status 2>&1", save="status-vault-keyboard.log")
        self.check("status: the keyboard's recipe", "pepper typed through a one-time keyboard" in out, out[-500:])

        layouts = []
        for boot in (1, 2):
            self.head(f"boot {boot} through the vault's keyboard")
            self.run("systemctl reboot")
            self.wait_port(22, False, 120)
            if not self.check(f"keyboard {boot}: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
                raise Fail("no boot SSH server")
            s = self.boot_session(f"keyboard-{boot}")
            try:
                text, _ = s.expect(r"Does the code match your authenticator\?.*$", 120)
                self.after_resume_boot(text)
                layout = self.vault_layout(vault, name, layouts)
                if not self.check(f"keyboard {boot}: the vault's CLI shows a layout of the 36 keys", layout is not None and sorted(layout.values()) == sorted(layout.keys())):
                    raise Fail("no layout shown")
                layouts.append(layout)
                typed = "".join(next(k for k, t in layout.items() if t == c) for c in self.KB_PEPPER)
                s.send("\r")
                text, _ = s.expect(r"Password for disk \S+: ?$", 300)
                self.check(f"keyboard {boot}: the prompt says to type the pepper through the vault's layout", "layout the vault shows" in text, text[-500:])
                s.send(VAULT_PASSWORD + "\r")
                s.expect(r"Pepper for disk \S+: ?$", 60)
                s.send("ab-cd\r")
                text, _ = s.expect(r"Pepper for disk \S+: ?$", 60)
                self.check(f"keyboard {boot}: what is no pepper is asked for again", "not a pepper" in text, text[-400:])
                s.send(typed + "\r")
                s.wait_end(600)
            finally:
                s.close()
            if not self.check(f"keyboard {boot}: the disk opens with password, salt and the pepper through the layout", self.wait_port(22, True, 300)):
                raise Fail("the keyboard's boot did not come up")
            self.booted(f"keyboard {boot}")
        self.check("the second boot's layout is another", len(layouts) == 2 and layouts[0] != layouts[1], str(len(layouts)))
        out = vault.admin("audit")
        self.log.save("vault-audit-keyboard.log", out)
        shown = ["".join(l[k] for k in "abcdefghijklmnopqrstuvwxyz0123456789") for l in layouts]
        self.check("the vault's audit holds neither layout nor pepper", self.KB_PEPPER not in out and not any(x in out for x in shown), out[-300:])

    PHONE_PASSWORD = "kira-vmtest-phone-pw"
    PHONE_PEPPER = "vmtest7phone"

    def phone_guest(self):
        """The test's own Bluetooth on the machine, never a package's: ttyS2 is the emulator's
        simulated Bluetooth (netsimd's HCI socket, tools/localvm.py --bt), made an adapter by btattach
        in the running system and in the boot image; bluetoothd masked, as the gate takes the adapter
        whole."""
        unit = """[Unit]
Description=vmtest: the emulator's simulated Bluetooth on ttyS2 (tools/phone-vm-test.py)
DefaultDependencies=no
Requires=dev-ttyS2.device
After=dev-ttyS2.device
Conflicts=initrd-switch-root.target shutdown.target
Before=initrd-switch-root.target shutdown.target

[Service]
ExecStartPre=-/usr/bin/modprobe hci_uart
ExecStart=/usr/bin/btattach -B /dev/ttyS2 -P h4

[Install]
WantedBy=sysinit.target
"""
        if self.distro == "arch":
            pkg = "pacman -S --noconfirm --needed bluez-utils"
            image = """build() {
    add_module hci_uart
    add_binary /usr/bin/btattach
    add_file /usr/lib/systemd/system/kira-test-btattach.service
    add_symlink /usr/lib/systemd/system/sysinit.target.wants/kira-test-btattach.service /usr/lib/systemd/system/kira-test-btattach.service
}
"""
            files = {"/usr/lib/systemd/system/kira-test-btattach.service": unit, "/etc/initcpio/install/kira-test-btattach": image}
            hook = "grep -q kira-test-btattach /etc/mkinitcpio.conf || sed -i 's/^HOOKS=(\\(.*\\))/HOOKS=(\\1 kira-test-btattach)/' /etc/mkinitcpio.conf"
        else:
            pkg = "DEBIAN_FRONTEND=noninteractive apt-get install -y bluez"
            head = 'PREREQ=""\nprereqs() { echo "$PREREQ"; }\ncase "$1" in prereqs) prereqs; exit 0;; esac\n'
            files = {"/usr/lib/systemd/system/kira-test-btattach.service": unit,
                     "/etc/initramfs-tools/hooks/kira-test-btattach": "#!/bin/sh\n" + head + ". /usr/share/initramfs-tools/hook-functions\ncopy_exec /usr/bin/btattach /usr/bin\nmanual_add_modules hci_uart\n",
                     "/etc/initramfs-tools/scripts/init-premount/kira-test-btattach": "#!/bin/sh\n" + head + "modprobe hci_uart\n/usr/bin/btattach -B /dev/ttyS2 -P h4 >/dev/null 2>&1 &\n",
                     "/etc/initramfs-tools/scripts/init-bottom/kira-test-btattach": "#!/bin/sh\n" + head + "kill $(pidof btattach) 2>/dev/null || true\n"}
            hook = "true"
        script = "set -e; " + pkg + " >/tmp/kira-test-bt.log 2>&1; "
        for path, text in files.items():
            b64 = base64.b64encode(text.encode()).decode()
            script += f"mkdir -p {os.path.dirname(path)}; echo {b64} | base64 -d > {path}; "
            if "/hooks/" in path or "/scripts/" in path:
                script += f"chmod 755 {path}; "
        script += f"{hook}; systemctl disable --now bluetooth.service 2>/dev/null || true; systemctl mask bluetooth.service; "
        script += "systemctl enable --now kira-test-btattach.service; sleep 3; ls /sys/class/bluetooth"
        rc, out = self.run(script + " 2>&1", save="phone-guest.log")
        self.check("phone: the simulated Bluetooth is an adapter (btattach on ttyS2)", rc == 0 and "hci" in out, out[-500:])

    def phone_keyboard(self):
        """Marify on the emulator over the simulated Bluetooth, its real BLE code against the real
        gate: the enrolment, the SAS compared on both sides; the hand-over of a phone salt with a
        keyboard (0x1302); two boots the phone attests in the initrd, the code on the boot's screen
        the phone's, its layout typed through at the boot SSH server, another layout each boot."""
        ph = self.phone
        self.head("the phone: Marify on the emulator, over the simulated Bluetooth")
        self.phone_guest()
        ok, out = ph.start("reset", 60).wait(120)
        self.check("phone: the test's record is reset", ok, out[-300:])

        st = ph.start("enrol", 300)
        s = self.session("sudo tpm2-kira phone enrol --verify-tpm off --verify-phone off --adapter-wait 60s", "phone-enrol")
        try:
            while True:
                text, m = s.expect(r"(\[y\] yes, I verified this boot.*: ?$|Enrol anyway\? \[y/N\]: ?$|\[y\] it matches.*: ?$|Enrolled: +phone)", 400)
                if "verified this boot" in m.group(1) or "Enrol anyway" in m.group(1):
                    s.send("y\n")
                elif "it matches" in m.group(1):
                    shown = re.findall(r"Confirm this number matches the one shown in the app:\s+([0-9 ]+?)\s*$", text, re.M)
                    machine_sas = re.sub(r"\D", "", shown[-1]) if shown else ""
                    phone_sas = re.sub(r"\D", "", st.value("sas", 60) or "")
                    same = machine_sas != "" and machine_sas == phone_sas
                    self.check("phone enrol: the SAS on the machine is the phone's", same, f"machine {machine_sas!r}, phone {phone_sas!r}")
                    s.send("y\n" if same else "n\n")
                else:
                    break
            s.wait_end(120)
        finally:
            s.close()
        ok, out = st.wait(300)
        self.check("phone enrol: the phone enrolled the machine over BLE", ok and st.values().get("outcome") == "Succeeded", out[-400:])
        out = self.rebuild()
        self.check("the image is rebuilt with the phone's Bluetooth in it", "Bluetooth" in out, out[-600:])

        st = ph.start("attest", 300)
        s = self.session(f"sudo tpm2-kira luks enrol {self.luks_dev} --salt phone --keyboard-pepper", "luks-enrol-phone-keyboard")
        try:
            s.expect(r"Password for the disk \(the factor's other half\): ?$", 420); s.send(self.PHONE_PASSWORD + "\n")
            s.expect(r"The same password again: ?$", 60); s.send(self.PHONE_PASSWORD + "\n")
            s.expect(r"Pepper: ?$", 60); s.send(self.PHONE_PEPPER + "\n")
            s.expect(r"The same pepper again: ?$", 60); s.send(self.PHONE_PEPPER + "\n")
            s.expect(r"to authorise: ?$", 600); s.send(self.luks_pass + "\n")
            s.expect(r"keyslot (\d+) added: tpm2-kira, 0x1302 ", 300)
            s.wait_end(120)
            self.check("luks enrol --salt phone --keyboard-pepper: the phone kept the salt, a keyslot of recipe 0x1302", True)
        except Fail as e:
            self.check("luks enrol --salt phone --keyboard-pepper", False, str(e))
            raise
        finally:
            s.close()
        ok, out = st.wait(120)
        vals = st.values()
        self.check("the hand-over: the phone's session passed and showed no layout", ok and "layout" not in vals, f"{vals} {out[-300:]}")

        layouts = []
        for boot in (1, 2):
            self.head(f"boot {boot}: the phone attests the initrd")
            self.run("systemctl reboot")
            self.wait_port(22, False, 120)
            if not self.check(f"phone boot {boot}: the boot SSH server answers", self.wait_port(SSH_PORT, True, 300)):
                raise Fail("no boot SSH server")
            # The first boot of the image the phone's enrolment rebuilt is a changed one: approved and remembered.
            st = ph.start("attest", 300, approve="changed" if boot == 1 else None)
            s = self.boot_session(f"phone-{boot}")
            try:
                ok, out = st.wait(300)
                vals = st.values()
                self.log.save(f"phone-boot-{boot}-values.txt", "\n".join(f"{k}={v}" for k, v in vals.items() if k != "layout"))
                # The first boot of the image the enrolment rebuilt may be changed (approved and
                # remembered); the second matches.
                want = ("changed", "match") if boot == 1 else ("match",)
                self.check(f"phone boot {boot}: the phone attested the initrd ({vals.get('state')}, its boot key proved: a code of {len(vals.get('code', ''))} digits)",
                           ok and vals.get("state", "").lower() in want and len(vals.get("code", "")) == 9, f"{ {k: v for k, v in vals.items() if k != 'layout'} } {out[-300:]}")
                if not self.check(f"phone boot {boot}: the phone shows a layout of the 36 keys", len(vals.get("layout", "")) == 36 and vals.get("layout_keys") == "abcdefghijklmnopqrstuvwxyz0123456789", str({k: v for k, v in vals.items() if k != "layout"})):
                    raise Fail("no layout from the phone")
                layout = dict(zip(vals["layout_keys"], vals["layout"]))
                layouts.append(vals["layout"])
                # The phone's verdict ends the code screen: nothing is pressed here.
                text, _ = s.expect(r"Password for disk \S+: ?$", 300)
                self.check(f"phone boot {boot}: the code screen ends on the phone's verdict, with no key pressed", "Confirmed." in text, text[-600:])
                self.check(f"phone boot {boot}: the prompt says to type the pepper through the phone's layout", "layout your phone shows" in text, text[-500:])
                s.send(self.PHONE_PASSWORD + "\r")
                s.expect(r"Pepper for disk \S+: ?$", 60)
                typed = "".join(next(k for k, t in layout.items() if t == c) for c in self.PHONE_PEPPER)
                s.send(typed + "\r")
                s.wait_end(600)
            finally:
                s.close()
            if not self.check(f"phone boot {boot}: the disk opens with password, phone salt and the pepper through the layout", self.wait_port(22, True, 300)):
                raise Fail("the phone's boot did not come up")
            self.booted(f"phone boot {boot}")
        self.check("the second boot's layout is another", len(layouts) == 2 and layouts[0] != layouts[1])

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

        # A person's yes is TestApprovalLeavesAMovedChannel's; control's line seals it here.
        s = self.session(f"sudo tpm2-kira slot approve --nvram {slot}", "channel-person-n")
        try:
            text, _ = s.expect(r"Seal slot \d+'s phone channel to the next boot's PCR 7\? \[y/N\] ?$", 120)
            self.check("at a terminal: old, new and what moved it, before the question (n)",
                       re.search(r"PCR 7 sealed: +[0-9a-f]{64}", text) is not None and re.search(r"PCR 7 next boot: +[0-9a-f]{64}", text) is not None and re.search(r"SecureBoot: (on|off)", text) is not None, text[-800:])
            s.send("n\n")
            out = s.wait_end(120)
        finally:
            s.close()
        self.check("at a terminal, n: left, and said", moved() and left in out, out[-500:])

        s = self.session("sudo tpm2-kira control", "control-channel")
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
            self.check("control: step 2 judges the machine's memory", re.search(r"Memory\s+\d+ MiB", re.sub(r"\x1b\[[0-9;]*m", "", text)) is not None, text[-1200:])
            self.check_control_secure_boot("control step 2", text, {"Setup Mode": "Setup Mode (risk: any root user", "off": "disabled (risk: the boot loader", "could": "state unknown,"}, s)
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
        s = self.session("sudo tpm2-kira control", "control-ssh-off")
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
            # What a rebuild then leaves out is TestDecidePlan's; control's own rebuild ran in the setup.
            if m.group(1).startswith("Run"):
                s.send("n\n")
                s.wait_end(120)
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

    def make_setup(self, reset=None, secure=False):
        """The steps up to the first reboot. The packages arrive while the machine goes back to
        its state. What the hibernate steps add comes before control, whose image takes it. secure:
        the setup with Secure Boot on, for what no other scenario shows there."""
        if reset:
            self.reset(reset)
        self.preflight()
        package = self.packages()
        self.install(package)
        self.seal()
        if not secure:
            self.inspect()
        self.enrol()
        if not secure:
            self.check_memory_lock()
            if self.hib:
                self.hib.prepare()
        self.control()
        self.control_keys()
        self.image()

    def secure_boot_setup(self):
        """Secure Boot really on: tools/secureboot-vm.py's steps from fresh, then the setup, kept,
        and its typed boot; from the saved one, its typed boot alone."""
        lv, setup = self.lv, self.secure_setup
        self.secrets = []
        self.__dict__.pop("_secure_boot", None)
        self.tpm_salt_keyslot = self.vault_keyslot = self.vault_device = None
        if self.secure_saved:
            self.notes.append(FROM_SETUP_NOTE)
            self.head(f"back to the setup with Secure Boot on: the snapshot {setup.tag}")
            setup.restore()
            self.packages()
        else:
            self.head("Secure Boot on: real keys in the firmware, from fresh (tools/secureboot-vm.py's steps)")
            secureboot_vm().make(lv, self.t, self.distro, self.vmcheck())
            self.lap("back to fresh, enrolled, the snapshot " + secureboot_vm().SNAPSHOT)
            lv.start()
            self.lap("the first boot with Secure Boot on")
            self.make_setup(secure=True)
            rc, out = self.run("command -v sbctl >/dev/null && sbctl verify 2>&1; dmesg | grep -iE 'secure ?boot' | head -3", save="secure-boot-state.log")
            self.check("Secure Boot is on in the firmware: its own variables", self.secure_boot_warning() is None, str(self.secure_boot_warning()))
            self.head(f"keeping the setup: the snapshot {setup.tag}")
            setup.save()
        self.setup_snapshot = setup
        self.first_boot_as("secure")

    def firmware_refuses(self):
        """The firmware itself: one byte changed in what it verifies does not start. Arch: the UKI,
        which systemd-boot hands to the firmware; Debian: shim, which the firmware starts. The
        machine is thrown away after it: this comes last."""
        lv = self.lv
        self.head("the firmware refuses a changed image")
        target = "/boot/EFI/Linux/arch-linux.efi" if self.distro == "arch" else "/boot/efi/EFI/debian/shimx64.efi"
        script = (f"f={target}; off=$(( $(stat -c %s $f) / 2 )); b=$(dd if=$f bs=1 skip=$off count=1 2>/dev/null | od -An -tu1 | tr -d ' '); "
                  "printf \"\\\\x$(printf %02x $(( b ^ 255 )))\" | dd of=$f bs=1 seek=$off conv=notrunc 2>/dev/null; sync; echo changed")
        rc, out = self.run(script, save="firmware-refuses-change.log")
        if not self.check(f"one byte of {target} changed", "changed" in out, out[-300:]):
            raise Fail("the file was not changed")
        since = self.console_mark()
        self.warm_reboot()
        deadline, text = time.time() + 60, ""
        while time.time() < deadline:
            text = lv.serial_text(since)
            if REFUSED_BY_FIRMWARE.search(text):
                break
            time.sleep(0.25)
        self.log.save("firmware-refuses-console.log", text)
        self.check("the firmware refuses it: Access Denied", REFUSED_BY_FIRMWARE.search(text) is not None, text[-800:])
        self.check("nothing of the changed image ran", "Linux version" not in text and "Password for disk" not in text if self.distro == "arch" else True, text[-800:])
        lv.kill()

    def save_setup(self, setup, reset=None):
        """--save-setup: the steps up to the first reboot, kept; the run ends."""
        try:
            self.make_setup(reset)
            self.head(f"keeping the setup: the snapshot {setup.tag}")
            setup.save()
        except Fail as e:
            self.rep.issues.append("stopped: " + str(e).split("\n")[0])
        except Exception as e:
            self.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        return self.report()

    def first_boot(self):
        """Boot 1, after the setup or from its snapshot: on tools/localvm.py's machines
        under a new qemu, which keeps the guest's clock short for V2 (tools/LOCALVM.md)."""
        self.first_boot_as(1)

    def first_boot_as(self, n):
        lv = getattr(self, "lv", None)
        if lv:
            lv.start(unlock=False)
        self.cycle(n, started=bool(lv))

    def scenario_steps(self):
        """What each scenario does here."""
        hib = self.hib
        out = {"typed-boot": self.first_boot, "second-typed-boot": lambda: self.cycle(3), "unapproved": self.unapproved_kernel, "tpm-salt": self.tpm_salt,
               "vault-pepper": self.vault_pepper, "revoked": self.revoked, "vault-alone": self.vault_alone, "typed-vault": self.vault_typed, "keyboard-vault": self.vault_keyboard,
               "slot-life": self.slot_life, "removal": self.removal, SECURE_BOOT: self.secure_boot_setup, "firmware-refuses": self.firmware_refuses,
               "phone": self.phone_keyboard}
        if hib:
            out.update({"V6": hib.swap_risk, "hibernate": hib.scenario_hibernate, "debian-resume": hib.scenario_resume, "V3": hib.step_v3, "no-tpm": hib.step_no_tpm, "V4-reverted": hib.step_v4_reverted,
                        "silent-tpm": hib.silent_tpm, "V9-long": hib.silent_tpm_long, "V8": hib.way_out})
        return out

    def scenarios(self, names):
        """Those of the names this machine has, each as (Scenario, function)."""
        steps = self.scenario_steps()
        wanted = [scenario(n) for n in names if n != SETUP]
        return [(s, steps[s.name]) for s in wanted if s.name in steps and s.distro in (None, self.distro) and (s.hib is False or self.hib) and (s.vault is False or self.vault_of_run)
                and (not s.secure or getattr(self, "lv", None)) and (not s.phone or self.phone)]

    def recover(self):
        """Back to the saved setup, booted: a state no failed step left anything in. False
        when that does not work either: the machine is gone."""
        setup = self.setup_snapshot
        if setup is None or setup.problem():
            return False
        try:
            self.head("back to the setup, after a failed step")
            setup.restore()
            self.lv.start(unlock=False)
            self.resumed = False
            self.typed_boot_unchecked()
            return True
        except (Fail, *load_localvm_fail()) as e:
            self.rep.issues.append("stopped: the machine does not come back after a failed step: " + str(e).split("\n")[0])
            return False

    def typed_boot_unchecked(self):
        """A boot of the recovery recipe over SSH, for a step that wants a running system: nothing
        is said of it, the steps that test a boot do that."""
        if not self.wait_port(SSH_PORT, True, 300):
            raise Fail("no boot SSH server")
        s = self.boot_session("unchecked")
        try:
            s.expect(r"Does the code match your authenticator\?.*$", 120)
            s.send("\r")
            s.expect(r"Password for disk \S+: ?$", 300); s.send(TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(TEST_SALT + "\r")
            s.wait_end(600)
        finally:
            s.close()
        if not self.wait_port(22, True, 300):
            raise Fail("the system does not come up")
        self.wait_login("the unchecked boot")

    def write_scenarios(self):
        """As the run goes, so that a run stopped at its limit still says where it was."""
        path = os.path.join(self.dir, "scenarios.json")
        with open(path + ".new", "w") as f:
            json.dump(self.done, f, indent=1)
        os.replace(path + ".new", path)

    def run_scenario(self, name, step):
        """One scenario, timed against its budget. Whether the machine can go on."""
        entry = {"name": name, "budget": (scenario(name).budget or {}).get(self.distro), "seconds": None, "result": "running"}
        self.done.append(entry)
        self.write_scenarios()
        start, failed, issues = time.monotonic(), len([c for c in self.rep.checks if c[1] == "FAIL"]), len(self.rep.issues)
        ok = self.run_step(name, step)
        entry["seconds"] = round(time.monotonic() - start, 1)
        new = self.rep.issues[issues:]
        if not ok or len([c for c in self.rep.checks if c[1] == "FAIL"]) > failed:
            entry["result"] = "FAILED"
        elif any("not tested" in i for i in new):
            entry["result"] = "not tested"
        else:
            entry["result"] = "ok"
        self.timing.finish()
        self.log.say(f"[{self.name}] scenario {name}: {entry['seconds']:.0f} s" + (f" of {entry['budget']}" if entry["budget"] else "") + f", {entry['result']}")
        self.write_scenarios()
        return ok

    def run_steps(self, steps):
        """Each scenario in its order. A failed one is said, the machine goes back to the setup and
        the next goes on, unless what it needs did not run, the machine is gone or there is no
        saved setup to go back to."""
        stopped = set()
        for i, (sc, step) in enumerate(steps):
            missing = [n for n in sc.needs if n in stopped]
            if missing:
                stopped.add(sc.name)
                self.rep.issues.append(f"stopped: {sc.name} not run: it needs {missing[0]}")
                self.done.append({"name": sc.name, "budget": (sc.budget or {}).get(self.distro), "seconds": 0, "result": "not run"})
                self.write_scenarios()
                continue
            if not self.run_scenario(sc.name, step):
                stopped.add(sc.name)
                if i + 1 < len(steps) and not self.recover():
                    self.rep.issues.append(f"stopped after {sc.name}; not run: " + ", ".join(s.name for s, _ in steps[i + 1:]))
                    return

    def run_step(self, name, step):
        try:
            step()
            return True
        except (Fail, *load_localvm_fail()) as e:
            self.rep.issues.append(f"stopped in {name}: " + str(e).split("\n")[0])
        except SystemExit as e:  # acceptance's Target, which a thread would drop without a word
            self.rep.issues.append(f"stopped in {name}: {e}")
        except Exception as e:  # a defect of the test, reported as such
            self.rep.issues.append(f"the test failed in {name}: {type(e).__name__}: {e}")
        return False

    def all(self, names, vault=None, reset=None, from_setup=None, setup=None, keep_setup=False, secure_setup=None, secure_saved=False):
        """A run of the scenarios named. from_setup: the saved setup instead of the steps up to the
        first reboot; setup: where those are kept, for what fails later. secure_setup: the same
        with Secure Boot on, secure_saved: taken from there."""
        self.vault_of_run = vault
        self.setup_snapshot = setup or from_setup
        self.secure_setup, self.secure_saved = secure_setup, secure_saved
        plain = [n for n in names if not scenario(n).secure]
        try:
            if not plain:
                go_on = True
            elif from_setup:
                self.notes.append(FROM_SETUP_NOTE)
                self.head(f"back to the setup: the snapshot {from_setup.tag}")
                from_setup.restore()
                self.packages()
                go_on = True
            else:
                def make():
                    self.make_setup(reset)
                    if setup:
                        self.head(f"keeping the setup: the snapshot {setup.tag}")
                        setup.save()
                go_on = self.run_scenario(SETUP, make)
            if go_on:
                self.run_steps(self.scenarios(names))
        except Fail as e:
            self.rep.issues.append("stopped: " + str(e).split("\n")[0])
        except SystemExit as e:
            self.rep.issues.append(f"stopped: {e}")
        except Exception as e:  # a defect of the test, reported as such
            self.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        finally:
            self.clean_up(setup, keep_setup or bool(from_setup))
        return self.report()

    def clean_up(self, setup, keep_setup):
        """The run's own snapshots go, the machine stops."""
        lv = getattr(self, "lv", None)
        if not lv:
            return
        lv.kill()
        if self.hib:
            lv.drop_snapshot(HIBERNATED)
        if setup and not keep_setup:
            setup.drop()
        if getattr(self, "secure_setup", None) and not keep_setup and not self.secure_saved:
            self.secure_setup.drop()

    def report(self):
        self.timing.finish()
        self.log.save("times.json", self.timing.as_json())
        lines = list(self.notes) + [f"tpm2-kira vmtest: {self.name} ({self.distro}) on {self.host}", datetime.datetime.now().isoformat(timespec="seconds"), ""]
        for name, status, detail in self.rep.checks:
            lines.append(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
        lines += ["", "Issues:" if self.rep.issues else "No issues."] + ["  - " + i for i in self.rep.issues]
        if self.done:
            lines += ["", "Scenarios (seconds, budget):"] + [f"  {d['seconds'] if d['seconds'] is not None else '-':>7}  {d['budget'] or '-':>5}  {d['name']}: {d['result']}" for d in self.done]
        lines += [""] + self.timing.lines()
        failed = self.rep.failed() or any(i.startswith(("stopped", "the test failed")) for i in self.rep.issues)
        lines += ["", "RESULT: FAIL" if failed else "RESULT: PASS", f"logs: {self.dir}"]
        text = "\n".join(lines) + "\n"
        self.log.save("report.txt", text)
        return not failed, text


SECUREBOOT_VM_LOCK = threading.Lock()


def secureboot_vm():
    """tools/secureboot-vm.py, one module per process; the machines' threads wait for it whole."""
    with SECUREBOOT_VM_LOCK:
        if "secureboot_vm" not in sys.modules:
            spec = importlib.util.spec_from_file_location("secureboot_vm", os.path.join(REPO, "tools", "secureboot-vm.py"))
            mod = importlib.util.module_from_spec(spec)
            sys.modules["secureboot_vm"] = mod
            spec.loader.exec_module(mod)
        return sys.modules["secureboot_vm"]


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


class Ready:
    """What the machines wait for, made once beside them: its result, or its failure raised in
    each of them."""

    def __init__(self):
        self.done, self.value, self.error = threading.Event(), None, None

    def run(self, make):
        try:
            self.value = make()
        except Exception as e:
            self.error = str(e)
        self.done.set()

    def wait(self):
        self.done.wait()
        if self.error:
            raise Fail(self.error)
        return self.value


def load_hibernate():
    spec = importlib.util.spec_from_file_location("hibernatetest", os.path.join(REPO, "tools", "hibernatetest.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["arch", "debian", "both"], required=True)
    p.add_argument("--config", default=os.path.join(REPO, "tools", "vmtest.conf"))
    p.add_argument("--packages", help="where the built .deb and .pkg.tar.zst are (default build/packages, with --fast-kdf build/packages-fastkdf)")
    p.add_argument("--fast-kdf", action="store_true", help="WARNING: NO FINAL PROOF. A test package, built here with Argon2id at a test's cost (a Go build tag), never a release; the whole typed-recipe path runs, the real cost does not. Disks enrolled with one cost do not open with the other")
    p.add_argument("--password-file", help="the VMs' user password (default: the config's password_file, or $VMTEST_PASSWORD)")
    p.add_argument("--run-dir", help="default: ./vmtest-<time>")
    p.add_argument("--no-build", action="store_true", help="take HEAD's packages already in --packages instead of building them")
    p.add_argument("--no-reset", action="store_true", help="do not run the machines' reset commands: they must be fresh already")
    p.add_argument("--all", action="store_true", help="every scenario, not the proof's alone: before a release")
    p.add_argument("--only", help="these scenarios alone, with what they need, " + ",".join(s.name for s in SCENARIOS) + ": no final proof; from the snapshot " + SETUP_SNAPSHOT + ", without building, unless setup is named")
    p.add_argument("--keep-setup", action="store_true", help=f"leave the snapshot {SETUP_SNAPSHOT} a run makes on the way")
    p.add_argument("--localvm-config", help="the machines' config for the saved setup (default: tools/localvm.py's)")
    p.add_argument("--save-setup", action="store_true", help=f"the steps up to the first reboot, kept in the snapshot {SETUP_SNAPSHOT}; the run ends")
    p.add_argument("--from-setup", action="store_true", help=f"start from the snapshot {SETUP_SNAPSHOT}, without building: no final proof")
    p.add_argument("--phone", metavar="SERIAL", help="the emulator (adb serial) whose Marify attests the machine over the simulated Bluetooth: the scenario phone; tools/phone-vm-test.py sets it up")
    p.add_argument("--drop-setup", action="store_true", help=f"remove the snapshots {SETUP_SNAPSHOT} and {SECURE_SETUP_SNAPSHOT} and end")
    args = p.parse_args()
    if sum((args.save_setup, args.from_setup, args.drop_setup)) > 1:
        p.error("--save-setup, --from-setup and --drop-setup exclude each other")
    only = args.only.split(",") if args.only else None
    unknown = set(only or ()) - {s.name for s in SCENARIOS}
    if unknown:
        p.error("no such scenario: " + ", ".join(sorted(unknown)) + "; there are " + ", ".join(s.name for s in SCENARIOS))
    names = scenarios_of(only, args.all)
    if only and SETUP not in only and SECURE_BOOT not in only:
        args.from_setup = True
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
    run_dir = os.path.abspath(args.run_dir or os.path.join(os.getcwd(), "vmtest-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    targets = ["arch", "debian"] if args.target == "both" else [args.target]
    if subprocess.run(["git", "-C", REPO, "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True).stdout.strip():
        print("note: uncommitted changes are not tested: the packages are HEAD's", file=sys.stderr)
    local = {}
    uses_localvm = any("localvm.py" in cfg.get(n, "reset", fallback="") for n in targets)
    if args.save_setup or args.from_setup or args.drop_setup or uses_localvm:
        localvm, local = local_machines(args.localvm_config or load_localvm().DEFAULT_CONFIG, targets)
    if args.drop_setup:
        for lv in local.values():
            SavedSetup(lv, None, SETUP_SNAPSHOT).drop()
            SavedSetup(lv, None, SECURE_SETUP_SNAPSHOT).drop()
        print(f"dropped {SETUP_SNAPSHOT} and {SECURE_SETUP_SNAPSHOT}")
        return 0
    timing = Timing("the run", print)
    os.makedirs(run_dir, exist_ok=True)
    machines, resets = [], {}
    for name in targets:
        sec = cfg[name]
        luks = sec.get("luks_passphrase") or os.environ.get("VMTEST_LUKS_PASSPHRASE") or password
        m = Machine(name, name, sec["host"], sec.get("user", "pix"), password, luks, run_dir, int(sec.get("ssh_port", "22")), int(sec.get("boot_port", str(SSH_PORT))))
        machines.append(m)
        if not args.no_reset and sec.get("reset"):
            resets[name] = sec["reset"]
        if name in local:
            m.lv = local[name]
        m.fast_kdf = args.fast_kdf
        if args.phone:
            m.phone = Phone(args.phone, m.dir)
        if args.fast_kdf:
            m.notes.append(FAST_KDF_NOTE)
        if only:
            m.notes.append(PARTIAL_NOTE + ", ".join(names))
    setups = {m.name: SavedSetup(local[m.name], m, SETUP_SNAPSHOT, args.fast_kdf) for m in machines if m.name in local}
    secure_setups = {m.name: SavedSetup(local[m.name], m, SECURE_SETUP_SNAPSHOT, args.fast_kdf) for m in machines if m.name in local}
    plain_names = [n for n in names if not scenario(n).secure]
    secure_names = [n for n in names if scenario(n).secure]
    if args.from_setup:
        problems = []
        if plain_names:
            problems += [why for why in (s.problem() for s in setups.values()) if why]
        if secure_names:
            problems += [why for why in (s.problem() for s in secure_setups.values()) if why]
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 2
        print(FROM_SETUP_NOTE, flush=True)
    vault = None
    if not args.save_setup and any(scenario(n).vault for n in names):
        vc = cfg["vault"] if cfg.has_section("vault") else {}
        vault = Vault(os.path.abspath(os.path.join(REPO, vc.get("src", "../tpm2-kira-vault"))),
                      vc.get("url", "https://172.17.2.174"), int(vc.get("port", "443")), int(vc.get("operator_port", "8444")), run_dir)
    ready = Ready()

    def prepare():
        """What the machines wait for after their reset: it runs beside the reset, not before it."""
        built = {}
        if not args.no_build:
            timing.step("building the packages")
            print(f"building the packages of HEAD ({' '.join(targets)}), log: {run_dir}/build-packages.log", flush=True)
            with open(os.path.join(run_dir, "build-packages.log"), "w") as log:
                if subprocess.run([os.path.join(REPO, "packaging", "build-packages.sh")] + (["--fast-kdf"] if args.fast_kdf else []) + ["arch" if n == "arch" else "deb" for n in targets], cwd=REPO, stdout=log, stderr=subprocess.STDOUT).returncode != 0:
                    raise Fail(f"the packages do not build: {run_dir}/build-packages.log")
        short, packages = head_packages(args.packages, args.fast_kdf)
        for m in machines:
            if not packages[m.name] and not args.from_setup:
                raise Fail(f"no {m.name} package of HEAD ({short}) in {args.packages} (leave out --no-build)")
            built[m.name] = packages[m.name]
            if packages[m.name]:
                why = package_is(packages[m.name], args.fast_kdf)
                m.check(f"the package is {'a test build, as --fast-kdf asks' if args.fast_kdf else 'a release build: no Go build tag, no trace of a test build'}", why is None, why or "")
                if why:
                    raise Fail(f"{os.path.basename(packages[m.name])}: {why}")
        if vault:
            timing.step("the vault's container")
            vault.start()
        if "slot-life" in names and not args.save_setup:
            timing.step("the channel fixture")
            fixture = build_channel_fixture(run_dir)
            for m in machines:
                m.channel_fixture = fixture
        if local and (args.save_setup or args.keep_setup or any(scenario(n).hib for n in names)):
            # The steps of hibernatetest.py, in this machine and this process.
            timing.step("aSSH's command, the hibernate steps' probe")
            sys.modules.setdefault("vmtest", sys.modules[__name__])
            hibernate = load_hibernate()
            probe = hibernate.build_probe(run_dir)
            for m in machines:
                if m.name in local:
                    m.hib = hibernate.Hib(local[m.name], m, probe)
        if secure_names and not args.from_setup:
            timing.step("go-uefi-slim's vmcheck, for Debian's keys")
            path = secureboot_vm().build_vmcheck(run_dir)
            for m in machines:
                m.vmcheck = lambda path=path: path
        timing.finish()
        print(f"tpm2-kira {short}: " + ", ".join(f"{m.name} {os.path.basename(built[m.name] or 'the saved setup')}" + (" (reset)" if m.name in resets else "") for m in machines), flush=True)
        return built

    results = {}
    for m in machines:
        m.packages = lambda m=m: ready.wait()[m.name]
        m.vmcheck = lambda m=m: (ready.wait(), m.vmcheck())[1]
    if args.save_setup:
        work = lambda m: m.save_setup(setups[m.name], resets.get(m.name))
    else:
        work = lambda m: m.all(names, vault, resets.get(m.name), setups.get(m.name) if args.from_setup else None, setups.get(m.name), keep_setup=args.keep_setup,
                               secure_setup=secure_setups.get(m.name), secure_saved=args.from_setup)
    threads = [threading.Thread(target=lambda m=m: results.__setitem__(m.name, work(m))) for m in machines]
    for th in threads:
        th.start()
    ready.run(prepare)
    for th in threads:
        th.join()
    if vault:
        vault.stop()
    ok = ready.error is None
    if ready.error:
        print(ready.error, file=sys.stderr)
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
