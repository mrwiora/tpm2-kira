#!/usr/bin/env python3
"""Test machines on this host, with qemu directly: no libvirt, no root.

    tools/localvm.py init arch           # files from the export, swtpm provisioned
    tools/localvm.py start arch          # boots, types the disk's passphrase at the serial console
    tools/localvm.py start arch --no-unlock   # boots only (the first boot: edit the boot loader by hand)
    tools/localvm.py send arch 'e'       # keys to the serial console (\\r, \\e, \\x.. escapes)
    tools/localvm.py log arch [N]        # the serial console's last N lines, cleaned
    tools/localvm.py ssh arch 'cmd'      # a command over the machine's sshd (the password answered)
    tools/localvm.py stop arch           # ACPI power-off, then quit
    tools/localvm.py snapshot arch fresh # stopped: the disk, the OVMF variables, the TPM
    tools/localvm.py reset arch [fresh]  # stop, back to the snapshot, start, unlock
    tools/localvm.py status

A machine is described in a config (default ../.local/vms/localvm.conf,
see localvm.conf.example): the exported disk, its MAC, and the local ports
its ssh (22) and tpm2-kira's boot SSH server (2222) are forwarded to on
127.0.0.1. Its files live in the config's dir/<machine>/:

  disk.qcow2      an overlay on the export: the export is never written
  vars.fd         the OVMF variables (a copy of the template; no Secure Boot)
  tpm/            swtpm's state, provisioned with EK certificates
  serial.log      everything the serial console printed
  snap-<tag>/     a snapshot's OVMF variables and TPM state; the disk's is
                  an internal snapshot of disk.qcow2

reset is what tools/vmtest.py's `reset` runs: the machine back to its
snapshot and cold-booted, its disk unlocked at the serial console (the
passphrase from the config's password file), ssh answering.

tools/LOCALVM.md: what the host needs, how an export became a machine
here (the serial console), and the pitfalls.
"""

import argparse
import configparser
import json
import os
import pty
import select
import re
import shutil
import socket
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(os.path.dirname(REPO), ".local", "vms", "localvm.conf")
OVMF_CODE = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
OVMF_VARS = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
# What a fresh machine's initrd asks for its disk: systemd (Arch), cryptsetup's askpass (Debian).
PASSPHRASE_PROMPT = re.compile(r"(Please enter passphrase for disk \S+|Please unlock disk \S+):[^\n]*$")


class Fail(Exception):
    pass


def clean(data):
    """Terminal output as text: escapes and carriage returns out."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]", "", text)
    return text.replace("\r", "")


class Machine:
    def __init__(self, name, sec, defaults):
        self.name = name
        self.export = os.path.expanduser(sec["export"])
        self.mac = sec["mac"]
        self.ssh_port = int(sec["ssh_port"])
        self.boot_port = int(sec["boot_port"])
        self.mem = sec.get("memory", "4096")
        self.user = sec.get("user", "pix")
        self.dir = os.path.join(os.path.expanduser(defaults.get("dir")), name)
        pwfile = os.path.expanduser(defaults.get("password_file", ""))
        self.passphrase = sec.get("luks_passphrase") or (open(pwfile).read().strip() if pwfile and os.path.exists(pwfile) else "")

    def path(self, *p):
        return os.path.join(self.dir, *p)

    # ── files ────────────────────────────────────────────────────────────

    def init(self):
        if os.path.exists(self.path("disk.qcow2")):
            raise Fail(f"{self.dir} exists: remove it to start from the export again")
        if not os.path.exists(self.export):
            raise Fail(f"no export at {self.export}")
        os.makedirs(self.path("tpm"), exist_ok=True)
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", self.export, self.path("disk.qcow2")])
        shutil.copyfile(OVMF_VARS, self.path("vars.fd"))
        # The TPM as libvirt provisions it: an EK with its certificate and a
        # platform certificate, from swtpm's local CA (in ~/.config).
        run(["swtpm_setup", "--create-config-files", "skip-if-exist"], check=False)
        run(["swtpm_setup", "--tpm2", "--tpmstate", self.path("tpm"), "--create-ek-cert", "--create-platform-cert",
             "--overwrite", "--logfile", self.path("swtpm_setup.log")])
        print(f"{self.name}: {self.dir} made from {self.export}")

    # ── running ──────────────────────────────────────────────────────────

    def pid(self):
        try:
            p = int(open(self.path("qemu.pid")).read())
            os.kill(p, 0)
            return p
        except (OSError, ValueError):
            return None

    def start(self, unlock=True, timeout=600):
        if self.pid():
            print(f"{self.name}: running")
        else:
            free = shutil.disk_usage(self.dir).free
            if free < 1 << 30:
                raise Fail(f"{self.dir}: less than 1 GB free")
            for f in ("serial.sock", "qmp.sock", os.path.join("tpm", "swtpm-sock")):
                if os.path.exists(self.path(f)):
                    os.remove(self.path(f))
            run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.path("tpm"),
                 "--ctrl", "type=unixio,path=" + self.path("tpm", "swtpm-sock"),
                 "--log", "file=" + self.path("tpm", "swtpm.log"), "--pid", "file=" + self.path("tpm", "swtpm.pid"),
                 "--terminate", "--daemon"])
            self.mark = os.path.getsize(self.path("serial.log")) if os.path.exists(self.path("serial.log")) else 0
            run(["qemu-system-x86_64", "-name", self.name, "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", self.mem,
                 "-rtc", "base=utc",
                 "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
                 "-drive", f"if=pflash,format=raw,file={self.path('vars.fd')}",
                 "-drive", f"file={self.path('disk.qcow2')},if=virtio,format=qcow2,discard=unmap",
                 "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22,hostfwd=tcp:127.0.0.1:{self.boot_port}-:2222",
                 # The NIC behind a root port on bus 1, as libvirt places it: the
                 # guest names it enp1s0, as its network configuration says.
                 "-device", "pcie-root-port,id=rp1,chassis=1,slot=1",
                 "-device", f"virtio-net-pci,bus=rp1,netdev=n0,mac={self.mac}",
                 "-chardev", f"socket,id=chrtpm,path={self.path('tpm', 'swtpm-sock')}",
                 "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-crb,tpmdev=tpm0",
                 "-chardev", f"socket,id=ser0,path={self.path('serial.sock')},server=on,wait=off,logfile={self.path('serial.log')},logappend=on",
                 "-serial", "chardev:ser0",
                 "-qmp", f"unix:{self.path('qmp.sock')},server=on,wait=off",
                 "-display", "none", "-daemonize", "-pidfile", self.path("qemu.pid")])
            print(f"{self.name}: started (ssh 127.0.0.1:{self.ssh_port}, boot ssh 127.0.0.1:{self.boot_port}, serial {self.path('serial.log')})")
        if unlock:
            self.unlock(timeout)
            self.wait_ssh(timeout)

    def serial_text(self, since=0):
        try:
            with open(self.path("serial.log"), "rb") as f:
                f.seek(since)
                return clean(f.read())
        except FileNotFoundError:
            return ""

    def send(self, keys):
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(self.path("serial.sock"))
            s.sendall(keys.encode() if isinstance(keys, str) else keys)
            time.sleep(0.2)

    def expect(self, rx, timeout, since):
        """Waits until rx matches the serial output after since; the match."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            m = rx.search(self.serial_text(since))
            if m:
                return m
            if not self.pid():
                raise Fail(f"{self.name}: qemu ended")
            time.sleep(1)
        raise Fail(f"{self.name}: waited {timeout} s for /{rx.pattern}/ at the serial console; it showed:\n" + self.serial_text(since)[-1500:])

    def unlock(self, timeout):
        """Types the disk's passphrase at the serial console's prompt."""
        if not self.passphrase:
            raise Fail(f"{self.name}: no passphrase (password_file or luks_passphrase)")
        since = getattr(self, "mark", 0)
        self.expect(PASSPHRASE_PROMPT, timeout, since)
        self.send(self.passphrase + "\r")
        print(f"{self.name}: the disk's passphrase typed at the serial console")

    def wait_ssh(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.ssh_port), timeout=3) as s:
                    s.settimeout(5)
                    if s.recv(64).startswith(b"SSH-"):
                        print(f"{self.name}: ssh answers")
                        return
            except OSError:
                pass
            time.sleep(2)
        raise Fail(f"{self.name}: ssh does not answer within {timeout} s")

    def qmp(self, *commands):
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(self.path("qmp.sock"))
            f = s.makefile("rw")
            f.readline()
            for c in [{"execute": "qmp_capabilities"}] + list(commands):
                f.write(json.dumps(c) + "\n")
                f.flush()
                while True:
                    reply = json.loads(f.readline())
                    if "event" not in reply:
                        break

    def stop(self, timeout=90):
        if not self.pid():
            print(f"{self.name}: not running")
            return
        try:
            self.qmp({"execute": "system_powerdown"})
        except OSError:
            pass
        deadline = time.time() + timeout
        while self.pid() and time.time() < deadline:
            time.sleep(1)
        if self.pid():
            try:
                self.qmp({"execute": "quit"})
            except OSError:
                os.kill(self.pid(), 9)
            time.sleep(2)
        print(f"{self.name}: stopped")

    def kill(self):
        if self.pid():
            try:
                self.qmp({"execute": "quit"})
            except OSError:
                os.kill(self.pid(), 9)
            for _ in range(20):
                if not self.pid():
                    break
                time.sleep(0.5)

    def ssh(self, command, timeout=600):
        """Runs command on the machine over its sshd, the password prompt
        answered in a pty; its output and exit status."""
        argv = ["ssh", "-tt", "-p", str(self.ssh_port), "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=" + self.path("known_hosts"), "-o", "PubkeyAuthentication=no",
                "-o", "LogLevel=ERROR", f"{self.user}@127.0.0.1", command]
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp(argv[0], argv)
        out, answered, deadline = b"", False, time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 1)
            if not r:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            out += data
            if not answered and re.search(rb"password: ?$", out[-200:]):
                os.write(fd, (self.passphrase + "\n").encode())
                out, answered = b"", True
        _, status = os.waitpid(pid, 0)
        return clean(out), os.waitstatus_to_exitcode(status)

    # ── snapshots ────────────────────────────────────────────────────────

    def snapshot(self, tag):
        if self.pid():
            raise Fail(f"{self.name} runs: stop it first")
        snap = self.path("snap-" + tag)
        if os.path.exists(snap):
            shutil.rmtree(snap)
            run(["qemu-img", "snapshot", "-d", tag, self.path("disk.qcow2")], check=False)
        os.makedirs(snap)
        run(["qemu-img", "snapshot", "-c", tag, self.path("disk.qcow2")])
        shutil.copyfile(self.path("vars.fd"), os.path.join(snap, "vars.fd"))
        shutil.copytree(self.path("tpm"), os.path.join(snap, "tpm"), ignore=shutil.ignore_patterns("swtpm-sock", "swtpm.pid", "swtpm.log"))
        print(f"{self.name}: snapshot {tag}")

    def revert(self, tag):
        snap = self.path("snap-" + tag)
        if not os.path.isdir(snap):
            raise Fail(f"{self.name}: no snapshot {tag}")
        self.kill()
        run(["qemu-img", "snapshot", "-a", tag, self.path("disk.qcow2")])
        shutil.copyfile(os.path.join(snap, "vars.fd"), self.path("vars.fd"))
        shutil.rmtree(self.path("tpm"))
        shutil.copytree(os.path.join(snap, "tpm"), self.path("tpm"))
        print(f"{self.name}: back to {tag}")


def run(argv, check=True):
    p = subprocess.run(argv, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise Fail(f"{' '.join(argv)}: exit {p.returncode}\n{p.stdout}{p.stderr}")
    return p


def unescape(s):
    return s.encode().decode("unicode_escape")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("command", choices=["init", "start", "stop", "send", "log", "ssh", "snapshot", "reset", "revert", "status"])
    p.add_argument("machine", nargs="?")
    p.add_argument("arg", nargs="?")
    p.add_argument("--no-unlock", action="store_true")
    p.add_argument("--timeout", type=int, default=600)
    a = p.parse_args()
    cfg = configparser.ConfigParser()
    if not cfg.read(a.config):
        print(f"no {a.config}: copy tools/localvm.conf.example", file=sys.stderr)
        return 2
    defaults = cfg["defaults"] if cfg.has_section("defaults") else {}
    names = [s for s in cfg.sections() if s != "defaults"]
    if a.command == "status":
        for n in names:
            m = Machine(n, cfg[n], defaults)
            snaps = sorted(d[5:] for d in os.listdir(m.dir) if d.startswith("snap-")) if os.path.isdir(m.dir) else []
            print(f"{n}: {'running' if m.pid() else 'stopped'}, ssh 127.0.0.1:{m.ssh_port}, snapshots {snaps}")
        return 0
    if a.machine not in names:
        print(f"machines: {', '.join(names)}", file=sys.stderr)
        return 2
    m = Machine(a.machine, cfg[a.machine], defaults)
    try:
        if a.command == "init":
            m.init()
        elif a.command == "start":
            m.start(unlock=not a.no_unlock, timeout=a.timeout)
        elif a.command == "stop":
            m.stop()
        elif a.command == "send":
            m.send(unescape(a.arg or ""))
        elif a.command == "ssh":
            out, rc = m.ssh(a.arg or "true")
            print(out, end="")
            return rc
        elif a.command == "log":
            print("\n".join(m.serial_text().splitlines()[-int(a.arg or 40):]))
        elif a.command == "snapshot":
            m.snapshot(a.arg or "fresh")
        elif a.command == "revert":
            m.revert(a.arg or "fresh")
        elif a.command == "reset":
            m.revert(a.arg or "fresh")
            m.start(timeout=a.timeout)
    except Fail as e:
        print(f"localvm: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
