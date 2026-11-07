"""tools/vmtest.py's helpers that need nothing of a run: the interactive ssh session (Session), the
run's vault in its container (Vault), the emulator's Marify stage by stage (Phone, PhoneStage), the
timing, TOTP and the cleaning of output. vmtest.py imports them under the same names, which
hibernatetest.py reaches as vmtest.X."""

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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\r")


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


class Session:
    """An interactive ssh session in a pty: expect text, send keys. The
    password prompts of ssh and sudo, and control's holds after a step
    ("[Enter: OK]": for a person to read what the step printed), are answered
    by themselves; every other prompt is the test's to answer."""

    def __init__(self, argv, log_path, password=None, size=None):
        self.password = password
        self.log = open(log_path, "ab", buffering=0)
        self.buf = b""
        self.mark = 0      # expect looks at what came after it
        self.answered = 0  # the password prompts are looked for after it
        self.closed = False
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            if size:
                # A terminal that says its size and has a TERM: where a menu takes the keys.
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", size[0], size[1], 0, 0))
                os.environ["TERM"] = "xterm"
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
        elif re.search(rb"\[Enter: [^\]\n]*\] ?$", tail):
            os.write(self.fd, b"\n")
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
            if self.closed:
                raise Fail(f"the session ended before /{pattern}/; it showed:\n" + clean(raw)[-1500:])
            if time.time() > deadline:
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


class PhoneStage:
    """One stage of Marify's RealMachineTest (app.marify.vm), running: its process, and what it
    logged under the tag KiraVm (key=value lines)."""

    def __init__(self, phone, name, proc, out_path):
        self.phone, self.name, self.proc, self.out_path = phone, name, proc, out_path

    def values(self):
        out = self.phone.adb("logcat", "-d", "-s", "KiraVm:I").stdout
        vals = {}
        for line in out.splitlines():
            m = re.search(r"KiraVm\s*:\s*(\w+)=(.*)$", line)
            if m:
                vals.setdefault(m.group(1), m.group(2).strip())
        return vals

    def value(self, key, timeout=120):
        """What the stage logged for key, waited for while it runs; None once it ended without."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = self.values().get(key)
            if v is not None:
                return v
            if self.proc.poll() is not None:
                return self.values().get(key)
            time.sleep(1)
        return None

    def wait(self, timeout=360):
        """The stage's end: (passed, its instrumentation output)."""
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        with open(self.out_path) as f:
            out = f.read()
        return ("OK (1 test)" in out, out)


class Phone:
    """The emulator's Marify, driven stage by stage through its instrumented RealMachineTest; the
    emulator, its simulated Bluetooth and the installed APKs are tools/phone-vm-test.py's."""

    RUNNER = "io.wiora.marify.debug.test/androidx.test.runner.AndroidJUnitRunner"

    def __init__(self, serial, log_dir):
        self.serial, self.log_dir, self.n = serial, log_dir, 0
        self.adb_path = os.path.join(os.environ.get("ANDROID_HOME", os.path.expanduser("~/Android/Sdk")), "platform-tools", "adb")

    def adb(self, *args, timeout=60):
        return subprocess.run([self.adb_path, "-s", self.serial, *args], capture_output=True, text=True, timeout=timeout)

    def start(self, stage, timeout=300, approve=None):
        """Starts a stage; its log is cleared first, so what it says is its own."""
        self.n += 1
        self.adb("logcat", "-c")
        cmd = ["shell", "am", "instrument", "-w", "-r", "-e", "class", "app.marify.vm.RealMachineTest", "-e", "vm", stage, "-e", "timeout", str(timeout)]
        if approve:
            cmd += ["-e", "approve", approve]
        out_path = os.path.join(self.log_dir, f"phone-{self.n:02d}-{stage}.log")
        f = open(out_path, "w")
        proc = subprocess.Popen([self.adb_path, "-s", self.serial, *cmd, self.RUNNER], stdout=f, stderr=subprocess.STDOUT)
        threading.Thread(target=self.capture, args=(proc, f"phone-{self.n:02d}-{stage}"), daemon=True).start()
        return PhoneStage(self, stage, proc, out_path)

    def capture(self, proc, prefix, every=1.5):
        """The screens the stage shows, while it runs: a screenshot every so often, each new one
        kept (log_dir/phone-screens). A window Marify keeps out of screenshots (the one-time
        keyboard, FLAG_SECURE) comes out black: by design."""
        out = os.path.join(self.log_dir, "phone-screens")
        os.makedirs(out, exist_ok=True)
        seen, n = set(), 0
        while proc.poll() is None:
            try:
                png = subprocess.run([self.adb_path, "-s", self.serial, "exec-out", "screencap", "-p"],
                                     capture_output=True, timeout=20).stdout
            except subprocess.TimeoutExpired:
                png = b""
            digest = hashlib.sha256(png).digest()
            if png.startswith(b"\x89PNG") and digest not in seen:
                seen.add(digest)
                n += 1
                with open(os.path.join(out, f"{prefix}-{n:02d}.png"), "wb") as f:
                    f.write(png)
            time.sleep(every)
