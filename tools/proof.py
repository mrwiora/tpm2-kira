#!/usr/bin/env python3
"""A proof, as one command: every part of it, a time per part, one total, one report.

    tools/proof.py                            # the parts every proof has
    tools/proof.py --with marify,safearch-vm  # and these
    tools/proof.py --only test-all            # these alone: NO FINAL PROOF

A part that fails does not stop the others. The report (report.txt, report.json in the run's
directory, --run-dir or .local/runs/proof-<time>/) names every part, its seconds, its result,
the host's least free memory and disk while it ran, and the wall clock of the whole. Its first
line says when it is no final proof. Each part's output is <part>.log there.

Nothing here decides what a batch has to run: AGENTS.md's table does.
"""

import argparse
import datetime
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.dirname(REPO)
LOCAL = os.path.join(WORKSPACE, ".local")
VM_LOCK = os.path.join(LOCAL, "vms", "vm.lock")
VM_CONFIG = os.path.join(LOCAL, "vms", "vmtest-local.conf")
NOT_FINAL = "NOT A FINAL PROOF: "


class Part:
    """A thing a proof runs. machines: it takes the VMs, under the lock. check: why
    a finished log is a failure all the same, or None."""

    def __init__(self, name, argv, cwd, env=None, machines=False, check=None):
        self.name, self.argv, self.cwd, self.env = name, argv, cwd, env or {}
        self.machines, self.check = machines, check
        self.seconds, self.ok, self.why = None, None, ""
        self.least_memory, self.least_disk = None, None
        self.running = False


def no_cached(log):
    """A result marked (cached) has tested nothing (AGENTS.md)."""
    hits = [l for l in log.splitlines() if "(cached)" in l]
    return f"{len(hits)} result(s) (cached): {hits[0]}" if hits else None


def parts_table(run_dir):
    """Every part there is, by name. The default set is DEFAULT, --with adds."""
    tool = lambda name: os.path.join(REPO, "tools", name)
    machines = os.path.join(run_dir, "machines")
    table = [
        Part("test-all", ["make", "test-all"], REPO, {"GOFLAGS": "-count=1"}, check=no_cached),
        Part("assh", ["go", "test", "-count=1", "./..."], os.path.join(WORKSPACE, "assh"), check=no_cached),
        Part("vmtest", [tool("vmtest.py"), "--config", VM_CONFIG, "--target", "both", "--run-dir", machines + "-vmtest"], REPO, machines=True),
        Part("hibernate", [tool("hibernatetest.py"), "--target", "both", "--no-build", "--run-dir", machines + "-hib"], REPO, machines=True),
        Part("safearch-run", ["tests/run.sh"], os.path.join(WORKSPACE, "safearch")),
        Part("safearch-vm", ["tests/vm.sh"], os.path.join(WORKSPACE, "safearch")),
        Part("vault", ["go", "test", "-count=1", "./..."], os.path.join(WORKSPACE, "tpm2-kira-vault"), check=no_cached),
        Part("marify", ["android/scripts/test-emulator.sh"], os.path.join(WORKSPACE, "marify")),
    ]
    return {p.name: p for p in table}


DEFAULT = ("test-all", "vmtest", "hibernate")


def sample_host(parts, stop, path):
    """The host's free memory and disk, against the parts that run now."""
    while not stop.wait(5):
        with open("/proc/meminfo") as f:
            mem = int(re.search(r"^MemAvailable:\s+(\d+)", f.read(), re.M).group(1)) >> 10
        disk = shutil.disk_usage(path).free >> 20
        for p in parts:
            if p.running:
                p.least_memory = mem if p.least_memory is None else min(p.least_memory, mem)
                p.least_disk = disk if p.least_disk is None else min(p.least_disk, disk)


def run_part(p, run_dir):
    log = os.path.join(run_dir, p.name + ".log")
    print(f"[proof] {p.name}: starts, log {log}", flush=True)
    p.running = True
    start = time.monotonic()
    with open(log, "wb") as f:
        rc = subprocess.run(p.argv, cwd=p.cwd, env=dict(os.environ, **p.env), stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT).returncode
    p.seconds = time.monotonic() - start
    p.running = False
    p.ok = rc == 0
    p.why = f"exit {rc}" if rc != 0 else ""
    if p.ok and p.check:
        with open(log, errors="replace") as f:
            p.why = p.check(f.read()) or ""
        p.ok = not p.why
    print(f"[proof] {p.name}: {'ok' if p.ok else 'FAILED, ' + p.why}, {p.seconds:.0f} s", flush=True)


def report(parts, wall, notes, run_dir):
    lines = list(notes) + ["tpm2-kira proof, " + datetime.datetime.now().isoformat(timespec="seconds"), ""]
    lines.append(f"{'part':<16}{'seconds':>9}  {'least free MiB':>14}  {'disk MiB':>9}  result")
    for p in parts:
        lines.append(f"{p.name:<16}{p.seconds:>9.0f}  {p.least_memory or 0:>14}  {p.least_disk or 0:>9}  {'ok' if p.ok else 'FAILED: ' + p.why}")
    lines += ["", f"{'the whole':<16}{wall:>9.0f}  (the wall clock)", f"{'sum of parts':<16}{sum(p.seconds for p in parts):>9.0f}", "",
              "ALL PASS" if all(p.ok for p in parts) else "FAILED", f"logs: {run_dir}"]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(run_dir, "report.txt"), "w") as f:
        f.write(text)
    with open(os.path.join(run_dir, "report.json"), "w") as f:
        json.dump({"wall": round(wall, 1), "notes": notes, "parts": [{"name": p.name, "seconds": round(p.seconds, 1), "ok": p.ok, "why": p.why,
                   "least_memory_mib": p.least_memory, "least_disk_mib": p.least_disk} for p in parts]}, f, indent=1)
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", help="where the report and the logs land (default .local/runs/proof-<time>)")
    ap.add_argument("--with", dest="more", default="", help="parts on top of the default: " + ",".join(n for n in parts_table("") if n not in DEFAULT))
    ap.add_argument("--only", help="these parts alone: no final proof")
    args = ap.parse_args()
    run_dir = os.path.abspath(args.run_dir or os.path.join(LOCAL, "runs", "proof-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    os.makedirs(run_dir, exist_ok=True)
    table = parts_table(run_dir)
    wanted = args.only.split(",") if args.only else list(DEFAULT) + [n for n in args.more.split(",") if n]
    unknown = [n for n in wanted if n not in table]
    if unknown:
        ap.error("no such part: " + ", ".join(unknown) + "; there are " + ", ".join(table))
    parts = [table[n] for n in wanted]
    notes = [NOT_FINAL + "--only " + args.only] if args.only else []
    lock = None
    if any(p.machines for p in parts):
        lock = open(VM_LOCK, "a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"the VMs are in use: {VM_LOCK} is held", file=sys.stderr)
            return 2
    stop = threading.Event()
    sampler = threading.Thread(target=sample_host, args=(parts, stop, LOCAL), daemon=True)
    sampler.start()
    start = time.monotonic()
    for p in parts:
        run_part(p, run_dir)
    stop.set()
    print(report(parts, time.monotonic() - start, notes, run_dir), flush=True)
    return 0 if all(p.ok for p in parts) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
