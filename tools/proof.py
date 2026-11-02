#!/usr/bin/env python3
"""A proof, as one command: every part of it, a time per part, one total, one report.

    tools/proof.py                            # test-all and the machines, from the snapshot fresh
    tools/proof.py --since '2026-11-03 09:00' # and what AGENTS.md's table asks for the batch since then
    tools/proof.py --with marify,safearch-vm  # and these
    tools/proof.py --only test-all            # these alone: NO FINAL PROOF

The parts run at once as far as the host's memory allows (MEMORY: measured, what each takes;
BUDGET: what it has for them), each with what it shares with nothing else. A part that fails
does not stop the others. The machines take .local/vms/vm.lock, and are reverted to fresh and
stopped at their end.

The report (report.txt, report.json in the run's directory, --run-dir or
.local/runs/proof-<time>/) names every part, its seconds, its result, the host's least free
memory and disk while it ran, and the wall clock of the whole. Its first line says when it is no
final proof. Each part's output is <part>.log there, the machines' reports under machines/.
"""

import argparse
import datetime
import fcntl
import importlib.util
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
MEMORY_BUDGET = 14000  # MiB of the host's 15 GB the parts may plan on


class Part:
    """A thing a proof runs. machines: it takes the VMs, under the lock. check: why
    a finished log is a failure all the same, or None. memory: MiB it may take at its
    height, measured (docs/TESTING.md)."""

    def __init__(self, name, argv, cwd, env=None, machines=False, check=None, memory=2000):
        self.name, self.argv, self.cwd, self.env = name, argv, cwd, env or {}
        self.machines, self.check, self.memory = machines, check, memory
        self.seconds, self.start, self.ok, self.why = None, None, None, ""
        self.least_memory, self.least_disk = None, None
        self.running = False


def no_cached(log):
    """A result marked (cached) has tested nothing (AGENTS.md)."""
    hits = [l for l in log.splitlines() if "(cached)" in l]
    return f"{len(hits)} result(s) (cached): {hits[0]}" if hits else None


def parts_table(run_dir):
    """Every part there is, by name. DEFAULT runs always, the rest when asked."""
    tool = lambda name: os.path.join(REPO, "tools", name)
    go_test = ["go", "test", "-count=1", "./..."]
    project = lambda name: os.path.join(WORKSPACE, name)
    table = [
        Part("test-all", ["make", "test-all"], REPO, {"GOFLAGS": "-count=1"}, check=no_cached, memory=3000),
        Part("machines", [tool("vmtest.py"), "--config", VM_CONFIG, "--target", "both", "--run-dir", os.path.join(run_dir, "machines")], REPO, machines=True, memory=9000),
        Part("assh", go_test, project("assh"), check=no_cached, memory=1500),
        Part("vault", go_test, project("tpm2-kira-vault"), check=no_cached, memory=1500),
        Part("go-uefi-slim", go_test, project("go-uefi-slim"), check=no_cached, memory=1000),
        Part("tpm2-verifier", go_test, project("tpm2-verifier"), check=no_cached, memory=1000),
        Part("safearch-run", ["tests/run.sh"], project("safearch"), memory=1000),
        Part("safearch-vm", ["tests/vm.sh"], project("safearch"), memory=4000),
        Part("marify", ["android/scripts/test-emulator.sh"], project("marify"), memory=5000),
    ]
    return {p.name: p for p in table}


DEFAULT = ("test-all", "machines")


def affected_parts(since):
    """What AGENTS.md's table asks for the changes since then (tools/test-affected.py)."""
    spec = importlib.util.spec_from_file_location("test_affected", os.path.join(REPO, "tools", "test-affected.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rows, _, _, _ = mod.affected(since=since)
    return mod.parts_of(rows)


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


def machines_back():
    """The machines back at fresh, stopped; a run removes its own snapshots itself."""
    for name in ("arch", "debian"):
        subprocess.run([os.path.join(REPO, "tools", "localvm.py"), "revert", name, "fresh"], cwd=REPO, capture_output=True)


def run_part(p, run_dir, begun):
    log = os.path.join(run_dir, p.name + ".log")
    print(f"[proof] {p.name}: starts, log {log}", flush=True)
    p.running = True
    p.start = time.monotonic() - begun
    start = time.monotonic()
    try:
        with open(log, "wb") as f:
            rc = subprocess.run(p.argv, cwd=p.cwd, env=dict(os.environ, **p.env), stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT).returncode
    except OSError as e:
        rc, log = f"not started: {e}", None
    if p.machines:
        machines_back()
    p.seconds = time.monotonic() - start
    p.running = False
    p.ok = rc == 0
    p.why = f"exit {rc}" if rc != 0 else ""
    if p.ok and p.check:
        with open(log, errors="replace") as f:
            p.why = p.check(f.read()) or ""
        p.ok = not p.why
    print(f"[proof] {p.name}: {'ok' if p.ok else 'FAILED, ' + p.why}, {p.seconds:.0f} s", flush=True)


def run_parts(parts, run_dir, budget, begun):
    """Every part, as many at once as the budget has room for; the first of those that do not
    wait, each in the table's order. One larger than the budget runs alone."""
    waiting, running, threads = list(parts), [], []
    while waiting or running:
        running = [(p, t) for p, t in running if t.is_alive()]
        used = sum(p.memory for p, _ in running)
        for p in list(waiting):
            if not running or used + p.memory <= budget:
                t = threading.Thread(target=run_part, args=(p, run_dir, begun))
                t.start()
                running.append((p, t))
                waiting.remove(p)
                used += p.memory
        time.sleep(0.5)


def report(parts, wall, notes, run_dir):
    lines = list(notes) + ["tpm2-kira proof, " + datetime.datetime.now().isoformat(timespec="seconds"), ""]
    lines.append(f"{'part':<16}{'from':>7}{'seconds':>9}  {'least free MiB':>14}  {'disk MiB':>9}  result")
    for p in parts:
        lines.append(f"{p.name:<16}{p.start:>7.0f}{p.seconds:>9.0f}  {p.least_memory or 0:>14}  {p.least_disk or 0:>9}  {'ok' if p.ok else 'FAILED: ' + p.why}")
    lines += ["", f"{'the whole':<23}{wall:>9.0f}  (the wall clock)", f"{'sum of parts':<23}{sum(p.seconds for p in parts):>9.0f}", "",
              "ALL PASS" if all(p.ok for p in parts) else "FAILED", f"logs: {run_dir}"]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(run_dir, "report.txt"), "w") as f:
        f.write(text)
    with open(os.path.join(run_dir, "report.json"), "w") as f:
        json.dump({"wall": round(wall, 1), "notes": notes, "parts": [{"name": p.name, "start": round(p.start, 1), "seconds": round(p.seconds, 1), "ok": p.ok, "why": p.why,
                   "least_memory_mib": p.least_memory, "least_disk_mib": p.least_disk} for p in parts]}, f, indent=1)
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", help="where the report and the logs land (default .local/runs/proof-<time>)")
    ap.add_argument("--since", help="add what AGENTS.md's table asks for the changes since this time (git's --before; tools/test-affected.py)")
    ap.add_argument("--with", dest="more", default="", help="parts on top: " + ",".join(n for n in parts_table("") if n not in DEFAULT))
    ap.add_argument("--only", help="these parts alone: no final proof")
    ap.add_argument("--one-at-a-time", action="store_true", help="the parts one after the other: what they take alone")
    args = ap.parse_args()
    run_dir = os.path.abspath(args.run_dir or os.path.join(LOCAL, "runs", "proof-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    os.makedirs(run_dir, exist_ok=True)
    table = parts_table(run_dir)
    wanted = args.only.split(",") if args.only else list(DEFAULT) + [n for n in args.more.split(",") if n]
    if args.since and not args.only:
        wanted += [p for p in affected_parts(args.since) if p not in wanted]
    unknown = [n for n in wanted if n not in table]
    if unknown:
        ap.error("no such part: " + ", ".join(unknown) + "; there are " + ", ".join(table))
    parts = [p for n, p in table.items() if n in wanted]
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
    threading.Thread(target=sample_host, args=(parts, stop, LOCAL), daemon=True).start()
    start = time.monotonic()
    run_parts(parts, run_dir, 0 if args.one_at_a_time else MEMORY_BUDGET, start)
    stop.set()
    print(report(parts, time.monotonic() - start, notes, run_dir), flush=True)
    return 0 if all(p.ok for p in parts) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
