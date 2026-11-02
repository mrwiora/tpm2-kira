#!/usr/bin/env python3
"""The proof, as one command: 15 minutes wall clock, the target; 16 a hard limit.

    tools/proof.py                            # the proof, from the snapshot fresh
    tools/proof.py --since '2026-11-03 09:00' # and, after it, what AGENTS.md's table asks for the batch
    tools/proof.py --with marify,safearch-vm  # and, after it, these
    tools/proof.py --all                      # before a release: every scenario and every part
    tools/proof.py --only test-all            # these parts alone: NO FINAL PROOF

The proof is DEFAULT: the two machines in parallel, each through the scenarios that have a budget
(tools/vmtest.py's SCENARIOS, measured seconds per machine), and beside them, once the machines'
setups are done, what needs no VM: the setups are what they would slow. At LIMIT it stops what still
runs and fails, and says which scenario it was in and which went over their budgets. Past TARGET and
within the limit it passes and names what went over. A scenario over its budget within the target is
printed, and no failure.
Parts on top of the proof run after it, outside the limit; so does everything --all adds, with no
limit at all: what leaves the proof is named there, never lost.

A part that fails does not stop the others. The machines take .local/vms/vm.lock, and are reverted
to fresh and stopped at their end.

The report (report.txt, report.json in the run's directory, --run-dir or
.local/runs/proof-<time>/) names every part with its seconds and result, every scenario against its
budget, the host's least free memory and disk while each part ran, and the wall clock of the whole.
Its first line says when it is no final proof. Each part's output is <part>.log there, the
machines' reports under machines/.
"""

import argparse
import datetime
import fcntl
import importlib.util
import json
import os
import re
import shutil
import signal
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
TARGET = 15 * 60  # the proof's seconds, wall clock; over it the report names what went over
LIMIT = 16 * 60  # at it the run stops and fails
MACHINES = ("arch", "debian")
VAULT_CONTAINER = "tpm2-kira-vmtest-vault"


class Part:
    """A thing a proof runs. machines: it takes the VMs, under the lock. check: why
    a finished log is a failure all the same, or None. memory: MiB it may take at its
    height, measured (docs/TESTING.md)."""

    def __init__(self, name, argv, cwd, env=None, machines=False, check=None, memory=2000):
        self.name, self.argv, self.cwd, self.env = name, argv, cwd, env or {}
        self.machines, self.check, self.memory = machines, check, memory
        self.seconds, self.start, self.ok, self.why = 0.0, 0.0, None, ""
        self.after_setup = False  # waits for the machines' setups, when machines run
        self.least_memory, self.least_disk = None, None
        self.running = False
        self.process = None
        self.stopped = False


def no_cached(log):
    """A result marked (cached) has tested nothing (AGENTS.md)."""
    hits = [l for l in log.splitlines() if "(cached)" in l]
    return f"{len(hits)} result(s) (cached): {hits[0]}" if hits else None


def parts_table(run_dir, everything=False):
    """Every part there is, by name."""
    tool = lambda name: os.path.join(REPO, "tools", name)
    go_test = ["go", "test", "-count=1", "./..."]
    project = lambda name: os.path.join(WORKSPACE, name)
    machines = [tool("vmtest.py"), "--config", VM_CONFIG, "--target", "both", "--run-dir", os.path.join(run_dir, "machines")] + (["--all"] if everything else [])
    table = [
        Part("test-all", ["make", "test-all"], REPO, {"GOFLAGS": "-count=1"}, check=no_cached, memory=3000),
        Part("machines", machines, REPO, machines=True, memory=8500),
        Part("assh", go_test, project("assh"), check=no_cached, memory=1000),
        Part("vault", go_test, project("tpm2-kira-vault"), check=no_cached, memory=500),
        Part("safearch-run", ["tests/run.sh"], project("safearch"), memory=500),
        Part("go-uefi-slim", go_test, project("go-uefi-slim"), check=no_cached, memory=1000),
        Part("tpm2-verifier", go_test, project("tpm2-verifier"), check=no_cached, memory=1000),
        Part("safearch-vm", ["tests/vm.sh"], project("safearch"), memory=3500),
        Part("marify", ["android/scripts/test-emulator.sh"], project("marify"), memory=6600),
    ]
    return {p.name: p for p in table}


DEFAULT = ("test-all", "machines", "assh", "vault", "safearch-run")


def affected_parts(since):
    """What AGENTS.md's table asks for the changes since then (tools/test-affected.py)."""
    spec = importlib.util.spec_from_file_location("test_affected", os.path.join(REPO, "tools", "test-affected.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rows, _, _, _ = mod.affected(since=since)
    return mod.parts_of(rows)


def assh_is_pinned():
    """Whether safearch's submodule is aSSH's checkout, nothing uncommitted in it."""
    head = lambda d: subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    checkout = os.path.join(WORKSPACE, "assh")
    dirty = subprocess.run(["git", "-C", checkout, "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    return head(checkout) == head(os.path.join(WORKSPACE, "safearch", "assh")) and not dirty


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


def machines_back(stopped):
    """The machines back at fresh, stopped. A run removes its own snapshots itself, one stopped
    at the limit could not: they go here, with its vault."""
    if stopped:
        subprocess.run(["docker", "rm", "-f", VAULT_CONTAINER], capture_output=True)
        subprocess.run([os.path.join(REPO, "tools", "vmtest.py"), "--config", VM_CONFIG, "--target", "both", "--drop-setup"], cwd=REPO, capture_output=True)
    for name in MACHINES:
        subprocess.run([os.path.join(REPO, "tools", "localvm.py"), "revert", name, "fresh"], cwd=REPO, capture_output=True)


def run_part(p, run_dir, begun):
    log = os.path.join(run_dir, p.name + ".log")
    print(f"[proof] {p.name}: starts, log {log}", flush=True)
    p.running = True
    p.start = time.monotonic() - begun
    start = time.monotonic()
    try:
        with open(log, "wb") as f:
            # A session of its own: the limit stops the part with all it started.
            p.process = subprocess.Popen(p.argv, cwd=p.cwd, env=dict(os.environ, **p.env), stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
            rc = p.process.wait()
    except OSError as e:
        rc, log = f"not started: {e}", None
    if p.machines:
        machines_back(p.stopped)
    p.seconds = time.monotonic() - start
    p.running = False
    p.ok = rc == 0
    p.why = "stopped at the limit" if p.stopped else f"exit {rc}" if rc != 0 else ""
    if p.ok and p.check:
        with open(log, errors="replace") as f:
            p.why = p.check(f.read()) or ""
        p.ok = not p.why
    print(f"[proof] {p.name}: {'ok' if p.ok else 'FAILED, ' + p.why}, {p.seconds:.0f} s", flush=True)


def stop_part(p):
    """A part at the limit, with everything it started."""
    p.stopped = True
    if p.process:
        try:
            os.killpg(p.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def setups_done(run_dir):
    """Whether no machine is still in its setup, by what each has written."""
    scenarios = read_scenarios(run_dir)
    return all(any(d["name"] == "setup" and d["result"] != "running" for d in scenarios[name]) for name in MACHINES)


def held(p, parts, run_dir):
    """Whether a part still waits for the machines' setups: until those are done, or the machines
    have ended without."""
    if not p.after_setup:
        return False
    machines = [x for x in parts if x.machines]
    return bool(machines) and machines[0].ok is None and not setups_done(run_dir)


def run_parts(parts, run_dir, budget, begun, limit=None):
    """Every part, as many at once as the budget has room for; the first of those that do not
    wait, each in the table's order. One larger than the budget runs alone. At the limit, seconds
    after begun, what runs is stopped and what waits never starts."""
    waiting, running = list(parts), []
    while waiting or running:
        running = [(p, t) for p, t in running if t.is_alive()]
        if limit is not None and time.monotonic() - begun > limit:
            for p, _ in running:
                if not p.stopped:
                    stop_part(p)
            for p in waiting:
                p.ok, p.why = False, "not started: the limit"
            waiting = []
        used = sum(p.memory for p, _ in running)
        for p in list(waiting):
            if not held(p, parts, run_dir) and (not running or used + p.memory <= budget):
                t = threading.Thread(target=run_part, args=(p, run_dir, begun))
                t.start()
                running.append((p, t))
                waiting.remove(p)
                used += p.memory
        time.sleep(0.5)


def read_scenarios(run_dir):
    """What each machine's run says of its scenarios, as far as it came."""
    out = {}
    for name in MACHINES:
        try:
            with open(os.path.join(run_dir, "machines", name, "scenarios.json")) as f:
                out[name] = json.load(f)
        except (OSError, ValueError):
            out[name] = []
    return out


def over_budget(scenarios):
    """Which scenarios went over their budgets, and which were still running: words for a report."""
    over, running = [], []
    for machine, done in scenarios.items():
        for d in done:
            if d["result"] == "running":
                running.append(f"{machine} {d['name']}" + (f" (budget {d['budget']} s)" if d["budget"] else ""))
            elif d["budget"] and d["seconds"] > d["budget"]:
                over.append(f"{machine} {d['name']} {d['seconds']:.0f} s of {d['budget']}")
    return over, running


def scenario_lines(scenarios):
    lines = [f"{'scenario':<20}" + "".join(f"{m + ' s / budget':>20}" for m in scenarios) + "  result"]
    names = []
    for done in scenarios.values():
        names += [d["name"] for d in done if d["name"] not in names]
    for name in names:
        row, results = f"{name:<20}", []
        for machine, done in scenarios.items():
            d = next((x for x in done if x["name"] == name), None)
            if not d:
                row += f"{'-':>20}"
                continue
            seconds = "-" if d["seconds"] is None else f"{d['seconds']:.0f}"
            over = " OVER" if d["budget"] and d["seconds"] is not None and d["seconds"] > d["budget"] else ""
            row += f"{seconds + ' / ' + str(d['budget'] or '-') + over:>20}"
            results.append(f"{machine} {d['result']}")
        lines.append(row + "  " + ", ".join(results))
    return lines


def report(parts, wall, notes, run_dir, limit=None, proof_wall=None, target=None):
    scenarios = read_scenarios(run_dir)
    over, running = over_budget(scenarios)
    lines = list(notes) + ["tpm2-kira proof, " + datetime.datetime.now().isoformat(timespec="seconds"), ""]
    lines.append(f"{'part':<16}{'from':>7}{'seconds':>9}  {'least free MiB':>14}  {'disk MiB':>9}  result")
    for p in parts:
        lines.append(f"{p.name:<16}{p.start:>7.0f}{p.seconds:>9.0f}  {p.least_memory or 0:>14}  {p.least_disk or 0:>9}  {'ok' if p.ok else 'FAILED: ' + p.why}")
    if any(scenarios.values()):
        lines += [""] + scenario_lines(scenarios)
    lines += ["", f"{'the whole':<23}{wall:>9.0f}  (the wall clock)", f"{'sum of parts':<23}{sum(p.seconds for p in parts):>9.0f}"]
    late = limit is not None and proof_wall is not None and proof_wall > limit
    if limit is not None:
        lines.append(f"{'the proof':<23}{proof_wall:>9.0f}  target {target if target is not None else '-'}, limit {limit}")
    if late:
        lines += ["", f"OVER THE LIMIT: {proof_wall:.0f} s of {limit}.", "  over budget: " + (", ".join(over) or "none"), "  stopped in: " + (", ".join(running) or "nothing")]
    elif target is not None and proof_wall is not None and proof_wall > target:
        lines += ["", f"OVER THE TARGET, within the limit: {proof_wall:.0f} s of {target}.", "  over budget: " + (", ".join(over) or "none")]
    elif over:
        lines += ["", "over budget, within the target: " + ", ".join(over)]
    ok = all(p.ok for p in parts) and not late
    lines += ["", "ALL PASS" if ok else "FAILED", f"logs: {run_dir}"]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(run_dir, "report.txt"), "w") as f:
        f.write(text)
    with open(os.path.join(run_dir, "report.json"), "w") as f:
        json.dump({"wall": round(wall, 1), "proof_wall": None if proof_wall is None else round(proof_wall, 1), "limit": limit, "notes": notes, "over_budget": over, "stopped_in": running,
                   "scenarios": scenarios, "parts": [{"name": p.name, "start": round(p.start, 1), "seconds": round(p.seconds, 1), "ok": p.ok, "why": p.why,
                   "least_memory_mib": p.least_memory, "least_disk_mib": p.least_disk} for p in parts]}, f, indent=1)
    return text, ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", help="where the report and the logs land (default .local/runs/proof-<time>)")
    ap.add_argument("--all", action="store_true", help="before a release: every scenario of the machines and every part, no limit")
    ap.add_argument("--since", help="add what AGENTS.md's table asks for the changes since this time (git's --before; tools/test-affected.py)")
    ap.add_argument("--with", dest="more", default="", help="parts on top: " + ",".join(n for n in parts_table("") if n not in DEFAULT))
    ap.add_argument("--only", help="these parts alone: no final proof")
    ap.add_argument("--one-at-a-time", action="store_true", help="the parts one after the other: what they take alone; no limit: no final proof")
    args = ap.parse_args()
    run_dir = os.path.abspath(args.run_dir or os.path.join(LOCAL, "runs", "proof-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    os.makedirs(run_dir, exist_ok=True)
    table = parts_table(run_dir, args.all)
    extra = [n for n in table if n not in DEFAULT] if args.all else [n for n in args.more.split(",") if n]
    if args.since and not args.only:
        extra += [p for p in affected_parts(args.since) if p not in extra]
    wanted = args.only.split(",") if args.only else list(DEFAULT) + extra
    unknown = [n for n in wanted if n not in table]
    if unknown:
        ap.error("no such part: " + ", ".join(unknown) + "; there are " + ", ".join(table))
    notes = [NOT_FINAL + "--only " + args.only] if args.only else [NOT_FINAL + "--one-at-a-time"] if args.one_at_a_time else []
    if "assh" in wanted and "safearch-run" in wanted and assh_is_pinned():
        # tests/run.sh runs aSSH's own tests on its pin: the same commit, nothing more to run.
        wanted.remove("assh")
        print("[proof] assh: its tests run in safearch-run, the pin being the checkout", flush=True)
    parts = [p for n, p in table.items() if n in wanted]
    for p in parts:
        p.after_setup = not p.machines and p.name in DEFAULT
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
    budget = 0 if args.one_at_a_time else MEMORY_BUDGET
    limited = not args.only and not args.all and not args.one_at_a_time
    first = [p for p in parts if p.name in DEFAULT] if not args.only else parts
    run_parts(first, run_dir, budget, start, LIMIT if limited else None)
    proof_wall = time.monotonic() - start
    if proof_wall <= LIMIT or not limited:
        run_parts([p for p in parts if p not in first], run_dir, budget, start)
    stop.set()
    text, ok = report(parts, time.monotonic() - start, notes, run_dir, LIMIT if limited else None, proof_wall if limited else None, TARGET if limited else None)
    print(text, flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
