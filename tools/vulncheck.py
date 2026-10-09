#!/usr/bin/env python3
"""govulncheck with a list of findings that are known to be wrong.

    tools/vulncheck.py ./...
    tools/vulncheck.py -mode binary dist/tpm2-kira-linux-amd64

The arguments go to govulncheck as they are. A vulnerability counts when the
code calls a vulnerable symbol (govulncheck's own rule); one in a module the
code requires but never calls into is listed and does not fail the run.

tools/vulncheck-ignore names the vulnerabilities the Go vulnerability
database reports wrongly, one per line, `GO-ID  why`, with the proof in the
why. An entry that no longer shows up is reported so it can be dropped.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
IGNORE_FILE = os.path.join(HERE, "vulncheck-ignore")


def read_ignores():
    ignores = {}
    if not os.path.exists(IGNORE_FILE):
        return ignores
    with open(IGNORE_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            vuln_id, _, why = line.partition(" ")
            ignores[vuln_id] = why.strip()
    return ignores


def scan(args):
    """The JSON stream of govulncheck, as a list of objects."""
    proc = subprocess.run(
        ["govulncheck", "-format", "json", *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    # 0: nothing called; 3: vulnerable symbols called. Anything else failed.
    if proc.returncode not in (0, 3):
        sys.stderr.write(proc.stderr)
        sys.exit(f"govulncheck exited with {proc.returncode}")
    objects = []
    decoder = json.JSONDecoder()
    text = proc.stdout
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        obj, pos = decoder.raw_decode(text, pos)
        objects.append(obj)
    return objects


def place(frame):
    """A frame of a trace as `file:line: pkg.Func`."""
    name = frame.get("function", "")
    if frame.get("receiver"):
        name = frame["receiver"] + "." + name
    pkg = frame.get("package", frame.get("module", ""))
    name = pkg.rsplit("/", 1)[-1] + "." + name if name else pkg
    p = frame.get("position")
    if p:
        return f"{p['filename']}:{p['line']}: {name}"
    return name


def main():
    args = sys.argv[1:] or ["./..."]
    ignores = read_ignores()
    osvs = {}
    called = {}   # id -> findings with a vulnerable symbol in the call graph
    required = {}  # id -> module@version, no call into it
    for obj in scan(args):
        if "osv" in obj:
            osvs[obj["osv"]["id"]] = obj["osv"]
        elif "finding" in obj:
            f = obj["finding"]
            top = f["trace"][0]
            if top.get("function"):
                called.setdefault(f["osv"], []).append(f)
            else:
                required.setdefault(f["osv"], f"{top['module']}@{top.get('version', '?')}")

    failed = 0
    for vuln_id in sorted(called, reverse=True):
        osv = osvs.get(vuln_id, {})
        top = called[vuln_id][0]["trace"][0]
        fixed = called[vuln_id][0].get("fixed_version", "none")
        why = ignores.get(vuln_id)
        verdict = "ignored" if why else "AFFECTED"
        if not why:
            failed += 1
        print(f"{verdict}: {vuln_id} in {top['module']}@{top.get('version', '?')}, fixed in {fixed}")
        print(f"  {osv.get('summary', '')}")
        print(f"  https://pkg.go.dev/vuln/{vuln_id}")
        if why:
            print(f"  ignored: {why}")
        # The call path, from the code to the symbol; a binary scan knows
        # only the symbol.
        seen = set()
        for f in called[vuln_id]:
            trace = f["trace"]
            line = place(trace[0]) if len(trace) == 1 else f"{place(trace[-1])} -> {place(trace[0])}"
            if line in seen:
                continue
            seen.add(line)
            print(f"  {line}")
            if len(seen) == 5:
                break
        print()

    required = {k: v for k, v in required.items() if k not in called}
    if required:
        print(f"{len(required)} in modules required but not called into:")
        for vuln_id in sorted(required, reverse=True):
            print(f"  {vuln_id} {required[vuln_id]}: {osvs.get(vuln_id, {}).get('summary', '')}")
        print()

    for vuln_id, why in ignores.items():
        if vuln_id not in called:
            print(f"note: {vuln_id} is in {os.path.relpath(IGNORE_FILE)} but no longer reported; drop it")

    sys.stdout.flush()
    if failed:
        sys.exit(f"{failed} vulnerabilit{'y' if failed == 1 else 'ies'} called into")
    print("no vulnerability is called into")


if __name__ == "__main__":
    main()
