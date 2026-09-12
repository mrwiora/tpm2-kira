#!/usr/bin/env python3
"""PCR reconstruction and diagnosis for tpm2-kira.

Two subcommands over one shared core:

  replay   Replay the firmware event log into PCR values.
  verify   Reconstruct the full chain (firmware log + systemd's userspace
           measurements) and explain every difference against the live TPM.

The firmware event log is root-only, so most invocations need sudo:

    sudo pcrtool.py verify
    sudo pcrtool.py replay --pcr 7 --verbose
    pcrtool.py replay --eventlog dumped.yaml        # a pre-dumped YAML needs no TPM
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict

import yaml

DEFAULT_EVENTLOG = "/sys/kernel/security/tpm0/binary_bios_measurements"
DEFAULT_MEASURE_LOG = "/run/log/systemd/tpm2-measure.log"

BANKS = ("sha256", "sha1")

# systemd-pcrextend hashes a plain WORD as the literal string bytes: no NUL
# terminator, no machine-id, no salt (src/pcrextend/pcrextend.c passes
# IOVEC_MAKE(word, strlen(word)) with secret == NULL), so these are universal
# constants. Host-specific words (--machine-id, --file-system=, --product-id,
# --login=) take a different code path and are deliberately not listed.
KNOWN_WORDS = (
    "os-separator",
    "enter-initrd",
    "leave-initrd",
    "sysinit",
    "ready",
    "shutdown",
    "final",
)

# PCRs systemd-pcrosseparator.service extends (see its ExecStart).
SEPARATOR_PCRS = (0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14)

# TPM2_Startup resets the DRTM PCRs to all-ones, not to zero.
DRTM_PCRS = range(17, 23)

# PCRs carrying host-specific measurements this tool does not model, so an
# unexplained verdict there is not a finding.
EXPECTED_HOST_SPECIFIC = {15}

STARTUP_LOCALITY_PREFIX = "537461727475704c6f63616c697479"  # "StartupLocality"


# ---------------------------------------------------------------- primitives


def digest_of(word, bank):
    return hashlib.new(bank, word.encode()).digest()


def extend(value, digest, bank):
    return hashlib.new(bank, value + digest).digest()


def initial_value(index, bank, locality=None):
    """PCR reset value. PCR 0 carries the startup locality; 17-22 reset to ones."""
    size = hashlib.new(bank).digest_size
    if index == 0 and locality is not None:
        return b"\x00" * (size - 1) + bytes([locality])
    if index in DRTM_PCRS:
        return b"\xff" * size
    return b"\x00" * size


# ------------------------------------------------------------ firmware log


def load_eventlog(path):
    """Parse a TCG event log, from either the binary log or a tpm2_eventlog dump."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(64)
    except FileNotFoundError:
        sys.exit(f"error: no such event log: {path}")
    except PermissionError:
        sys.exit(f"error: {path} is root-only; re-run with sudo")

    if head.lstrip().startswith((b"---", b"version:", b"events:")):
        with open(path, "r") as handle:
            text = handle.read()
    else:
        try:
            proc = subprocess.run(
                ["tpm2_eventlog", path], capture_output=True, text=True, check=True
            )
        except FileNotFoundError:
            sys.exit("error: tpm2_eventlog not found (install tpm2-tools)")
        except subprocess.CalledProcessError as exc:
            sys.exit(f"error: tpm2_eventlog failed: {exc.stderr.strip()}")
        text = proc.stdout

    # WARN: lines are not YAML; comment them out rather than dropping them.
    cleaned = "".join(
        ("# " + line) if line.strip().startswith("WARN:") else line
        for line in text.splitlines(keepends=True)
    )
    try:
        parsed = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        sys.exit(f"error: could not parse the event log: {exc}")
    if not parsed or "events" not in parsed:
        sys.exit(f"error: {path} contains no 'events' section")
    return parsed


def find_startup_locality(eventlog):
    """PCR 0 starts at the locality value rather than zero, per the TCG spec.

    The StartupLocality EV_NO_ACTION event carries it and does not extend PCR 0.
    """
    for event in eventlog["events"]:
        if (
            event.get("PCRIndex") == 0
            and event.get("EventType") == "EV_NO_ACTION"
            and event.get("EventSize") == 17
        ):
            data = str(event.get("Event", ""))
            if data.startswith(STARTUP_LOCALITY_PREFIX):
                return int(data[-2:], 16)
    return None


def event_digest(event, bank):
    """Return this event's digest in the requested bank, or None."""
    digests = event.get("Digests")
    if isinstance(digests, list):
        for entry in digests:
            if str(entry.get("AlgorithmId", "")).lower() == bank:
                return bytes.fromhex(entry["Digest"])
        return None
    # Older single-digest layout.
    raw = event.get("Digest")
    expected = hashlib.new(bank).digest_size * 2
    if isinstance(raw, str) and len(raw) == expected:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None
    return None


def replay_eventlog(eventlog, bank, only=None, verbose=False):
    """Replay the log.

    Returns (values, extend_counts, locality). extend_counts distinguishes
    "left at its reset value" from "no digests in this bank", which is the
    difference between a correct zero and a silently wrong one.
    """
    locality = find_startup_locality(eventlog)
    by_pcr = defaultdict(list)

    for event in eventlog["events"]:
        index = event.get("PCRIndex")
        if index is None or (only is not None and index != only):
            continue
        if event.get("EventType") == "EV_NO_ACTION":
            continue  # informational, never extends
        by_pcr[index].append(event)

    values, counts = {}, {}
    for index in sorted(by_pcr):
        value = initial_value(index, bank, locality)
        applied = 0
        if verbose:
            print(f"\nPCR{index}")
            print(f"  initial               {value.hex()}")
        for event in by_pcr[index]:
            digest = event_digest(event, bank)
            if digest is None:
                continue
            value = extend(value, digest, bank)
            applied += 1
            if verbose:
                print(
                    f"  event {str(event.get('EventNum', '?')):>3}"
                    f" {event.get('EventType', '?'):<32} {digest.hex()[:16]}..."
                )
                print(f"    -> {value.hex()}")
        values[index] = value
        counts[index] = applied

    return values, counts, locality


# --------------------------------------------------- systemd measurement log


def parse_measure_log(path, bank):
    """Parse systemd's userspace measurement log (JSON-seq, RS separated).

    Returns (entries, unparsed_count) or (None, 0) when the file is absent.
    Record structure is probed rather than assumed, so a format change shows up
    as unparsed records instead of silently wrong output.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return None, 0
    except PermissionError:
        sys.exit(f"error: {path} is root-only; re-run with sudo")

    chunks = [c for c in raw.split("\x1e") if c.strip()]
    if len(chunks) <= 1:
        chunks = [line for line in raw.splitlines() if line.strip()]

    entries, unparsed = [], 0
    for chunk in chunks:
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            unparsed += 1
            continue

        pcr = obj.get("pcr")
        digest = None
        for entry in obj.get("digests") or []:
            alg = str(entry.get("hashAlg", entry.get("algorithmId", ""))).lower()
            if alg == bank and entry.get("digest"):
                digest = bytes.fromhex(entry["digest"])
        content = obj.get("content") or {}
        description = (
            content.get("string")
            or content.get("event")
            or obj.get("description")
            or "?"
        )
        if pcr is None or digest is None:
            # NvPCR records carry no 'pcr' field; they are not PCR extends.
            unparsed += 1
            continue
        entries.append((int(pcr), digest, str(description)))

    return entries, unparsed


# ------------------------------------------------------------- live registers


def read_live_pcrs(bank):
    try:
        proc = subprocess.run(
            ["tpm2_pcrread", bank], capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        sys.exit("error: tpm2_pcrread not found (install tpm2-tools)")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"error: tpm2_pcrread failed: {exc.stderr.strip()}")

    live = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if ":" not in line or not line.split(":")[0].strip().isdigit():
            continue
        index, value = line.split(":", 1)
        value = value.strip()
        if value.lower().startswith("0x"):
            live[int(index)] = bytes.fromhex(value[2:])
    return live


def explain(start, target, bank, max_depth):
    """Shortest chain of KNOWN_WORDS extending start into target, or None."""
    if start == target:
        return []
    digests = {word: digest_of(word, bank) for word in KNOWN_WORDS}
    frontier = [(start, [])]
    for _ in range(max_depth):
        nxt = []
        for value, path in frontier:
            for word, digest in digests.items():
                new_value = extend(value, digest, bank)
                new_path = path + [word]
                if new_value == target:
                    return new_path
                nxt.append((new_value, new_path))
        frontier = nxt
    return None


# ---------------------------------------------------------------- subcommands


def cmd_replay(args):
    eventlog = load_eventlog(args.eventlog)
    values, counts, locality = replay_eventlog(
        eventlog, args.bank, only=args.pcr, verbose=args.verbose
    )

    if not values:
        target = "any PCR" if args.pcr is None else f"PCR {args.pcr}"
        sys.exit(f"no events for {target} in {args.eventlog}")

    if args.verbose:
        print()
    print(f"bank                  : {args.bank}")
    print(f"StartupLocality (PCR0): {locality}")
    print()
    print(f"{'PCR':>4}  {'extends':>7}  value")
    print("-" * 78)
    for index in sorted(values):
        print(f"{index:>4}  {counts[index]:>7}  {values[index].hex()}")

    silent = [i for i, n in counts.items() if n == 0]
    if silent:
        print()
        print(f"WARNING: PCRs {silent} received no {args.bank} digests from this log.")
        print("Their values above are just the reset value, not a measurement.")
        return 1
    return 0


def cmd_verify(args):
    eventlog = load_eventlog(args.eventlog)
    replay, counts, locality = replay_eventlog(eventlog, args.bank)
    live = read_live_pcrs(args.bank)

    print(f"bank                  : {args.bank}")
    print(f"StartupLocality (PCR0): {locality}")
    print(f'H("os-separator")     : {digest_of("os-separator", args.bank).hex()}')
    print()

    header = f"{'PCR':>4}  {'replay':<16}  {'live':<16}  verdict"
    print(header)
    print("-" * len(header))

    findings = []
    for index in sorted(set(replay) | set(live)):
        if index not in live:
            continue
        replay_value = replay.get(index, initial_value(index, args.bank, locality))
        path = explain(replay_value, live[index], args.bank, args.depth)

        if path == []:
            verdict = "unchanged since firmware"
        elif path == ["os-separator"]:
            verdict = "os-separator (x1)"
        elif path is not None:
            verdict = "explained: " + " + ".join(path)
        else:
            verdict = "UNEXPLAINED"
            if index not in EXPECTED_HOST_SPECIFIC:
                findings.append((index, verdict))

        print(
            f"{index:>4}  {replay_value.hex()[:16]:<16}  "
            f"{live[index].hex()[:16]:<16}  {verdict}"
        )

    if findings:
        print()
        print("Not explained by firmware plus known systemd words:")
        for index, verdict in findings:
            print(f"  PCR {index}: {verdict}")

    return report_full_chain(args, replay, counts, live, locality, findings)


def report_full_chain(args, replay, counts, live, locality, findings):
    entries, unparsed = parse_measure_log(args.measure_log, args.bank)
    print()
    print("=" * 72)
    print(f"FULL CHAIN (firmware log + {args.measure_log})")
    print("=" * 72)
    if entries is None:
        print(f"{args.measure_log} not present; skipping full-chain reconstruction.")
        return 1 if findings else 0
    if unparsed:
        print(f"note: {unparsed} record(s) carried no PCR extend (e.g. NvPCR records)")

    by_pcr = defaultdict(list)
    for pcr, digest, description in entries:
        by_pcr[pcr].append((digest, description))

    print(f"{len(entries)} userspace measurement(s) recorded")
    print()
    unresolved = []
    for index in sorted(set(replay) | set(live) | set(by_pcr)):
        if index not in live:
            continue
        value = replay.get(index, initial_value(index, args.bank, locality))
        applied = []
        for digest, description in by_pcr.get(index, []):
            value = extend(value, digest, args.bank)
            applied.append(description)

        ok = value == live[index]
        if not ok and index not in EXPECTED_HOST_SPECIFIC:
            unresolved.append(index)
        chain = " + ".join(applied) if applied else "(firmware only)"
        print(f"{index:>4}  {'OK' if ok else 'MISMATCH':<9} {chain}")
        if not ok:
            print(f"        expected {value.hex()}")
            print(f"        actual   {live[index].hex()}")

    silent = [i for i, n in counts.items() if n == 0]
    if silent:
        print()
        print(f"WARNING: PCRs {silent} received no {args.bank} digests from the")
        print("firmware log. Sealing them with the eventlog source would bind to")
        print("the reset value. Use the register source, or --bank sha1.")

    print()
    if unresolved:
        print(f"PCRs still unaccounted for after the full chain: {unresolved}")
        print("=> something outside firmware and systemd extended these.")
        return 1
    print("Full chain reconstructs every PCR. Nothing unaccounted for.")
    return 1 if findings else 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--eventlog", default=DEFAULT_EVENTLOG,
                        help="binary event log or a tpm2_eventlog YAML dump")
    parser.add_argument("--bank", default="sha256", choices=BANKS)
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="replay the firmware event log")
    replay.add_argument("--pcr", type=int, help="only this PCR index")
    replay.add_argument("--verbose", action="store_true",
                        help="show every extension step")
    replay.set_defaults(func=cmd_replay)

    verify = sub.add_parser(
        "verify", help="reconstruct the full chain and compare against the live TPM"
    )
    verify.add_argument("--measure-log", default=DEFAULT_MEASURE_LOG)
    verify.add_argument("--depth", type=int, default=4,
                        help="max chained known-word extends to search (default: 4)")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
