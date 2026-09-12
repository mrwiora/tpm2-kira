#!/usr/bin/env python3
"""Check which OS-side extends sit between the firmware event log and the live PCRs.

Replays /sys/kernel/security/tpm0/binary_bios_measurements, reads the live PCR
registers, and tries to explain every difference as a sequence of known
systemd-pcrextend measurements. Anything it cannot explain is reported loudly --
that is the point of the script: to find out whether systemd's 'os-separator' is
really the ONLY addition on this host, or whether there are others.

Must run as root; the firmware event log is root-only.

    sudo python3 verify_os_separator.py
"""

import argparse
import hashlib
import json
import subprocess
import sys
from collections import defaultdict

import yaml

DEFAULT_EVENTLOG = "/sys/kernel/security/tpm0/binary_bios_measurements"
DEFAULT_MEASURE_LOG = "/run/log/systemd/tpm2-measure.log"

# systemd-pcrextend hashes a plain WORD as the literal string bytes: no NUL
# terminator, no machine-id, no salt (src/pcrextend/pcrextend.c:
# extend_pcr_now(..., &IOVEC_MAKE(word, strlen(word)), NULL, event)).
# Host-specific words (--machine-id, --file-system=, --product-id, --login=)
# take a different code path and are NOT listed here.
KNOWN_WORDS = [
    "os-separator",
    "enter-initrd",
    "leave-initrd",
    "sysinit",
    "ready",
    "shutdown",
    "final",
]

# PCRs systemd-pcrosseparator.service extends (see its ExecStart).
SEPARATOR_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14]

# TPM2_Startup resets the DRTM PCRs to all-ones, not to zero.
DRTM_PCRS = range(17, 23)

# PCRs that are expected to carry host-specific measurements we deliberately do
# not model, so an "unexplained" verdict there is not a finding.
EXPECTED_HOST_SPECIFIC = {15}


def initial_value(index, bank, locality):
    size = hashlib.new(bank).digest_size
    if index == 0 and locality is not None:
        return b"\x00" * (size - 1) + bytes([locality])
    if index in DRTM_PCRS:
        return b"\xff" * size
    return b"\x00" * size


def digest_of(word, bank):
    return hashlib.new(bank, word.encode()).digest()


def extend(value, digest, bank):
    return hashlib.new(bank, value + digest).digest()


def read_eventlog(path):
    try:
        proc = subprocess.run(
            ["tpm2_eventlog", path], capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        sys.exit("error: tpm2_eventlog not found (install tpm2-tools)")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"error: tpm2_eventlog failed: {exc.stderr.strip()}")

    # WARN: lines are not YAML; comment them out rather than dropping them.
    cleaned = "".join(
        ("# " + line) if line.strip().startswith("WARN:") else line
        for line in proc.stdout.splitlines(keepends=True)
    )
    try:
        return yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        sys.exit(f"error: could not parse tpm2_eventlog output: {exc}")


def replay_eventlog(eventlog, bank):
    """Return {pcr_index: digest} from replaying the firmware log."""
    pcr_events = defaultdict(list)
    locality = None

    for event in eventlog.get("events", []):
        index = event.get("PCRIndex")
        if index is None:
            continue

        # EV_NO_ACTION never extends. The StartupLocality variant instead sets
        # PCR0's initial value to 31 zero bytes + the locality byte.
        if event.get("EventType") == "EV_NO_ACTION":
            if index == 0 and event.get("EventSize") == 17:
                data = str(event.get("Event", ""))
                if data.startswith("537461727475704c6f63616c697479"):
                    locality = int(data[-2:], 16)
            continue

        for entry in event.get("Digests", []):
            if str(entry.get("AlgorithmId", "")).lower() == bank:
                pcr_events[index].append(bytes.fromhex(entry["Digest"]))

    values = {}
    for index, digests in pcr_events.items():
        value = initial_value(index, bank, locality)
        for digest in digests:
            value = extend(value, digest, bank)
        values[index] = value

    return values, locality


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
    """Find the shortest sequence of KNOWN_WORDS extending start into target."""
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


def parse_measure_log(path, bank):
    """Return [(pcr, digest, description)] from systemd's userspace measurement log.

    The file is JSON-seq (RS-separated); fall back to line-delimited JSON.
    Structure is probed rather than assumed, so a format change shows up as
    unparsed records instead of silently wrong output.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return None, 0
    except PermissionError:
        sys.exit(f"error: {path} is root-only; run this script with sudo")

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
            unparsed += 1
            continue
        entries.append((int(pcr), digest, str(description)))

    return entries, unparsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eventlog", default=DEFAULT_EVENTLOG)
    parser.add_argument("--measure-log", default=DEFAULT_MEASURE_LOG)
    parser.add_argument("--bank", default="sha256", choices=["sha256", "sha1"])
    parser.add_argument(
        "--depth",
        type=int,
        default=4,
        help="max number of chained known-word extends to search (default: 4)",
    )
    args = parser.parse_args()

    eventlog = read_eventlog(args.eventlog)
    replay, locality = replay_eventlog(eventlog, args.bank)
    live = read_live_pcrs(args.bank)

    sep = digest_of("os-separator", args.bank).hex()
    print(f"bank                  : {args.bank}")
    print(f"StartupLocality (PCR0): {locality}")
    print(f'H("os-separator")     : {sep}')
    print()

    header = f"{'PCR':>4}  {'replay':<16}  {'live':<16}  verdict"
    print(header)
    print("-" * len(header))

    findings = []
    for index in sorted(set(replay) | set(live)):
        replay_value = replay.get(index)
        live_value = live.get(index)

        if replay_value is None:
            # No firmware events: the PCR is still at its reset value.
            replay_value = initial_value(index, args.bank, locality)
        if live_value is None:
            continue

        path = explain(replay_value, live_value, args.bank, args.depth)
        if path == []:
            verdict = "unchanged since firmware"
        elif path == ["os-separator"]:
            verdict = "os-separator (x1)"
        elif path is not None:
            verdict = "explained: " + " + ".join(path)
            if path != ["os-separator"] and index in SEPARATOR_PCRS:
                findings.append((index, verdict))
        else:
            verdict = "UNEXPLAINED"
            if index not in EXPECTED_HOST_SPECIFIC:
                findings.append((index, verdict))

        print(
            f"{index:>4}  {replay_value.hex()[:16]:<16}  "
            f"{live_value.hex()[:16]:<16}  {verdict}"
        )

    print()
    expected = sorted(
        i
        for i in SEPARATOR_PCRS
        if i in live
        and explain(
            replay.get(i, initial_value(i, args.bank, locality)),
            live[i],
            args.bank,
            args.depth,
        )
        == ["os-separator"]
    )
    print(f"PCRs explained by exactly one os-separator extend: {expected}")
    missing = sorted(set(SEPARATOR_PCRS) - set(expected))
    if missing:
        print(f"PCRs in the separator list NOT matching that pattern : {missing}")

    if findings:
        print()
        print("FINDINGS (something other than a single os-separator is present):")
        for index, verdict in findings:
            print(f"  PCR {index}: {verdict}")
    else:
        print()
        print("No other OS-side additions found on the separator PCRs.")

    # Full chain: firmware log + every systemd userspace measurement, in order.
    measure_entries, unparsed = parse_measure_log(args.measure_log, args.bank)
    print()
    print("=" * 72)
    print(f"FULL CHAIN (firmware log + {args.measure_log})")
    print("=" * 72)
    if measure_entries is None:
        print(f"{args.measure_log} not present; skipping full-chain reconstruction.")
        return 1 if findings else 0
    if unparsed:
        print(f"warning: {unparsed} record(s) could not be parsed")

    by_pcr = defaultdict(list)
    for pcr, digest, description in measure_entries:
        by_pcr[pcr].append((digest, description))

    print(f"{len(measure_entries)} userspace measurement(s) recorded")
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
        status = "OK" if ok else "MISMATCH"
        chain = " + ".join(applied) if applied else "(firmware only)"
        print(f"{index:>4}  {status:<9} {chain}")
        if not ok:
            print(f"        expected {value.hex()}")
            print(f"        actual   {live[index].hex()}")

    print()
    if unresolved:
        print(f"PCRs still unaccounted for after the full chain: {unresolved}")
        print("=> something outside firmware and systemd extended these.")
        return 1
    print("Full chain reconstructs every PCR. Nothing unaccounted for.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
