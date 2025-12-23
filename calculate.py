#!/usr/bin/env python3
import hashlib
import sys
from collections import defaultdict

import yaml


def preprocess_eventlog(file_path):
    """
    Preprocess eventlog file to handle WARN lines and other non-YAML content.

    Args:
        file_path: Path to the eventlog file

    Returns:
        Cleaned YAML string
    """
    with open(file_path, "r") as f:
        lines = f.readlines()

    cleaned_lines = []
    for line in lines:
        # Skip WARN lines that break YAML parsing
        if line.strip().startswith("WARN:"):
            # Convert to a comment so it doesn't break parsing
            cleaned_lines.append("# " + line)
        else:
            cleaned_lines.append(line)

    return "".join(cleaned_lines)


def calculate_all_pcrs(eventlog_file):
    """
    Calculate all PCR values by parsing eventlog and extending with digests.

    Args:
        eventlog_file: Path to the eventlog YAML file

    Returns:
        Dictionary mapping PCR index to final PCR value
    """
    print(f"Calculating all PCRs from eventlog: {eventlog_file}")
    print("=" * 70)
    print()

    # Load the eventlog with preprocessing
    cleaned_yaml = preprocess_eventlog(eventlog_file)
    eventlog = yaml.safe_load(cleaned_yaml)

    # Group events by PCR index
    pcr_events = defaultdict(list)
    pcr0_locality = None

    for event in eventlog["events"]:
        pcr_index = event.get("PCRIndex")
        if pcr_index is not None:
            pcr_events[pcr_index].append(event)

        # Check for StartupLocality event (PCR0, EV_NO_ACTION with "StartupLocality" signature)
        if (
            pcr_index == 0
            and event.get("EventType") == "EV_NO_ACTION"
            and event.get("EventSize") == 17
        ):
            event_data = event.get("Event", "")
            if event_data.startswith("537461727475704c6f63616c697479"):
                # Extract locality byte (last byte of the 17-byte event)
                pcr0_locality = int(event_data[-2:], 16)
                print(f"Found StartupLocality event: locality = {pcr0_locality}")

    # Get sorted list of PCR indices
    pcr_indices = sorted(pcr_events.keys())

    print(f"Found events for {len(pcr_indices)} PCR(s): {pcr_indices}")
    print()

    # Calculate each PCR
    pcr_values = {}

    for pcr_index in pcr_indices:
        print(f"\n{'=' * 70}")
        print(f"PCR{pcr_index}")
        print("=" * 70)

        # Initial PCR value (32 bytes of zeros for SHA256)
        # PCR0 is special: it's initialized with the locality value in the last byte
        if pcr_index == 0 and pcr0_locality is not None:
            pcr = b"\x00" * 31 + bytes([pcr0_locality])
            print(f"Initial PCR value (31 zeros + locality {pcr0_locality}):")
        else:
            pcr = b"\x00" * 32
            print(f"Initial PCR value (32 zeros):")
        print(f"  {pcr.hex()}")
        print()

        events = pcr_events[pcr_index]
        print(f"Processing {len(events)} event(s) for PCR{pcr_index}")
        print()

        # Process each event
        extension_count = 0
        for event in events:
            event_num = event.get("EventNum", "?")
            event_type = event.get("EventType", "Unknown")

            # Skip EV_NO_ACTION events - they don't extend PCRs
            if event_type == "EV_NO_ACTION":
                print(
                    f"  Event {event_num} ({event_type}): Skipped (informational only)"
                )
                continue

            extension_count += 1

            # Extract the SHA256 digest
            digest = None
            if "Digests" in event and isinstance(event["Digests"], list):
                for d in event["Digests"]:
                    if d.get("AlgorithmId") == "sha256":
                        digest = bytes.fromhex(d["Digest"])
                        break
            elif "Digest" in event:
                # Handle old format with single digest
                digest_str = event["Digest"]
                # Only process if it's a valid hex string
                if digest_str and len(digest_str) == 64:
                    try:
                        digest = bytes.fromhex(digest_str)
                    except ValueError:
                        pass

            if digest is None:
                print(f"  Event {event_num}: No SHA256 digest found, skipping")
                continue

            # Extend PCR: PCR = SHA256(PCR || digest)
            print(f"Extension {extension_count} (EventNum {event_num}, {event_type}):")
            print(f"  Digest:              {digest.hex()}")
            pcr = hashlib.sha256(pcr + digest).digest()
            print(f"  PCR after extension: {pcr.hex()}")
            print()

        pcr_values[pcr_index] = pcr

    return pcr_values


def calculate_single_pcr(eventlog_file, pcr_index):
    """
    Calculate a single PCR value.

    Args:
        eventlog_file: Path to the eventlog YAML file
        pcr_index: PCR index to calculate

    Returns:
        Final PCR value as bytes
    """
    print(f"Calculating PCR{pcr_index} from eventlog: {eventlog_file}")
    print("=" * 70)
    print()

    # Load the eventlog with preprocessing
    cleaned_yaml = preprocess_eventlog(eventlog_file)
    eventlog = yaml.safe_load(cleaned_yaml)

    # Check for StartupLocality event for PCR0
    pcr0_locality = None
    if pcr_index == 0:
        for event in eventlog["events"]:
            if (
                event.get("PCRIndex") == 0
                and event.get("EventType") == "EV_NO_ACTION"
                and event.get("EventSize") == 17
            ):
                event_data = event.get("Event", "")
                if event_data.startswith("537461727475704c6f63616c697479"):
                    # Extract locality byte (last byte of the 17-byte event)
                    pcr0_locality = int(event_data[-2:], 16)
                    print(f"Found StartupLocality event: locality = {pcr0_locality}")
                    break

    # Initial PCR value (32 bytes of zeros for SHA256)
    # PCR0 is special: it's initialized with the locality value in the last byte
    if pcr_index == 0 and pcr0_locality is not None:
        pcr = b"\x00" * 31 + bytes([pcr0_locality])
        print(f"Initial PCR value (31 zeros + locality {pcr0_locality}):")
    else:
        pcr = b"\x00" * 32
        print(f"Initial PCR value (32 zeros):")
    print(f"  {pcr.hex()}")
    print()

    # Filter events for the specified PCR index
    events = [e for e in eventlog["events"] if e.get("PCRIndex") == pcr_index]

    if not events:
        print(f"Warning: No events found for PCR{pcr_index}")
        return pcr

    print(f"Found {len(events)} event(s) for PCR{pcr_index}")
    print()

    # Process each event
    extension_count = 0
    for event in events:
        event_num = event.get("EventNum", "?")
        event_type = event.get("EventType", "Unknown")

        # Skip EV_NO_ACTION events - they don't extend PCRs
        if event_type == "EV_NO_ACTION":
            print(f"Event {event_num} ({event_type}): Skipped (informational only)")
            continue

        extension_count += 1

        # Extract the SHA256 digest
        digest = None
        if "Digests" in event and isinstance(event["Digests"], list):
            for d in event["Digests"]:
                if d.get("AlgorithmId") == "sha256":
                    digest = bytes.fromhex(d["Digest"])
                    break
        elif "Digest" in event:
            # Handle old format with single digest
            digest_str = event["Digest"]
            if digest_str and len(digest_str) == 64:
                try:
                    digest = bytes.fromhex(digest_str)
                except ValueError:
                    pass

        if digest is None:
            print(f"Event {event_num}: No SHA256 digest found, skipping")
            continue

        # Extend PCR: PCR = SHA256(PCR || digest)
        print(f"Extension {extension_count} (EventNum {event_num}, {event_type}):")
        print(f"  Digest:              {digest.hex()}")
        pcr = hashlib.sha256(pcr + digest).digest()
        print(f"  PCR after extension: {pcr.hex()}")
        print()

    return pcr


if __name__ == "__main__":
    # Default values
    eventlog_file = "eventlog"
    pcr_index = None

    # Allow command line arguments
    if len(sys.argv) > 1:
        eventlog_file = sys.argv[1]
    if len(sys.argv) > 2:
        pcr_index = int(sys.argv[2])

    try:
        if pcr_index is None:
            # Calculate all PCRs
            pcr_values = calculate_all_pcrs(eventlog_file)

            print("\n" + "=" * 70)
            print("SUMMARY - Final PCR Values")
            print("=" * 70)
            for pcr_idx in sorted(pcr_values.keys()):
                print(f"PCR{pcr_idx:2d}: {pcr_values[pcr_idx].hex()}")
            print("=" * 70)
        else:
            # Calculate single PCR
            final_pcr = calculate_single_pcr(eventlog_file, pcr_index)
            print("=" * 70)
            print(f"Final PCR{pcr_index} value: {final_pcr.hex()}")
            print("=" * 70)

    except FileNotFoundError:
        print(f"Error: Eventlog file '{eventlog_file}' not found", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)
