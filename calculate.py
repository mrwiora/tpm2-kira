#!/usr/bin/env python3
import hashlib
import re
import sys

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


def calculate_pcr(eventlog_file, pcr_index):
    """
    Calculate PCR value by parsing eventlog and extending with digests.

    Args:
        eventlog_file: Path to the eventlog YAML file
        pcr_index: PCR index to calculate (e.g., 9)

    Returns:
        Final PCR value as bytes
    """
    # Initial PCR value (32 bytes of zeros for SHA256)
    pcr = b"\x00" * 32

    print(f"Calculating PCR{pcr_index} from eventlog: {eventlog_file}")
    print("=" * 70)
    print()

    # Load the eventlog with preprocessing
    cleaned_yaml = preprocess_eventlog(eventlog_file)
    eventlog = yaml.safe_load(cleaned_yaml)

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
    for i, event in enumerate(events, 1):
        event_num = event.get("EventNum", "?")
        event_type = event.get("EventType", "Unknown")

        # Extract the SHA256 digest
        digest = None
        if "Digests" in event and isinstance(event["Digests"], list):
            for d in event["Digests"]:
                if d.get("AlgorithmId") == "sha256":
                    digest = bytes.fromhex(d["Digest"])
                    break
        elif "Digest" in event:
            # Handle old format with single digest
            digest = bytes.fromhex(event["Digest"])

        if digest is None:
            print(f"Event {event_num}: No SHA256 digest found, skipping")
            continue

        # Extend PCR: PCR = SHA256(PCR || digest)
        print(f"Extension {i} (EventNum {event_num}, {event_type}):")
        print(f"  Digest:             {digest.hex()}")
        pcr = hashlib.sha256(pcr + digest).digest()
        print(f"  PCR after extension: {pcr.hex()}")
        print()

    return pcr


if __name__ == "__main__":
    # Default values
    eventlog_file = "eventlog"
    pcr_index = 9

    # Allow command line arguments
    if len(sys.argv) > 1:
        eventlog_file = sys.argv[1]
    if len(sys.argv) > 2:
        pcr_index = int(sys.argv[2])

    try:
        final_pcr = calculate_pcr(eventlog_file, pcr_index)
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
        sys.exit(1)
