# Troubleshooting

When a code stops matching or a command refuses: the event-log calculator, the PCR mismatch diagnosis, the common errors, the exit status table.

## Eventlog PCR Calculator

`tools/pcrtool.py` independently reconstructs PCR values, which is the first
thing to reach for when a sealed policy stops matching. It reads the live
firmware event log directly, or a `tpm2_eventlog` YAML dump:

```bash
# All PCRs from the running system's event log
sudo python3 tools/pcrtool.py replay

# A specific PCR, showing every extension step
sudo python3 tools/pcrtool.py replay --pcr 7 --verbose

# From a dump, which needs neither root nor a TPM
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > evlog.yaml
python3 tools/pcrtool.py --eventlog evlog.yaml replay

# The SHA-1 bank
sudo python3 tools/pcrtool.py --bank sha1 replay
```

The `extends` column counts how many events actually extended each PCR. A zero
there means the log carries no digests for that PCR **in the selected bank**, so
the value shown is only the reset value — the tool warns and exits non-zero
rather than letting that pass as a measurement.

Requires PyYAML (`pip install pyyaml`) and tpm2-tools.

## Troubleshooting

**TPM device not found:**
```bash
ls -la /dev/tpm*
sudo dmesg | grep -i tpm
```
Ensure TPM 2.0 is enabled in your BIOS/UEFI settings.

**Permission denied on `/dev/tpmrm0`:**
```bash
# Check current permissions
ls -la /dev/tpmrm0

# tpm2-kira runs as root: every command but the help refuses otherwise
sudo tpm2-kira status
```

**TOTP code doesn't match after update:**
```bash
tpm2-kira slot approve
```
If reseal also fails, check `tpm2-kira slot info` to see which PCRs changed and verify you have the correct signing key available.

**The phone is not asked at boot; the kernel says hci0's firmware is missing:**
The image has the Bluetooth driver but not the adapter's firmware. The image
build learns the firmware's name from the kernel log of a boot that loaded
it, and not every boot does: an Intel controller keeps its firmware over a
warm reboot and then names none. The boot plan reads every boot the journal
keeps and remember what they found per adapter
(`/var/lib/tpm2-kira/bt-firmware/`); `control`'s overview shows the
firmware on its Bluetooth line, red when none is known.
```bash
sudo tpm2-kira initramfs plan                         # what the next image gets, and why not
journalctl -k -o cat | grep -E 'Bluetooth: hci[0-9]+:' # what the kernel logged
lsinitcpio /boot/EFI/Linux/arch-linux.efi | grep -iE 'firmware|bluetooth|bt'
```
If no firmware line appears: power the machine off (a cold start loads the
firmware and logs it), boot, and rebuild with `mkinitcpio -P`. More in
[DEBUG-BLE.md](DEBUG-BLE.md).

**Debug output:**
```bash
tpm2-kira --debug reveal
```

**Check current PCR values vs. sealed values:**
```bash
tpm2-kira slot info            # shows what was sealed
tpm2-kira pcrtips         # explains what each PCR measures
```

## Diagnosing PCR mismatches

If the displayed PCR values differ from what was sealed, reconstruct the whole
chain before changing anything:

```bash
# Replays the firmware event log AND systemd's own measurement log,
# then explains every difference against the live registers.
sudo python3 tools/pcrtool.py verify
```

Each PCR is reported as `unchanged since firmware`, `os-separator (x1)`,
`explained: <words>`, or `UNEXPLAINED`. Anything unexplained on a sealed PCR is
a real finding.

Two things to keep in mind while reading any PCR output:

- `tpm2_eventlog`'s trailing `pcrs:` block is a **replay of the log**, not a
  read of the TPM. Comparing it against `tpm2_pcrread` is comparing a
  calculation against a measurement — and that difference is usually the answer.
- The **post-boot register is not the measure-point value** for PCRs 9, 11 and
  15. They keep being extended after the initrd, so a mismatch there is expected
  and not evidence of tampering.

See [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §5.6–5.8 for the full
reconstruction rules and constants.

## Exit status

**A failed command exits 0.** This is deliberate: tpm2-kira is meant to be
chainable in a boot sequence, so a TPM or NVRAM problem must not stop the
commands after it.

```bash
tpm2-kira && cryptsetup open /dev/nvme0n1p2 cryptroot
```

Scripts must therefore judge success from the **output**, not the exit status.
Failures are printed to stderr with a fixed marker:

```
tpm2-kira: FAILED: <reason>
tpm2-kira: (exit status is 0 by design; this command did NOT succeed)
```

The mkinitcpio post hook does exactly this — it greps the output for the success
line rather than testing `$?`.

**Exception: the attestation commands.** `phone gate`, `phone verify`,
`phone quote` and `phone enrol` gate or judge something, and a gate that
exits 0 on failure is not a gate. They exit non-zero on failure: `1` internal
error, `2` usage, `3` no phone or no adapter, `4` the phone rejected this boot
(do not type a passphrase before checking further), `5` the receipt was not
signed by the enrolled phone.

**The other non-zero exits:** `1` when a command runs as a user (root is
needed), `2` for a missing or unknown subcommand, and `1` from the three
commands a script reads the status of - `unlock-key` (cryptroot's
keyscript), `luks route` (the hook) and `ssh-child` (`run` watches it).
