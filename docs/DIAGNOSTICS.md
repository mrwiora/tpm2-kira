# Diagnosing and recovering

What to reach for when the TOTP code stops appearing, or when an NVRAM write does
not complete.

The first question is always which PCR changed and why. A mismatch after a
firmware, kernel or bootloader update is expected and needs a reseal; a mismatch
with no explanation is the finding tpm2-kira exists to surface.

---

## Diagnosing a PCR mismatch

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

## The eventlog PCR calculator

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

## Recovering an interrupted NVRAM write

Replacing an NVRAM index means undefining it first, and TPM 2.0 has no atomic
replace. `seal` and `reseal` do everything that can fail *before* that point —
loading the key, computing the write policy, and a test signature — so the window
is narrow. But a TPM error, or a hardware token unplugged mid-write, can still
leave the index empty.

When that happens the blob is written to `/var/lib/tpm2-kira/recovery/` and the
error says so. That file is not a consolation prize: the sealed object's private
area is wrapped by this TPM's storage primary key, which is re-derived
deterministically, so **the secret survives in those bytes**. Write them back:

```bash
sudo tpm2-kira nvram restore --nvram 0
sudo tpm2-kira nvram restore --nvram 0 --from /var/lib/tpm2-kira/recovery/slot-0x01803010-1700000000.blob
```

Restore needs the signing key, because the index's write policy is PolicySigned —
it uses the reference stored in the blob, so usually no flags are needed. Before
writing anything it verifies the blob's signature, checks the key is the one the
blob was sealed with, and loads the sealed object to confirm the blob belongs to
this TPM. It refuses to overwrite a *different* blob already in the index, since
that may be a newer secret you sealed in the meantime; `--force` overrides.

The restored policy binds the PCR values from when the blob was written, so
`reseal` afterwards if the current state has moved on.

**Power loss during the write is an accepted risk, not a covered one.** The
stash is written by the same process doing the NV write, so a machine that loses
power mid-write does not get one, and the secret is gone — `seal` again and
re-enrol your authenticator. TPM 2.0 has no atomic replace, so the window cannot
be closed; and a machine that dies partway through a root-privileged write
probably has a half-written initramfs too. The TOTP secret is among the easier
things to rebuild.
