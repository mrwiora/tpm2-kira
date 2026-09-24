# Platform observations

Measured facts about the two platforms tpm2-kira is developed against, with the
commands that produced them. Recorded because several of these were rediscovered
the hard way after a design decision had already been made on an assumption.

**Everything below was observed on a real machine.** Where something is inferred
rather than measured it says so explicitly. If you change a claim here, change it
because you ran the command again — not because it sounds right.

Host identifiers (machine-id, disk and filesystem UUIDs) are abbreviated or
redacted. They add nothing to the observation and this file is public.

Dates: Arch 2026-09-24, Debian 2026-09-23/24.

---

## Arch Linux (UKI + systemd initramfs)

```
kernel       7.2.6-arch2-1
mkinitcpio   42-1
systemd      261.3-1
go           1.27.1
sbctl        0.18-2
tpm2-tools   5.8-1
UKI          /boot/EFI/Linux/arch-linux.efi (+ arch-linux-tmp.efi)
HOOKS        base systemd autodetect microcode modconf kms keyboard block
             sd-tpm2-kira sd-encrypt filesystems fsck
SecureBoot   enabled (1)          SetupMode 0
IMA          /sys/kernel/security/ima absent -> not enabled
StartupLocality 3 (PCR 0 starts at 0x…03, not zeros)
```

### systemd extends PCRs before tpm2-kira reads them

`systemd-pcrosseparator.service` extends `os-separator` into PCRs 0–7, 9, 12–14
and `systemd-pcrphase-initrd.service` extends `enter-initrd` into PCR 11, both
before the passphrase prompt. This is the entire reason the measure-point model
exists; see SECURITY-BACKGROUND.md §5.6.

```bash
sudo python3 tools/pcrtool.py verify     # replay vs live, explains each delta
```

Re-verified on 2026-09-24 after a systemd 261.3 / mkinitcpio 42 update: PCRs
0–7, 12 and 13 each show `os-separator (x1)`, and the separator-only PCRs 2, 3
and 6 match the documented constants exactly — `3d458cfe…` replayed,
`8d22c738…` live.

PCR 11 reports `enter-initrd + leave-initrd + sysinit + ready` because the tool
runs on the booted system, past the measure point. Only `enter-initrd` applies
at the point tpm2-kira actually reads.

PCR 9 shows `UNEXPLAINED` in the verdict table **by design**: it is extended
after disk unlock by `systemd-tpm2-setup` with host-specific
`nvpcr-init:<name>:…` words, which the table cannot search for. The FULL CHAIN
section below it, which reads systemd's own measurement log, is what resolves
PCR 9. Treat an unexplained PCR as a finding only if it survives that section.

### The full chain reconstructs every PCR

`pcrtool.py verify` on 2026-09-24 accounted for all 24 registers with nothing
left over — 21 userspace measurements on top of the firmware log:

| PCR | Explained by |
|-----|--------------|
| 0–7, 12, 13, 14 | `os-separator` |
| 8, 10, 16–23 | firmware only (never extended on this system) |
| 9 | `os-separator` + `nvpcr-init` ×4 — `verity`, `hardware`, `cryptsetup`, `login` at NV indices `0x1d10200`–`0x1d10203`, all **after** disk unlock |
| 11 | `enter-initrd` + `leave-initrd` + `sysinit` + `ready` |
| 15 | `machine-id:<redacted>` |

This is the property the measure-point model depends on: if a PCR cannot be
reconstructed from firmware log + systemd log, sealing it binds the policy to a
value the machine will not reproduce. Re-run the command above after any
systemd or firmware update.

### PCR 8 and PCR 10 are unused on this system

Both read all zeros, which cross-checks two claims made on the Debian side:
PCR 8 carries GRUB's commands and so stays at its reset value under a UKI, and
PCR 10 is Linux IMA — absent here (`/sys/kernel/security/ima` does not exist),
and correspondingly never extended.

### mkinitcpio only honours .wants under /usr/lib

`add_systemd_unit` copies reverse dependencies with:

```bash
for dep in {/usr,}/lib/systemd/system/*.wants/"${unit##*/}"; do
```

`/etc` is not searched, so `systemctl enable` does **not** reach the initramfs.
The install hook therefore calls `add_symlink` to enable the unit inside the
image, leaving the host untouched.

```bash
sed -n '/^add_systemd_unit()/,/^}/p' /usr/lib/initcpio/install/systemd
```

### efivars layout

`SecureBoot` and `SetupMode` are one-byte variables prefixed by a 4-byte
attribute word:

```bash
od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
#  6 0 0 0 1   <- attributes, then the value
```

---

## Debian 13 (GRUB + initramfs-tools), VM with emulated TPM

```
kernel          6.12.107+deb13-amd64
initramfs-tools 0.148.4          (no systemd in the initrd)
golang-go       1.24.4
boot            GRUB, EFI
disk            vda3 crypto_LUKS -> vda3_crypt -> debian--vg {root,swap}
crypttab        vda3_crypt UUID=b0c9ff53-… none luks,discard,x-initrd.attach
event log       crypto-agile, ONE algorithm: SHA-256
StartupLocality None (PCR 0 starts at zeros)
SecureBoot      DISABLED, platform in Setup Mode
UKI             none -> PCR 11 empty, `11u`/`11e` inapplicable
```

### Boot script ordering

`/init` runs exactly three `run_scripts` stages: `init-top` (line 222),
`init-premount` (240), `init-bottom` (277). `local-top/cryptroot` runs later,
from `mountroot` in `/scripts/local`. That ordering is what lets an
`init-premount` script print before the passphrase prompt.

```bash
grep -n run_scripts /usr/share/initramfs-tools/init
```

### The measure point is end-of-firmware

With no systemd in the initrd, none of the `os-separator` / `enter-initrd`
units exist, so nothing extends PCRs between firmware and tpm2-kira.
`--measure-point=auto` correctly resolves to `off`.

```bash
sudo python3 tools/pcrtool.py replay     # matches live PCRs 0-9 exactly
```

### What GRUB measures — PCR 8 vs PCR 9

```bash
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > /tmp/ev.yaml
```

| PCR | Events | Sample payload |
|-----|--------|----------------|
| 8 | 56 × `EV_IPL` | `grub_cmd: search.fs_uuid 6b94b598-… root` |
| 9 | 12 × `EV_IPL` | `(hd0,gpt1)/EFI/debian/grub.cfg` |
| 9 | 2 × `EV_EVENT_TAG` | `LOADED_IMAGE::LoadOptions` (26 bytes) |

So PCR 8 is **every GRUB command**, not just the kernel command line, and PCR 9
covers grub.cfg, GRUB's modules, the kernel and the initrd, plus the EFI load
options.

### PCR 9 digests cover file contents, not paths

`update-initramfs -u` with an unchanged kernel version:

```
PCR 9 before  AC48EACFA41CE62694F73C310324A0752B482B5ED691254A36F5FD99687FA44B
PCR 9 after   1DB0B067E5B68DE87AABB0DA2F09C4F19FB9256F8B99623E31A7CE64FF200150
PCR 8         unchanged
```

The initrd's path did not change, only its content — so the measurement is over
the bytes. PCR 8 stayed put because grub.cfg's commands were untouched.

**Consequence:** PCR 9 changes on every kernel or initramfs update, and no
source can predict its next value (every Debian source reads the *running*
system). Sealing PCR 8/9 means resealing *after* the reboot, never at rebuild
time. This is why the Debian post-update hook only prints a reminder.

### PCR 10 is Linux IMA, with a single measurement

```bash
sudo cat /sys/kernel/security/ima/runtime_measurements_count     # 1
sudo head -1 /sys/kernel/security/ima/ascii_runtime_measurements
# 10 10b39613… ima-sig sha256:d8a4d585… boot_aggregate
```

Replaying that one entry reproduces the register exactly:

```bash
sudo awk '{print $2}' /sys/kernel/security/ima/ascii_runtime_measurements_sha256 |
  python3 -c "import sys,hashlib; v=bytes(32); [v:=hashlib.sha256(v+bytes.fromhex(l.strip())).digest() for l in sys.stdin]; print(v.hex())"
# ab46a2c9ccc82438e0ffc98c9b84f466f087112d95b177730e84e65dd055c29c
# tpm2_pcrread sha256:10 -> 0xAB46A2C9…C29C   (identical)
```

A one-entry replay landing on the live value also proves nothing *else* extends
PCR 10 here. IMA is compiled in with no policy loaded, so only `boot_aggregate`
is measured — a digest of the earlier PCRs, which makes PCR 10 redundant to
seal. If a policy were loaded it would never stabilise. Either way it is a poor
seal target.

### Separator-only PCRs

PCRs 3 and 6 hold only the firmware `EV_SEPARATOR`, so their value is
machine-independent: `3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969`.
Anything else there means extra extends, never a changed measurement.

### post-update.d

`/etc/initramfs/post-update.d/` does not exist by default, but
`update-initramfs` runs it when present, via
`run-parts --arg="$version" --arg="$initramfs"` — once per kernel version.

```bash
grep -n post-update /usr/sbin/update-initramfs
```

---

## Caveat on the VM

SecureBoot is disabled and the platform is in Setup Mode, so **PCR 7 attests
almost nothing there** and PCR 0/2 may be identical across every VM built from
the same firmware image. The plumbing can be validated on that VM; the security
property cannot. Real hardware with Secure Boot enabled is required for that.
