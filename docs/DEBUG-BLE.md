# Debugging the phone check at boot (Bluetooth LE)

The phone is asked at boot by a gate that runs in the initramfs, next to the
code screen. For that the image needs the Bluetooth adapter's driver
modules, its firmware, the gate's unit and the signing public key. This page
says how they get there, how to see what was put in, and how to find out
why a phone was not asked.

## 1. How Bluetooth gets into the image

**Through the `sd-tpm2-kira` hook, not through an edit of
`/etc/mkinitcpio.conf`.** The hook is the one you put into `HOOKS` for the
code screen; at every `mkinitcpio -P` its build function also adds
Bluetooth, when it belongs in the image:

| `TPM2_KIRA_ATTEST_BLUETOOTH` in `/etc/tpm2-kira/control.conf` | Bluetooth in the image |
|---|---|
| `auto` (default) | once a phone is enrolled for some slot |
| `always` | in every image, before any phone (~1.1 MB) |

`control` writes `always` when you answer *Yes* to "Pack Bluetooth into every
boot image?" (offered before a rebuild, preselected). That line is the only
setting; `mkinitcpio.conf` is not touched for Bluetooth. Debian's
initramfs-tools hook (`/usr/share/initramfs-tools/hooks/tpm2-kira`) does the
same with the same setting.

What the hook adds, for the adapter `TPM2_KIRA_ATTEST_ADAPTER` (default
`hci0`):

| What | From where |
|---|---|
| the driver modules along the adapter's sysfs path (`btusb`, `btintel`, `xhci_pci`, ..., `bluetooth`) with their dependencies | `/sys/class/bluetooth/hciN` |
| the firmware files the adapter loads (e.g. `intel/ibt-0040-0041.sfi` and its `.ddc`) | the kernel log of every boot the journal keeps; remembered per adapter in `/var/lib/tpm2-kira/bt-firmware/` (§3) |
| `/etc/modules-load.d/tpm2-kira-bluetooth.conf` | the module list, loaded early in the initrd |
| `tpm2-kira-attest.service` | the gate's unit |
| `/etc/tpm2-kira/attest-signer.pem` | the signing public key, to check the enrolment record |
| `/etc/udev/rules.d/70-tpm2-kira-bluetooth.rules`, only when the adapter's USB bus lets no new device in by itself | a rule that lets exactly this adapter in, at its port (§4) |

The resolution is `tpm2-kira attest initramfs-deps`; the hook only copies
what it answers. `control` runs the same resolution and shows its answer
before the rebuild ("The sd-tpm2-kira hook adds for hci0: ...").

### Why the hook, and not MODULES= and FILES= in mkinitcpio.conf

- **The firmware's name is not known in advance.** It depends on the chip
  and is learnt from the kernel log; a `FILES=` line would have to be
  written per machine and kept in step with `linux-firmware` (compressed
  names, renamed files). `MODULES=(btusb)` alone brings the firmware the
  modules *declare*, which for current Intel adapters is not the file they
  load.
- **Modules alone are not the gate.** Its unit, the module list and the
  signing public key have to be added by a hook in any case.
- **`auto` follows the enrolment:** no phone, no Bluetooth in the image,
  without anyone editing a file.
- **One mechanism for mkinitcpio and initramfs-tools**, which has no
  `mkinitcpio.conf`.

What makes it visible instead: the plan shown before every rebuild, the
hook's line in the `mkinitcpio` output (`tpm2-kira: Bluetooth attestation
via hci0: 6 modules, 2 firmware files`, or a warning), and `control`'s check
of the built image (§2).

## 2. Is it in the image?

`control`'s overview checks the image the next boot starts - the first
preset's `default_uki` (or `default_image`), Debian's `initrd.img` of the
running kernel - whenever Bluetooth belongs in it. Fallback images and
further profiles are not checked yet (PLAN-SUPPORT-MULTIPLE-UKI.md, step
6); look into them by hand:

```
  Bluetooth   hci0 (attestation by phone possible; firmware intel/ibt-0040-0041.sfi, intel/ibt-0040-0041.ddc)
  Boot image  carries hci0's driver and firmware for the phone's gate
```

red when an image lacks the gate's part or the adapter's firmware. By hand:

```bash
lsinitcpio /boot/EFI/Linux/arch-linux.efi | grep -E 'tpm2-kira|firmware|bluetooth'   # a UKI or an .img
lsinitramfs /boot/initrd.img-$(uname -r) | grep -E 'tpm2-kira|firmware|bluetooth'     # Debian
sudo tpm2-kira attest initramfs-deps --adapter 0     # what the next build will add
```

## 3. The firmware

The kernel names the firmware it loads, but not in every boot: an Intel
controller that kept its firmware over a warm reboot logs "Firmware already
loaded" and names no file. An image built in such a boot used to get the
modules' declared files instead, and the next cold start failed in the
initrd with the firmware missing. Therefore:

- the hooks read the Bluetooth kernel lines of **every boot the journal
  keeps** (`journalctl -k`), not just the current one;
- what a log named is **remembered per adapter**, by its modalias, in
  `/var/lib/tpm2-kira/bt-firmware/`, and used when no log names any;
- an Intel `.sfi` brings its `.ddc`;
- with nothing known the hook warns, and `control` shows the Bluetooth line
  red.

If no firmware is known: **power the machine off** (a cold start loads the
firmware and logs it), boot, and rebuild (`mkinitcpio -P`).

```bash
journalctl -k -o cat | grep -E 'Bluetooth: hci[0-9]+:'   # what the kernel logged, all boots
ls /var/lib/tpm2-kira/bt-firmware/ && cat /var/lib/tpm2-kira/bt-firmware/*
```

## 4. Why was the phone not asked?

After the boot, on the unlocked system:

```bash
journalctl -b -u tpm2-kira-attest.service -u tpm2-kira.service   # Debian: /run/initramfs/tpm2-kira.log
journalctl -b -k | grep -iE 'bluetooth|hci|firmware'
```

| What the log says | Cause | What to do |
|---|---|---|
| kernel: `usb 3-10: Device is not authorized for usage`, later `authorized to connect` once the system is up | the USB bus lets no new device in by itself (`usbcore.authorized_default=0`, as USBGuard sets it), and the image had no rule that lets the adapter in | rebuild: the hook now adds the rule (below) |
| no `tpm2-kira-attest.service` at all | the image has no Bluetooth: no phone was enrolled when it was built (`auto`), or the hook warned | `control`'s Boot image line; rebuild |
| kernel: `Direct firmware load for ... failed`, `firmware missing` | the image lacks the adapter's firmware (§3) | power off, boot, rebuild |
| `no Bluetooth adapter` / the gate waits for the adapter until the code screen ends | module, firmware or USB authorization missing in the image | `control`'s *Boot image* and *Adapter at boot* lines; `TPM2_KIRA_ATTEST_ADAPTER` says whose driver goes in |
| `the attestation record is not accepted` | the enrolment in the TPM is not the one the image's signing key vouches for (replaced, or an older one put back) | `tpm2-kira attest status`; enrol again |
| the phone sees no machine | the phone's Bluetooth is off, or Marify has no record for this machine (enrolled again elsewhere) | enrol the phone again |

**USB authorization.** With `usbcore.authorized_default=0` (USBGuard sets
it) the kernel lets no new USB device in until something authorizes it.
On the running system that is USBGuard or your udev rules; in the image
neither exists, so the adapter stays out and its driver never binds. When
the adapter's bus blocks new devices (`authorized_default` 0 or 2 on its
root hub), the hook writes one rule into the image - never onto the
system, where your own policy decides:

```
ACTION=="add", SUBSYSTEM=="usb", KERNEL=="3-10", ATTR{idVendor}=="8087", ATTR{idProduct}=="0033", ATTR{authorized}="1"
```

exactly this adapter, at its port. `control` shows it before a rebuild and
checks it in its own line, *Adapter at boot*. By hand:

```bash
cat /sys/bus/usb/devices/usb*/authorized_default         # 0: new devices blocked
cat /proc/cmdline | tr ' ' '\n' | grep usbcore           # usbcore.authorized_default=0?
lsinitcpio /boot/EFI/Linux/arch-linux.efi | grep 70-tpm2-kira-bluetooth.rules
```

For every step the gate takes (TPM, adapter, controller commands,
advertising, connections), switch **Debug at boot** on in `tpm2-kira
control` and boot: the code screen and the gate then log every step, and the
narrative also reaches the console, at every boot until it is switched off
(the overview shows it, orange). The switch is in the TPM (NV index
`0x01803000`, the boot settings), written with the signing key: no rebuild,
and the image and PCR 11 stay as they are. Nothing of `control.conf` goes into the image; the
gate takes the adapter that comes up and waits as long as the code screen
holds. The gate can be run by hand on the booted system to
test the radio and the phone without a reboot:

```bash
sudo tpm2-kira attest gate     # the verdict is shown; nothing is unlocked
```
