# The phone: Marify verifies the boot (experimental)

The second way to check the boot, in place of the code: the slot's
enrolment holds a phone instead of a TOTP key ([SLOT.md](SLOT.md)).
`tpm2-kira phone enrol | unenrol | status | gate | ekcert | quote | verify`;
the phone can also keep the salt of the disk's key (`phone salt`,
[DISK-KEY.md](DISK-KEY.md#password--phone-salt-passwordphonesalt)).

## What the phone checks

Instead of comparing six digits by eye, a phone app can verify the boot: the
machine's TPM signs a quote over its PCRs, the phone checks it against what it
recorded at enrolment and shows **match**, **changed** (with an explanation of
which part of the boot chain moved) or **failed**, together with a code that
the machine's screen must show (the measure point, [SEALING.md](SEALING.md#the-measure-point)) and whether the
machine's TPM released its *boot key* for this boot state. Nothing is signed
until you have compared the code and pressed the button. After a kernel update the
machine is not silent as with the OTP: it attests its new state and you approve
the change on the phone. The slot the phone attests has no TOTP code while a
phone is enrolled; the fallback slot keeps its code for a boot without the
phone. The machine does not store or show the phone's name, and the phone
gives every machine an identity of its own: one phone attests any number of
machines, none of which can tell that the others share it.

```bash
# Once, on the booted system (needs the signing key and a Bluetooth adapter):
sudo tpm2-kira phone enrol --name "Thinkpad-X1"
#   compare the 6-digit code on the console with the app, confirm on both
#   A TPM without a SHA-256 PCR bank, or a slot sealed with --sha1, needs
#   --sha1 here as well: SHA-1 is never chosen without being asked for.

# Serve an attestation by hand (shows the verdict, never blocks):
sudo tpm2-kira phone gate
sudo tpm2-kira phone status

```

**Both sides check each other's hardware at enrolment.** The phone checks
that this machine's TPM is genuine (its EK certificate against vendor roots
built into the app; Intel signs each product family's EKs under its own
issuing CA, which the machine fetches from the URL the chain names and
sends along - trust still comes from the embedded root alone, and
`tpm2-kira phone ekcert` shows the chain and where it breaks off); `phone enrol` runs the same check on itself first
(`--verify-tpm`). The machine checks the phone's key attestation against
Google's attestation roots and revocation list: key in StrongBox or the TEE,
an unlock for every use, a locked and verified phone (`--verify-phone`).
Both default to `warn`: the result is shown and, if not verified, you are
asked (custom ROMs such as LineageOS boot "self-signed" and fail the last
check). `require` refuses, `off` skips.

**Choose PCRs that cover the initrd.** The initrd is where a passphrase
logger would sit; if no quoted PCR measures it, a modified initrd attests as
unchanged. `phone enrol` reads this boot's event log, says which PCRs
measured the initrd, and asks before enrolling a selection that misses them:

| Boot path | Initrd measured into | For example |
|---|---|---|
| GRUB, separate initrd | PCR 9 (the file) | `--pcrs 0,2,4,7,9` |
| systemd-boot / EFI stub, separate initrd (kernel ≥ 5.17) | PCR 9 (tagged "Linux initrd") | `--pcrs 0,2,4,7,9` |
| Unified kernel image (UKI) | PCR 11 (`.initrd` section) and PCR 4 (the whole image) | the default: the slot's sealed selection (`0,2,4,7` when it has none) |

PCR 9 also changes with every kernel or initrd update; the phone then shows
*changed* with the diff, and you approve the new state once.

The phone enrolment lives in the slot's blob in TPM NV storage, next to the
TOTP key: readable and — through the owner hierarchy — replaceable by anyone
who can talk to the TPM, including another OS booted on this machine. So the gate checks it before the passphrase prompt:
the record must be signed by your signing key, whose public half the hook puts
into the image, and its count must equal a counter the TPM keeps for the slot,
which cannot be turned back. A foreign record fails the first check, an older
one put back the second. Enrolling or removing a phone needs no rebuild. The
check is as strong as the protection of the initramfs itself (a Secure
Boot-signed unified kernel image, or PCRs that cover the initrd); the verdict
on the console stays advisory: **only the phone's screen counts.**

While enrolling or attesting, tpm2-kira takes the Bluetooth adapter
exclusively through an HCI user channel (no BlueZ needed); other Bluetooth
devices on that adapter disconnect until it finishes. `--adapter N` selects
another adapter.

## At the code screen

Once a phone is enrolled, rebuild the initramfs:

```bash
sudo mkinitcpio -P            # or: sudo update-initramfs -u
```

There is no mode to switch on: the boot plan (`tpm2-kira initramfs plan`)
puts the phone's gate in once a phone is enrolled, with exactly what the
adapter needs (`TPM2_KIRA_ATTEST_ADAPTER` in `/etc/tpm2-kira/control.conf`,
hci0 by default): its driver modules and the firmware files the kernel
loaded for it (about 1.1 MB on an Intel adapter). Nothing is added while
no phone is enrolled, without a TPM, or when the adapter is missing; the
build says why. At boot the gate runs beside
the TOTP display, waits for the adapter, serves the phone, prints the
verdict, and never holds the boot.

The new modules and firmware change the initramfs and therefore PCR 11 (UKI)
or PCR 9 (GRUB): on both, the post hook reseals automatically, on Debian
with PCR 8/9 predicted for the next boot
([BOOT-INTEGRATION.md](BOOT-INTEGRATION.md#pcr-8-and-9-are-predicted-for-the-next-boot)).

The same session also releases the phone salt when a LUKS keyslot is
made from your password and a salt the phone keeps (`password+phonesalt`,
[DISK-KEY.md](DISK-KEY.md#password--phone-salt-passwordphonesalt)).

Status: the machine side, Bluetooth inside the initramfs and the phone's
verification core are implemented but not yet tested on real Bluetooth
hardware. The phone's verdict informs;
the passphrase can always be entered by hand
([DISK-KEY.md](DISK-KEY.md#when-the-answer-is-wrong-systemds-prompt-is-the-fallback)).
The phone apps are specified in [mobile/](mobile/). The protocol is
defined in [PROTOCOL-BLE.md](PROTOCOL-BLE.md), the design in
[PLAN-PHONE.md](PLAN-PHONE.md) and
[PLAN-BLE.md](PLAN-BLE.md).
