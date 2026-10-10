# PLAN — Several unified kernel images per slot

> **Status:** concept. Step 1 (a smaller blob, and a size check against
> the TPM instead of a fixed refusal) is implemented; steps 2–6 are open.
> **Scope:** the slot blob, `seal`, `reseal`, the boot's policy session,
> the mkinitcpio post hook and `control`.

---

## 1. The problem

A mkinitcpio preset can build several unified kernel images, for example
`default` and `fallback` in `/etc/mkinitcpio.d/linux.preset`, each with its
own `<preset>_uki=` path. systemd-stub measures the sections of whichever
image boots (kernel, command line, initrd, …) into PCR 11, so every image
gives PCR 11 its own value.

Today slot 0's PCR 11 is computed from **one** image: `11u` stands for
`/boot/EFI/Linux/arch-linux.efi` (or the path after `11u:`), and that path is
stored in the slot. The post hook runs once per built image and calls
`tpm2-kira reseal`, which ignores the image it was called for and recomputes
PCR 11 from the stored path each time. The outcome:

- booting the image at the stored path: slot 0 matches, the code appears;
- booting any other image of the preset: slot 0 reports a PCR mismatch and
  only slot 1 (PCRs 0 and 7, no PCR 11) still shows a code;
- `mkinitcpio -P` signs the same approval once per image, which costs a
  YubiKey touch each time when the key is on a token.

## 2. Goal

Slot 0 shows its code for up to **three** images, its *profiles*, with the
same TOTP secret: one entry in the authenticator, whichever image booted.
Everything bound to the slot (the boot key, the release key, the LUKS
tokens of the slot) works for every profile without being enrolled again.

## 3. Design: one slot, one approval per profile

The TOTP key object accepts whatever the signing key approves for the slot's
`PolicyRef` (PolicyAuthorize, SECURITY-BACKGROUND §4). An approval names
the PCR values and the generation. Nothing in the TPM limits a key object to
*one* approval: the signing key can approve several PCR states, and the
object accepts each of them.

So the slot keeps one key object, one generation and one `PolicyRef`, and
carries one approval per profile:

| Shared by all profiles                                        | Per profile                       |
|---------------------------------------------------------------|-----------------------------------|
| key object (`Public`, `Private`), `TOTPAlgorithm`             | UKI path                          |
| `PolicyRef`, `SigningPublic`, `Generation`                    | PCR 11 value                      |
| PCR values other than 11 (`0e,2e,7e`, …)                      | approval signature                |
| attestation part, blob signature                              |                                   |

An approval covers the PCR selection as a whole (PolicyPCR digests all the
selected registers at once), so each profile needs its own signature even
though only PCR 11 differs.

### 3.1 What a profile costs

Measured on swtpm (step 1), per additional profile:

| Signing key | PCR 11 value + path + framing | Approval signature | Total  |
|-------------|-------------------------------|--------------------|--------|
| ECC P-256   | ~80                           | 72                 | ~150 B |
| RSA 2048    | ~80                           | 262                | ~340 B |
| RSA 4096    | ~80                           | ~518               | ~600 B |

The limit is one NV index (`TPM2_PT_NV_INDEX_MAX`, 2048 bytes on the
machines seen so far). After step 1, slot 0 with one phone takes about
1450 bytes with an ECC P-256 key (690 for the TOTP part, 760 for the
attestation part), which leaves room for three profiles, or two profiles and
a second phone. ECC P-256 is the default signing key; RSA keys remain
supported and simply leave less room (RSA 2048: about 2010 bytes already).

### 3.2 No fixed limits, one active check

The blob is checked against the TPM it is written to, every time, for the
combination the person actually has: two phones and one image may fit where
one phone and three images do not, and the other way round. Nothing is
refused because some worst case *might* not fit (step 1 does this for
phones already: `WriteToNVRAM` compares the signed blob with
`TPM2_PT_NV_INDEX_MAX` before the old index is touched).

For profiles:

- the first profile, the image `11u` names, is always sealed and resealed;
  a slot without it does not exist;
- a further profile is added only if the blob with it fits; if not, `seal`,
  `reseal` and `control` say which profile was left out, how many bytes
  were missing and what would make room (an ECC key, a phone less), and
  that image keeps booting through slot 1;
- a reseal never fails because of a profile: a profile that no longer fits
  (a phone was added since) is dropped with that message, and the rest is
  written.

## 4. Seal and reseal

- **Profiles come from the presets.** `control` and `seal` read
  `/etc/mkinitcpio.d/*.preset` and list every `<preset>_uki=`. The default
  is the first image and the others in the preset's order, up to three;
  `control` shows the list for acknowledgement, as it does for the PCRs. The
  paths are stored in the blob (signed), not in a configuration file.
- **The generation is shared**, so a reseal raises it once and signs every
  profile again, each with PCR 11 computed from its own image. Raising the
  generation revokes all earlier approvals of the slot at once, which keeps
  revocation as simple as it is now.
- **The post hook passes the image it was called for** (`$2`). `reseal`
  still re-signs every profile (the generation is shared), but first
  compares: when every profile's recomputed PCR 11 and the other PCRs equal
  what is approved, nothing is written and nothing signed. During
  `mkinitcpio -P` the first run reseals, a later run whose image did not
  change the outcome is skipped.
- **A missing image** (a preset removed, a path renamed) drops that profile
  at the next reseal, with a message; the first profile's image missing is
  an error, as today.

## 5. The boot

`approvedSession` today verifies the one approval against the session's
policy digest (PolicyPCR + PolicyNV, then PolicyGetDigest), and
PolicyAuthorize takes the ticket. With profiles it tries each profile's
signature against that same digest with `TPM2_VerifySignature`, and uses the
one that verifies. Only the approval of the image that booted can verify,
since the digest comes from the live PCRs. At most three VerifySignature
calls, no extra NV reads, no change for the boot key, the release key or the
remote salt, which all authorize through this session.

A mismatch is explained as today, against the profile whose PCR 11 is
closest (all PCRs equal but 11: "an image that is not one of the slot's
profiles booted").

## 6. Phone attestation

The phone pins PCR values per *profile* already: an unexpected change asks
for approval, and an approved state is added to the machine's record
(`attest/verifier.go`). The first boot of a second image therefore asks once
on the phone and is known afterwards. Announcing the profiles at enrolment
(the machine predicts each image's values, the phone pins them all) is a
later improvement, not part of this plan.

## 7. Limits

- **PCR 11 only.** Profiles differ in PCR 11, which tpm2-kira computes from
  the image (`11u`). A selection that also contains a register an image
  changes in another way (PCR 4, the image as the firmware loaded it; PCR 9)
  is limited to one profile, and `control` says so where it offers the
  profiles.
- **Three profiles.** Enough for default and fallback with room to spare;
  the per-index limit makes more impractical anyway.
- **One kernel per image.** A profile is an image path. A kernel update
  rewrites the image in place and the reseal follows, as today.

## 8. Blob format (step 2)

The PCR list keeps every register except 11. PCR 11 becomes the profile
list, after the PCR digests:

```
Profile count           uint8       1–3; the first is the image 11u names
For each profile:
  Path length           uint16
  Path                  string      the image, as the preset names it
  PCR 11 length         uint16
  PCR 11                []byte      value at the measure point
  Approval length       uint16
  Approval              []byte      TPMT_SIGNATURE over H(approvedPolicy ‖ PolicyRef)
```

`ApprovalSignature` moves into the profile. A slot without `11u` has exactly
one profile with an empty path and no PCR 11 value, so every slot reads the
same way. The blob version is raised; existing slots are sealed again
(AGENTS.md: no migration).

## 9. Steps

1. **Blob cleanup and an active size check** (done): fields nothing reads
   are removed from the blob, the signing key paths are tpm2-kira's
   defaults instead of a record in every blob, and every write is checked
   against the TPM's NV index limit before the old index is touched. A
   phone is refused only when the blob with *that* phone would not fit.
2. **Profiles in the blob**: format (§8), `seal` and `reseal` signing every
   profile, the fit check per profile (§3.2), `info` and `status` listing
   them.
3. **The boot**: `approvedSession` choosing the approval that verifies (§5),
   mismatch explanation per profile.
4. **Presets and the hook**: reading the presets, the post hook passing the
   image, the skip when nothing changed (§4), `control` showing the
   profiles for acknowledgement.
5. **Tests and documentation**: swtpm integration with two images that
   differ in their initrd; SECURITY-BACKGROUND §3.1 and §10, SEALING.md,
   README.
6. **`control` checks every image, not only the default.** Today its
   image checks - the hook built in, the image newer than the boot, a
   file it is built from changed after it, the phone's Bluetooth part in
   it - look at the first preset's `default_uki` (or `default_image`)
   alone (`mkinitcpioImages`, `cmd/initramfs_hooks.go`); a fallback or a
   further profile is not looked at, so a stale one goes unnoticed and an
   image outside the presets' build list cannot raise a false alarm. With
   profiles every image matters. Proposed: the overview's Boot image line
   turns **orange** when the default image is good but another one is not,
   and picking it opens a submenu with one line per image (the preset's
   name and path) saying what each carries - the hook, the Bluetooth
   modules and the adapter's firmware - green or red, with the rebuild of
   the ones that lack something offered there. Images the presets name but
   do not build (`PRESETS=` leaves them out) are listed as such, not as
   failures.
