# PLAN — IMA appraisal of the initrd (later)

> **Status:** not started; written down on 2026-10-07 so the option is not
> lost. Nothing in tpm2-kira depends on it, and nothing here is scheduled.

## 1. What it would add

Today the binding between "the tpm2-kira that resealed the slot" and the
TPM is the measured image: `systemd-stub` extends PCR 11 with the initrd,
`seal`/`reseal` sign a policy over that value, and the TPM admits the
policy only if the signature verifies for the PCRs it recorded
(SECURITY-BACKGROUND.md §4, PLAN-FACTORRELEASE.md §8.4). A changed binary
gets no code and no factor. What it still gets is *to run*: the initrd
executes whatever is in it, and refusing is left to the TPM.

The kernel's Integrity Measurement Architecture (IMA) can add the other
half:

- **Measurement** (`ima_policy=tcb` or a custom policy): every executed
  file is hashed and the hash extended into PCR 10, with a log in
  `/sys/kernel/security/ima/ascii_runtime_measurements`. The measurer is
  the kernel, which is itself in PCR 11 (UKI) or 4/9 - in the chain, not
  the thing being measured.
- **Appraisal** (`ima_appraise=enforce`): a file without a valid signature
  in its `security.ima` extended attribute, verified against a key on the
  `.ima` kernel keyring, is not executed at all. A replaced tpm2-kira is
  refused before it runs, not only refused a secret afterwards.

Together they turn "the TPM will not unseal for a modified binary" into
"the kernel will not run a modified binary, and if it somehow did, the
TPM would not unseal for it".

## 2. What it would take

1. A kernel with `CONFIG_IMA`, `CONFIG_IMA_APPRAISE`,
   `CONFIG_IMA_ARCH_POLICY` or a custom policy, and the `.ima` keyring
   (`CONFIG_INTEGRITY_SIGNATURE`, `CONFIG_INTEGRITY_ASYMMETRIC_KEYS`). Arch's
   kernel has IMA built in but off by default (PLATFORM-OBSERVATIONS.md:
   `/sys/kernel/security/ima` absent on the T450s).
2. A signing certificate for file signatures, loaded into the `.ima`
   keyring: either built into the kernel, or signed by a key in the
   kernel's `.builtin_trusted_keys`/`.secondary_trusted_keys` (which with
   Secure Boot can be the MOK list). The private key stays with the
   image-building step - the same place and the same discipline as the
   slot's signing key.
3. **Signing the files in the initrd** at image build: `evmctl ima_sign`
   on every executable and library in the image (not only tpm2-kira: a
   policy that appraises `tpm2-kira` and nothing else is a policy an
   attacker renames around). mkinitcpio has no hook for this; it would be a
   post-processing step over `$BUILDROOT` before the image is packed, in
   our install hook or a separate one, and the extended attributes have to
   survive the cpio (`mkinitcpio` uses `bsdtar`/`cpio` formats that carry
   xattrs; to verify).
4. A policy loaded early: `ima_policy=` on the command line for the
   built-in ones, or `/etc/ima/ima-policy` written into the initrd, which
   systemd's `ima-setup` loads before anything else runs (systemd does
   this in the initrd when the file is present).
5. `ima_appraise=enforce` only after `ima_appraise=log` has shown that
   every file the initrd executes verifies; a single unsigned helper is an
   unbootable system.

## 3. What it does not change

- The TPM policy stays what it is. IMA is an addition in front of it, not
  a replacement: PCR 10 is not a good sealing target (it is the running
  aggregate of everything executed, in order, so any new file anywhere in
  the boot path moves it), and the policy signature over PCR 11 already
  covers the binary.
- It does not help against a tampered *kernel*: the kernel is the
  appraiser. Secure Boot over the UKI is what covers that.
- It does not cover what the binary does with its inputs; a signed binary
  with a flaw is still signed.

## 4. Where it would show in tpm2-kira

- `tpm2-kira info` / `attest status`: report whether IMA appraisal is
  enforcing (`/sys/kernel/security/ima/policy` readable and
  `ima_appraise=enforce` on `/proc/cmdline`), as a line of the platform
  report, the way the measure point is reported today.
- The install hook: sign the image's files when a signing certificate is
  configured; refuse to build an enforcing image with unsigned files.
- Nothing in the boot path: the kernel does the work before tpm2-kira runs.
