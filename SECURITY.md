# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tpm2-kira:

1. **DO NOT** open a public GitHub issue.
2. Email the maintainers directly (see [MAINTAINERS](MAINTAINERS)).
3. Include:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)

We will acknowledge your report within 48 hours and keep you updated on our progress. If confirmed, we will coordinate a fix and disclosure timeline with you.

## Supported Versions

All versions of tpm2-kira receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| *       | :white_check_mark: |

## Automated Penetration Testing with Strix AI

This project uses [Strix AI](https://strix.ai) for automated penetration testing. Strix is an autonomous AI security agent that dynamically probes the codebase for vulnerabilities, validates findings with real proof-of-concepts, and produces actionable reports.

### How it's triggered

The Strix scan runs as a GitHub Actions workflow (`.github/workflows/strix-security-scan.yml`) on pull requests whose **source branch name ends with `pentest`** — for example `feature-xyz-pentest` or `bugfix-123-pentest`. This keeps the (relatively expensive) deep scan out of the normal CI path and runs it only when explicitly requested.

The workflow supports three scan modes via manual dispatch (`workflow_dispatch`):

| Mode | Description |
|------|-------------|
| `quick` | Fast surface-level check (default) |
| `standard` | Broader coverage |
| `deep` | Full deep scan with higher reasoning effort |

Results are uploaded as a GitHub Actions artifact (`strix-security-report`, retained for 30 days) and — for PRs — summarized in a comment on the pull request.

### Performed scans

| Date | Scope | Codebase state | Duration | Result | Link |
|------|-------|----------------|----------|--------|------|
| 2026-02-02 | Full scan | `dev` branch, between releases 0.0.12 and 0.0.13 (PR [#26](https://github.com/mrwiora/tpm2-kira/pull/26), branch `copilot/add-ai-pentest-scan-workflow`) | ~56 min | Completed, report artifact available | [Actions run](https://github.com/mrwiora/tpm2-kira/actions/runs/20994975512/job/62242599102) |

The scan report artifact (`strix-security-report`, 23.7 KB) is downloadable from the Actions run linked above.

## Remote attestation with a phone: what it does not protect against

The phone's screen is the only authoritative verdict; the machine's console
line is advisory.

The record that names the enrolled phone lives in TPM NV storage, where the
owner hierarchy (root, or another OS booted on this machine) can replace it:
with one naming an attacker's phone, or with an older one that still names a
phone you removed. The gate therefore checks the record before it advertises,
in the initrd, before a passphrase is typed and whether or not a phone is
there:

- **its signature**, against this machine's signing public key, a copy of
  which the hook puts into the image (public, not a secret). That refuses a
  record written by anyone else;
- **its count**, against a counter the TPM holds for the slot. Every record
  tpm2-kira writes carries the counter's next value, and a TPM counter cannot
  be turned back: even deleting it only makes the TPM start a new one above
  the old value. That refuses an older record, however genuinely signed.

Enrolling or removing a phone writes a new signed record with the next count;
the image stays as it is, so nothing has to be rebuilt.

Known residual risks:

- **The public key is as trustworthy as the initramfs that carries it.**
  Whoever can replace the image can replace the key with it, and then sign a
  record of their own. That is noticed when the image is a unified kernel
  image signed for Secure Boot, or when the PCRs that the TOTP seal or the
  phone checks cover the initrd (`attest enrol` and `seal` warn when they do
  not). With neither - a seal on PCRs 0, 2, 7 only, say, and no Secure Boot -
  a replaced record goes unnoticed, as would any other change to the
  initramfs. Nothing checks the record after the disk is unlocked: by then
  the passphrase has been typed.
- **The counter can be pushed up, not back.** Someone with the owner hierarchy
  can raise it, which makes the genuine record stale: the gate then refuses
  it and no phone is served until you enrol again. That denies the phone
  check; it never produces an accepted record.
- **The attestation blob is readable by anyone who can talk to the TPM.**
  It holds the machine's Noise private key and its advertising key. Someone
  who reads it once — root, or a live USB on this machine — can recognise the
  machine's advertisements and imitate its Bluetooth endpoint. They cannot
  produce a quote: quotes come from the TPM, are bound to the session, and a
  tampered boot reports tampered PCRs. The phone then shows a failed or
  changed verdict, or "did not accept this phone", never a green one.
  Sealing these keys to the PCRs was rejected: a legitimate update could then
  not show its "changed" diff, which is the point of the phone.
- **Relay to a look-alike machine.** Attestation proves that *your enrolled
  TPM* booted a known state, not that the laptop in front of you is that
  machine. An attacker who swaps the laptop for a look-alike and relays
  Bluetooth to the real one (kept elsewhere, booted cleanly) gets a green
  check, and the passphrase is typed into the fake. The TOTP check has the
  same limit, and Bluetooth LE offers no secure distance bounding. Mitigations:
  tamper-evident marking of the device, and salt release (PLAN-FACTORRELEASE.md),
  after which the passphrase alone no longer opens the disk.
- **A machine compromised before enrolment.** Enrolment pins whatever TPM
  answers. `attest ekcert` and the phone show whether the TPM's endorsement
  key is certified by its vendor (currently Intel PTT); "not verified" means
  this protection is absent.
- **The initrd must be covered by the quoted PCRs.** `attest enrol` warns
  when it is not; see README.md, "Choose PCRs that cover the initrd".

## The Bluetooth gate's process

`tpm2-kira-attest.service` is the only part of tpm2-kira that takes input from
outside the machine before the disk is unlocked: it parses Bluetooth packets
from anyone in range, as root. Its unit therefore confines it to what it
needs: `AF_BLUETOOTH` and `AF_UNIX` sockets and no IP, `CAP_NET_ADMIN` and
`CAP_NET_RAW` and no other capability, the TPM, rfkill and the console as its
only devices, a read-only file system, no new privileges, and a system call
filter. A parsing bug in the radio path would be confined to that. The unit is
in the image only when attestation is enabled and a phone is enrolled. On
initramfs-tools (Debian) the gate is started by a script and is not confined
this way.

## The TOTP secret on a running system

`tpm2-kira.service` checks its policy in the initrd *before*
`systemd-pcrosseparator.service` extends PCRs 0–7, 9, 12–14, and is
`Type=notify` so that the separator waits for that check. The key is an HMAC
key object that never leaves the TPM; while the display holds the boot (a
fresh code every 30 seconds until Enter or 90 seconds), the policy is still
satisfiable, and the moment it releases the boot it exits. PCR extends are
one-way: once the
separator has run, no process in the booted system — root included — can
satisfy the key's policy again until the next boot; `tpm2-kira cap` read-locks
the generation index at `initrd-switch-root` on top of that. `tpm2-kira
reveal` on the running system reports the slot as *locked until the next
boot*. A runtime compromise can therefore neither read the key nor compute a
code to replay at a later, tampered boot.

Two things fall outside that lock:

- **The signing key.** Whoever can use it can approve a new policy for the
  current state and compute codes at any time. Keep it on a YubiKey (the
  intended setup); a key file under `/var/lib/tpm2-kira/keys` is the fallback,
  better than no recovery path, but with it a runtime root has that power.
- **Blobs whose policy holds after the separator.** Blobs from versions that
  ran after the separator, and blobs sealed from registers because the event
  log could not be replayed, get their codes live after the boot has been
  released, until `cap`. They work, the display marks their code, and a reseal
  moves them before the separator where the log allows it.

## Security Design

For an in-depth description of the cryptographic architecture, threat model, authentication model (an HMAC key inside the TPM under PolicyAuthorize, with a revocable generation and a boot-time cap), blob format, and trust boundaries, see [SECURITY-BACKGROUND.md](docs/SECURITY-BACKGROUND.md).