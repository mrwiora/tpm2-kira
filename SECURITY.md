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

The phone's screen is the only authoritative verdict. The machine's console
line is advisory: the initrd cannot authenticate the attestation blob that
names the enrolled phone (see `tpm2-kira attest check` for the check on the
booted system). Known residual risks:

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

## Security Design

For an in-depth description of the cryptographic architecture, threat model, authentication model (PolicyOR with PCR + PolicySigned branches), blob format, and trust boundaries, see [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md).