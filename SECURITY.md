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

## Security Design

For an in-depth description of the cryptographic architecture, threat model, authentication model (PolicyOR with PCR + PolicySigned branches), blob format, and trust boundaries, see [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md).