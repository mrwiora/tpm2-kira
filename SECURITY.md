# Security Policy

## Supported Versions

This project currently supports all versions with security updates.

| Version | Supported          |
| ------- | ------------------ |
| *       | :white_check_mark: |

## Automated Security Scanning

This repository uses **HexStrike AI** for automated security scanning through GitHub Actions. The workflow:

- Runs on every push to `main` and `dev` branches
- Executes on all pull requests
- Performs daily scheduled scans at 2 AM UTC
- Can be manually triggered via workflow dispatch

### What is HexStrike AI?

HexStrike AI is an advanced AI-driven cybersecurity automation platform that integrates 150+ security tools to perform comprehensive vulnerability scanning and security analysis. More information: [HexStrike AI Repository](https://github.com/0x4m4/hexstrike-ai)

### Security Scan Coverage

The automated workflow includes:
- Static code analysis
- Dependency vulnerability scanning
- Configuration security checks
- Best practices validation
- Security tool analysis (Nmap, Nikto, SQLMap, etc.)

Security scan reports are automatically generated and available as workflow artifacts.

## Reporting a Vulnerability

If you discover a security vulnerability in tpm2-kira, please report it by:

1. **Do NOT** open a public issue
2. Email the maintainers directly (see MAINTAINERS file)
3. Include detailed information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Timeline

- **Initial Response**: Within 48 hours of report
- **Status Update**: Within 7 days with assessment
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Best effort basis

### Disclosure Policy

- We follow coordinated disclosure practices
- Vulnerabilities will be patched before public disclosure
- Credit will be given to reporters (unless anonymity is requested)
- Security advisories will be published after fixes are released
