# Security Policy

## Supported Versions

The following versions of tpm2-kira are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.0.x   | :white_check_mark: |

## Automated Security Scanning

This project implements comprehensive automated security scanning using multiple AI-powered and industry-standard tools:

### Security Scanners

1. **CodeQL** - GitHub's semantic code analysis engine
   - Runs on every push and pull request
   - Scans for security vulnerabilities and code quality issues
   - Uses extended security queries for comprehensive coverage

2. **GoSec** - Go-specific security scanner
   - Identifies common security issues in Go code
   - Checks for hardcoded credentials, weak crypto, SQL injection, etc.

3. **Trivy** - Comprehensive vulnerability scanner
   - Scans dependencies for known vulnerabilities
   - Checks for misconfigurations
   - Detects critical, high, and medium severity issues

4. **Semgrep** - Pattern-based static analysis
   - Uses rules from security-audit, golang, secrets, and crypto rulesets
   - AI-powered pattern matching for security issues

5. **Nancy** - Sonatype OSS Index scanner
   - Scans Go dependencies for known vulnerabilities
   - Integrates with Sonatype's vulnerability database

### Scan Schedule

- **Push/Pull Request**: All scanners run automatically
- **Daily Schedule**: Security scans run at 2 AM UTC for continuous monitoring
- **Manual Trigger**: Security scans can be manually triggered via GitHub Actions

### Viewing Security Results

Security scan results are available in:
- [Security Tab](../../security) - View CodeQL, GoSec, Trivy, and Semgrep findings
- [Actions Tab](../../actions/workflows/security-scan.yml) - View scan execution logs
- Pull Request checks - See security status before merging

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in tpm2-kira, please report it responsibly:

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Send an email to the maintainers listed in [MAINTAINERS](MAINTAINERS) file
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Updates**: Every 5-7 days until resolved
- **Fix Timeline**: Critical issues will be addressed within 7 days, others within 30 days
- **Disclosure**: We follow responsible disclosure practices
  - Vulnerabilities will be patched before public disclosure
  - Credit will be given to security researchers (if desired)
  - Security advisories will be published after patches are released

### Security Best Practices

When using tpm2-kira:

1. **Keep Updated**: Always use the latest version
2. **Secure Your TPM**: Enable BIOS/UEFI TPM security features
3. **Strong Passwords**: Use strong passwords for fallback access
4. **PCR Selection**: Carefully choose appropriate PCRs for your security model
5. **Backup Secrets**: Securely backup your TOTP secrets
6. **Review Logs**: Monitor system logs for suspicious TPM activity

## Security Features

tpm2-kira includes several security features:

- **TPM 2.0 Hardware Binding**: Secrets are sealed to hardware TPM
- **PCR Policies**: Platform Configuration Register policies for secure boot verification
- **Password Protection**: Optional password-based fallback access
- **Secure Key Storage**: Keys never leave the TPM in plaintext
- **Memory Protection**: Sensitive data cleared from memory after use

## Security Considerations

Be aware of these security considerations:

1. **TPM Reset**: Clearing TPM will destroy sealed secrets
2. **Firmware Updates**: May change PCR values requiring reseal
3. **Physical Access**: Physical access to the device may bypass some protections
4. **Side Channels**: Consider side-channel attacks in high-security environments
5. **Backup Access**: Ensure you have fallback access methods before sealing

For more information, see the [README.md](README.md) documentation.
