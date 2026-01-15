# Security Policy

## Supported Versions

This project currently supports all versions with security updates.

| Version | Supported          |
| ------- | ------------------ |
| *       | :white_check_mark: |

## Automated Security Scanning

This repository includes a **HexStrike AI** security framework setup workflow through GitHub Actions. The workflow:

- Runs on every push to `main` and `dev` branches
- Executes on all pull requests
- Performs daily scheduled setup verification at 2 AM UTC
- Can be manually triggered via workflow dispatch

### What is HexStrike AI?

HexStrike AI is an advanced AI-driven cybersecurity automation platform that integrates 150+ security tools to perform comprehensive vulnerability scanning and security analysis. It operates as an MCP (Model Context Protocol) server that requires an AI client (Claude Desktop, VS Code Copilot, etc.) for interactive security testing. More information: [HexStrike AI Repository](https://github.com/0x4m4/hexstrike-ai)

### Security Framework Setup

The automated workflow provides:
- HexStrike AI framework installation and verification
- Essential security tools setup (Nmap, Nikto, SQLMap, Gobuster, etc.)
- Python environment configuration for security analysis
- Infrastructure readiness validation

**Important:** This workflow sets up the security framework infrastructure but does not perform active vulnerability scanning. HexStrike AI requires an MCP client connection for interactive security analysis.

### Additional Security Tools

For automated security scanning in CI/CD, the repository also benefits from:
- GitHub's built-in Dependabot for dependency vulnerability alerts
- CodeQL for code security analysis (if enabled)
- Regular security audits by maintainers

Framework setup reports are automatically generated and available as workflow artifacts.

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
