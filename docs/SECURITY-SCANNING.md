# Security Scanning and AI Penetration Testing

This document describes the automated security scanning infrastructure implemented in tpm2-kira, including AI-powered security analysis tools.

## Overview

The tpm2-kira project uses a comprehensive suite of automated security scanning tools to continuously monitor for vulnerabilities, security issues, and code quality problems. The security scanning workflow runs multiple specialized tools in parallel to provide comprehensive coverage.

## Security Scanning Tools

### 1. CodeQL (GitHub Advanced Security)

**Purpose**: Semantic code analysis for vulnerability detection

**What it does**:
- Deep semantic analysis of Go code
- Identifies complex security vulnerabilities
- Detects data flow issues (SQL injection, XSS, path traversal, etc.)

**Configuration**:
- Enabled via GitHub's default setup (native integration)
- Automatically scans on every push and pull request
- No manual workflow configuration required

**When it runs**:
- Automatically via GitHub default setup
- Every push to main/dev branches
- Every pull request

**Results**: Available in GitHub Security tab under "Code scanning alerts"

### 2. GoSec

**Purpose**: Go-specific security vulnerability scanner

**What it checks**:
- Hardcoded credentials
- Weak cryptographic practices
- SQL injection vulnerabilities
- Command injection
- File inclusion issues
- Unsafe use of reflect
- Integer overflows
- Directory traversal

**Output format**: SARIF (uploaded to GitHub Security tab)

**Configuration**: Scans all Go packages in the repository

### 3. Trivy

**Purpose**: Comprehensive vulnerability and misconfiguration scanner

**What it scans**:
- Known vulnerabilities (CVEs) in dependencies
- Go module vulnerabilities
- Misconfigurations in code
- Security issues in configuration files
- Licenses compliance

**Severity levels**: CRITICAL, HIGH, MEDIUM

**Results**: SARIF format uploaded to GitHub Security tab

### 4. Semgrep

**Purpose**: AI-powered pattern-based static analysis

**Rulesets used**:
- `p/security-audit` - General security auditing rules
- `p/golang` - Go-specific security patterns
- `p/secrets` - Hardcoded secrets detection

**Features**:
- Pattern matching with semantic awareness
- Fast scanning with low false positives
- Community-contributed rules
- AI-assisted rule suggestions

**Output**: SARIF format for GitHub Security integration

### 5. Dependency Review (Pull Requests Only)

**Purpose**: Review dependency changes in pull requests

**What it checks**:
- New vulnerabilities introduced by dependency changes
- License compliance issues
- Denied licenses (GPL-3.0, AGPL-3.0)

**Threshold**: Fails on moderate or higher severity vulnerabilities

**Note on Nancy**: Nancy (Sonatype OSS Index scanner) has been removed from the workflow as it requires authentication credentials to access the OSS Index API. Dependency vulnerability scanning is adequately covered by Trivy, Dependency Review, and CodeQL.

## Workflow Architecture

### Parallel Execution

All scanning tools run in parallel as separate jobs to minimize execution time:

```
Security Scan Workflow
├── CodeQL Analysis (GitHub default setup, runs automatically)
├── Dependency Review (PRs only)
├── GoSec Analysis
├── Trivy Scan
├── Semgrep Scan
└── Security Summary (aggregates results)
```

### Permissions

The workflow uses minimal required permissions:
- `contents: read` - Read repository code
- `security-events: write` - Write to Security tab
- `actions: read` - Read action metadata

### Trigger Conditions

**Automatic triggers**:
- Push to `dev` or `main` branches
- Pull requests to `dev` or `main` branches
- Scheduled daily at 2 AM UTC

**Manual trigger**:
- `workflow_dispatch` - Can be triggered manually from Actions tab

## Viewing Results

### GitHub Security Tab

1. Navigate to repository Security tab
2. Click on "Code scanning alerts"
3. Filter by:
   - Tool (CodeQL, GoSec, Trivy, Semgrep)
   - Severity (Critical, High, Medium, Low)
   - Status (Open, Closed, Fixed)

### Actions Tab

1. Go to Actions → Security Scanning workflow
2. Click on a specific run
3. View individual job logs
4. Check the Security Summary at the bottom

### Pull Request Checks

- Security scan status shows in PR checks
- Failed scans block merge (configurable)
- Click "Details" to see specific findings

## Integration with Development Workflow

### Pre-commit

While the automated scans run on every push, consider adding pre-commit hooks for faster feedback:

```bash
# Install pre-commit hook for GoSec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run before committing
gosec ./...
```

### Local Scanning

Run security scans locally before pushing:

```bash
# GoSec
gosec ./...

# Trivy
trivy fs .

# Semgrep
semgrep --config "p/security-audit" .

# Note: Nancy has been removed as it requires authentication.
# Dependency scanning is covered by Trivy and Dependency Review.
```

## AI-Powered Features

### Semgrep AI

Semgrep uses machine learning and AI to:
- Identify complex security patterns
- Reduce false positives
- Suggest fixes for common issues
- Learn from community patterns

### CodeQL AI-Assisted Analysis

CodeQL leverages AI for:
- Data flow analysis
- Taint tracking
- Pattern recognition
- Vulnerability prediction

## Responding to Security Findings

### Severity Classification

**Critical** (P0):
- Immediate action required
- Fix within 24 hours
- May require hotfix release

**High** (P1):
- Action required
- Fix within 7 days
- Include in next release

**Medium** (P2):
- Should fix
- Fix within 30 days
- Include in upcoming release

**Low** (P3):
- Nice to fix
- Fix when convenient
- Consider in future releases

### Remediation Process

1. **Triage**: Review finding details in Security tab
2. **Validate**: Confirm if it's a true positive
3. **Fix**: Implement fix in code
4. **Test**: Verify fix with tests
5. **Verify**: Re-run security scan
6. **Close**: Mark as resolved in Security tab

### False Positives

If a finding is a false positive:

1. Document why it's not a real issue
2. Add suppression comment in code
3. Close with reason in Security tab
4. Consider updating scan configuration

Example suppression:
```go
// #nosec G104 - Error intentionally ignored in this context
_, _ = fmt.Println("message")
```

## Best Practices

### For Contributors

1. **Run local scans** before pushing
2. **Review security findings** in PRs
3. **Don't ignore warnings** without investigation
4. **Use secure coding patterns** from the start
5. **Keep dependencies updated**

### For Maintainers

1. **Review security alerts regularly**
2. **Prioritize security fixes**
3. **Keep scanning tools updated**
4. **Monitor scan performance**
5. **Document security decisions**

## Continuous Improvement

### Metrics to Track

- Number of findings per scan
- Time to remediate by severity
- False positive rate
- Scan execution time
- Coverage percentage

### Regular Reviews

- **Weekly**: Review new findings
- **Monthly**: Analyze trends
- **Quarterly**: Evaluate tool effectiveness
- **Annually**: Assess overall security posture

## Additional Resources

### Documentation

- [GitHub CodeQL Documentation](https://codeql.github.com/docs/)
- [GoSec Rules](https://github.com/securego/gosec#rules)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Semgrep Rules](https://semgrep.dev/r)
- [Nancy Documentation](https://github.com/sonatype-nexus-community/nancy)

### Security Standards

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Go Security Best Practices](https://github.com/OWASP/Go-SCP)

### Reporting Issues

For security vulnerabilities, see [SECURITY.md](../SECURITY.md)

For scanning infrastructure issues, open a GitHub issue with label `security-scanning`.

## Future Enhancements

### Planned Additions

1. **DAST (Dynamic Analysis)**:
   - Runtime vulnerability testing
   - API security testing
   - Fuzzing integration

2. **Supply Chain Security**:
   - SLSA compliance checking
   - Build provenance verification
   - Software Bill of Materials (SBOM)

3. **Advanced AI Tools**:
   - Integration with Strix AI penetration testing
   - Machine learning-based anomaly detection
   - Predictive vulnerability analysis

4. **Compliance Scanning**:
   - PCI-DSS compliance checks
   - SOC 2 requirements validation
   - GDPR data flow analysis

### Contributing

To improve security scanning:

1. Suggest new tools or rules
2. Report false positives/negatives
3. Contribute custom security patterns
4. Improve documentation

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

---

**Last Updated**: 2026-01-14
**Maintained By**: tpm2-kira security team
