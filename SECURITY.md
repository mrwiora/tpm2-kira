# Security Policy

## Supported Versions

All versions of tpm2-kira are currently supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| *       | :white_check_mark: |

## Automated Security Testing

This project uses [Strix AI](https://strix.ai) for automated penetration testing on every pull request. Strix is an autonomous AI security agent that:

- Dynamically tests code for vulnerabilities
- Validates findings with real proof-of-concepts
- Provides actionable security reports

### Required GitHub Secrets

To enable Strix security scanning in CI/CD, the following secrets must be configured in the repository settings:

1. **`STRIX_LLM`** - The LLM provider and model (e.g., `openai/gpt-5`, `anthropic/claude-sonnet-4-5`)
2. **`LLM_API_KEY`** - API key for your chosen LLM provider
3. **`PERPLEXITY_API_KEY`** (optional) - API key for enhanced search capabilities

### Running Strix Locally

To run Strix security scans locally:

```bash
# Install Strix
curl -sSL https://strix.ai/install | bash

# Configure environment
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Run security assessment
strix --target ./
```

For more information, see the [Strix documentation](https://docs.strix.ai).

## Reporting a Vulnerability

If you discover a security vulnerability in tpm2-kira, please report it by:

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainers directly (see MAINTAINERS file)
3. Include detailed information about the vulnerability:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

We will acknowledge receipt of your vulnerability report within 48 hours and will send you regular updates about our progress. If the vulnerability is accepted, we will work on a fix and coordinate disclosure timing with you.
