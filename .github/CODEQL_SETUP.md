# CodeQL Setup Instructions

## Issue: SARIF Upload Error

If you encounter the error:
```
Error: Code Scanning could not process the submitted SARIF file:
CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled
```

This means that GitHub's **default CodeQL setup** is enabled in the repository settings, which conflicts with the custom CodeQL workflow in `.github/workflows/codeql-security.yml`.

## Solution

You need to **switch from default setup to advanced setup**. Follow these steps:

1. Navigate to the repository on GitHub.com
2. Click on **Settings** tab
3. Click on **Code security and analysis** in the left sidebar
4. Scroll down to the **Code scanning** section
5. Find **CodeQL analysis**
6. Click on the **⋯** (three dots) menu
7. Select **Switch to advanced** or **Disable** the default setup

## Why Advanced Setup?

This repository uses a custom CodeQL workflow with extended security queries:
- `security-extended`: Additional security vulnerability checks
- `security-and-quality`: Code quality and security analysis

The advanced setup (custom workflow) provides more control and additional checks compared to the default setup.

## After Disabling Default Setup

Once you've switched to advanced setup or disabled the default setup:
1. The custom workflow will run on:
   - Every push to the `dev` branch
   - Every pull request to the `dev` branch  
   - Weekly on Mondays at 00:00 UTC (scheduled)

2. Results will appear in the **Security** tab under **Code scanning alerts**

## Additional Information

- Custom workflow file: `.github/workflows/codeql-security.yml`
- Language analyzed: Go
- Go version: 1.21
- Analysis includes: Security-extended and security-and-quality queries
