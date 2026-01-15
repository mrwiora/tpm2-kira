# Resolution: Code Scanning SARIF File Error

## Problem
The CodeQL Security Scan workflow was failing with the error:
```
Error: Code Scanning could not process the submitted SARIF file:
CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled
```

## Root Cause
GitHub's **default CodeQL setup** is currently enabled in the repository settings. This conflicts with the custom CodeQL workflow file (`.github/workflows/codeql-security.yml`) that uses advanced configuration with extended security queries.

GitHub does not allow both default setup and advanced (custom workflow) setup to run simultaneously.

## Solution Implemented

### Code Changes
The following changes have been made to the repository to document and guide users through resolving this issue:

1. **Created `.github/CODEQL_SETUP.md`**
   - Comprehensive documentation explaining the issue
   - Step-by-step instructions to disable default setup
   - Explanation of why advanced setup is beneficial for this repository

2. **Enhanced `.github/workflows/codeql-security.yml`**
   - Added clear header comments explaining the requirement
   - Added a "Check CodeQL Configuration" step that prints helpful messages during execution
   - Made the configuration more transparent and self-documenting

3. **Updated `SECURITY.md`**
   - Added a "Security Scanning" section
   - Referenced the CodeQL setup documentation
   - Made maintainers aware of the configuration requirement

### Manual Action Required
**To fully resolve the SARIF upload error, a repository administrator must:**

1. Navigate to the repository on GitHub.com
2. Go to **Settings** → **Code security and analysis**
3. Under **Code scanning** → **CodeQL analysis**
4. Click the **⋯** (three dots) menu
5. Select **"Switch to advanced"** or **"Disable"** the default setup

This action can only be performed through the GitHub web interface by someone with admin permissions on the repository.

## Verification
After disabling the default setup:
1. The workflow will run successfully on the next push to `dev` branch or PR
2. Code scanning results will appear under **Security** → **Code scanning alerts**
3. The SARIF upload error will be resolved

## Why Advanced Setup?
The custom workflow provides:
- **Extended security queries** (`security-extended`)
- **Code quality checks** (`security-and-quality`)
- More comprehensive vulnerability detection
- Better control over when scans run (push, PR, weekly schedule)

## Additional Notes
- This is a one-time configuration change
- Once switched to advanced setup, the custom workflow will handle all future scans
- The custom workflow is configured to run:
  - On every push to `dev` branch
  - On every pull request to `dev` branch
  - Weekly on Mondays at 00:00 UTC
