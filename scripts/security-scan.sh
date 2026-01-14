#!/bin/bash
# Local security scanning script for tpm2-kira
# This script runs the same security checks locally that run in CI/CD

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔒 tpm2-kira Local Security Scanner"
echo "===================================="
echo ""

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall status
OVERALL_STATUS=0

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ $status -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
        OVERALL_STATUS=1
    fi
}

# 1. Check if Go is installed
echo "Checking prerequisites..."
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Go is installed: $(go version)"
echo ""

# 2. Run go vet
echo "Running go vet..."
if go vet ./... 2>&1; then
    print_status 0 "go vet passed"
else
    print_status 1 "go vet found issues"
fi
echo ""

# 3. Run gofmt check
echo "Checking code formatting..."
UNFORMATTED=$(gofmt -l . | grep -v vendor/ | grep -v node_modules/ || true)
if [ -z "$UNFORMATTED" ]; then
    print_status 0 "Code is properly formatted"
else
    print_status 1 "Code formatting issues found:"
    echo "$UNFORMATTED"
fi
echo ""

# 4. Run GoSec if available
echo "Running GoSec security scanner..."
if command -v gosec &> /dev/null; then
    if gosec -quiet ./... 2>&1; then
        print_status 0 "GoSec found no security issues"
    else
        print_status 1 "GoSec found security issues"
    fi
else
    echo -e "${YELLOW}⚠${NC} GoSec not installed. Install with:"
    echo "  go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi
echo ""

# 5. Run Trivy if available
echo "Running Trivy vulnerability scanner..."
if command -v trivy &> /dev/null; then
    if trivy fs --quiet --severity HIGH,CRITICAL . 2>&1; then
        print_status 0 "Trivy found no high/critical vulnerabilities"
    else
        print_status 1 "Trivy found vulnerabilities"
    fi
else
    echo -e "${YELLOW}⚠${NC} Trivy not installed. Install from: https://github.com/aquasecurity/trivy"
fi
echo ""

# 6. Run Semgrep if available
echo "Running Semgrep security analysis..."
if command -v semgrep &> /dev/null; then
    if semgrep --config=auto --quiet --error 2>&1; then
        print_status 0 "Semgrep found no security issues"
    else
        print_status 1 "Semgrep found security issues"
    fi
else
    echo -e "${YELLOW}⚠${NC} Semgrep not installed. Install with:"
    echo "  pip install semgrep"
fi
echo ""

# Summary
echo "===================================="
if [ $OVERALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ All security checks passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some security checks failed${NC}"
    echo ""
    echo "Please review and fix the issues above."
    echo "For more details, see docs/SECURITY-SCANNING.md"
    exit 1
fi
