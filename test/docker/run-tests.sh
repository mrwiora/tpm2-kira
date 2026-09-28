#!/bin/bash
# Runs the tests that need something this machine may not have: a TPM, and a
# PC/SC daemon with a reader attached.
set -u

# The source tree is mounted read-only; tests build binaries and write
# temporary files, so work on a copy.
cp -a /src /work-copy && cd /work-copy || exit 1

# --disable-polkit is needed because pcsc-lite 2.x asks polkit before accepting
# any client, and a container has no session bus for it to ask. That is not a
# workaround for the test — see docs/YUBIKEY.md, it is a real deployment
# consideration for unattended reseals too.
mkdir -p /run/pcscd
if pcscd --help 2>&1 | grep -q disable-polkit; then
    pcscd --disable-polkit > /tmp/pcscd.log 2>&1 &
else
    pcscd > /tmp/pcscd.log 2>&1 &
fi
sleep 2

echo "=== environment ==="
go version
pcscd --version 2>&1 | head -1
swtpm --version 2>&1 | head -1
echo

status=0

echo "=== unit tests ==="
go test ./... || status=1
echo

echo "=== integration tests (software TPM) ==="
go test -tags=integration -timeout 10m ./... || status=1
echo

echo "=== PC/SC tests (real pcscd, virtual reader) ==="
go test -tags=pcsc -timeout 5m ./internal/pcsc/ || status=1

exit $status
