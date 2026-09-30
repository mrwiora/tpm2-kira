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
go test -count=1 ./... || status=1
echo

echo "=== integration tests (software TPM) ==="
go test -count=1 -tags=integration -timeout 10m ./... || status=1
echo

# The container runs as root, which hides anything that wrongly demands it. The
# integration suite drives a software TPM over a socket the test user owns, so it
# must pass unprivileged — a check that only exists because keying the privilege
# requirement off the command name once broke exactly this.
echo "=== integration tests as an unprivileged user ==="
if id tpm2kiratest >/dev/null 2>&1 || useradd -m tpm2kiratest 2>/dev/null; then
    chmod -R a+rwX /work-copy
    mkdir -p /tmp/gocache-unpriv && chmod 777 /tmp/gocache-unpriv
    su tpm2kiratest -c "export PATH=$PATH GOCACHE=/tmp/gocache-unpriv \
        GOMODCACHE=$GOMODCACHE GOFLAGS=-mod=mod; \
        cd /work-copy && go test -count=1 -tags=integration -timeout 10m ./test/integration/" || status=1
else
    echo "  (could not create an unprivileged user; skipped)"
fi
echo

echo "=== PC/SC tests (real pcscd, virtual reader) ==="
go test -count=1 -tags=pcsc -timeout 5m ./internal/pcsc/ || status=1
echo

# Both simulators at once: a software TPM and a virtual YubiKey. This is the
# only pass that exercises the whole feature — key reference, PC/SC transport,
# PIV APDUs, TPM2_PolicySigned and the NVRAM write — without hardware.
echo "=== YubiKey end-to-end (software TPM + virtual PIV card) ==="
# Everything in the root package that needs both simulators. The reader lock in
# internal/virtualpiv makes the whole-tree form safe too, but naming the tests
# keeps this pass quick and its output readable.
go test -count=1 -tags="integration pcsc" -timeout 10m -run "TestYubiKey|TestSetup" -v \
    ./test/integration/ 2>&1 |
    grep -E "^(=== RUN|--- |ok|FAIL)|_test.go:" || status=1

exit $status
