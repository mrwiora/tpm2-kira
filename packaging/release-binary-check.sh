#!/bin/sh
# A binary of a release carries no Go build tag: a tag can change the security
# parameters a build has (internal/diskkey/combine_cost_fast.go). Every release
# recipe runs this on what it built, and refuses to go on.
#
# Usage: packaging/release-binary-check.sh BINARY...
set -eu
[ $# -gt 0 ] || { echo "usage: $0 BINARY..." >&2; exit 2; }
for b in "$@"; do
    info=$(go version -m "$b") || { echo "$b: go version -m failed" >&2; exit 1; }
    if printf '%s\n' "$info" | grep -q 'build[[:space:]]*-tags='; then
        echo "$b was built with Go build tags: a release carries none" >&2
        printf '%s\n' "$info" | grep 'build[[:space:]]*-tags=' >&2
        exit 1
    fi
    if grep -aq 'kira_test_fast_kdf' "$b"; then
        echo "$b holds the test build's mark (kira_test_fast_kdf): a release does not" >&2
        exit 1
    fi
done
