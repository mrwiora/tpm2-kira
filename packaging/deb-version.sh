#!/bin/sh
# Print a Debian-valid version derived from git describe.
#
#   exactly on a tag     v0.2.3                     -> 0.2.3
#   after a tag          v0.2.3-13-g1a2b3c4d        -> 0.2.3+13.g1a2b3c4d
#   prerelease tag       v0.3.0-rc1                 -> 0.3.0~rc1
#   prerelease + commits v0.3.0-rc1-13-g1a2b3c4d    -> 0.3.0~rc1+13.g1a2b3c4d
#   uncommitted changes  v0.2.3-dirty               -> 0.2.3+dirty
#
# '-' is not allowed in a native package version. '+' sorts AFTER the bare tag
# and '~' BEFORE it, which is exactly the ordering a post-tag build and a
# prerelease respectively need.
#
# Accepts a describe string as $1 so the mapping can be tested without a repo.

set -eu

describe=${1:-$(git describe --tags --dirty --always 2>/dev/null || echo 0.0.0)}
version=${describe#v}

dirty=
case $version in
*-dirty)
    dirty=1
    version=${version%-dirty}
    ;;
esac

# git describe appends -<commits>-g<hash>; anything else is part of the tag.
suffix=
if expr "$version" : '.*-[0-9][0-9]*-g[0-9a-f][0-9a-f]*$' >/dev/null; then
    distance=$(echo "$version" | sed -E 's/.*-([0-9]+)-g[0-9a-f]+$/\1/')
    commit=$(echo "$version" | sed -E 's/.*-[0-9]+-g([0-9a-f]+)$/\1/')
    version=$(echo "$version" | sed -E 's/-[0-9]+-g[0-9a-f]+$//')
    suffix="+${distance}.g${commit}"
fi

# Remaining hyphens can only be prerelease markers.
version=$(echo "$version" | tr '-' '~')

if [ -n "$dirty" ]; then
    if [ -n "$suffix" ]; then
        suffix="${suffix}.dirty"
    else
        suffix="+dirty"
    fi
fi

# A Debian version must start with a digit, and an untagged repo yields a bare
# commit hash, which may itself start with one. Require a dotted version.
case $version in
[0-9]*.[0-9]*) ;;
*) version="0.0.0+g${version}" ;;
esac

printf '%s%s\n' "$version" "$suffix"
