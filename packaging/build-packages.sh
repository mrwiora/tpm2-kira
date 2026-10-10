#!/usr/bin/env bash
# Builds the packages of the committed state (HEAD) in one run:
#
#   arch   the Arch Linux package, with makepkg on this machine
#   deb    the Debian package, in a Debian 13 container (packaging/deb/Dockerfile)
#   apk    the Marify app: the Go core (gomobile) and the debug and release APKs
#
# Usage: packaging/build-packages.sh [arch] [deb] [apk] [--core-head]
#
# Without targets all three are built. Everything lands in build/packages/.
#
# The app links the tpm2-kira commit pinned in marify/core.properties.
# --core-head pins HEAD there first (a change to commit in marify);
# without it, a pin behind HEAD is reported and built as pinned.
#
# Environment:
#   GOVERSION    Go release to build with (default: the current one from
#                go.dev, as AGENTS.md asks; else the local go's)
#   MARIFY_SRC   the Marify checkout (default ../marify next to this one)
#   ANDROID_HOME Android SDK with an NDK (for apk; see marify's build-core.sh)
#   JAVA_HOME    a JDK (for apk: gomobile runs javac, Gradle runs on it)
#
# Uncommitted changes are not built: the packages come from 'git archive
# HEAD', so they always match a commit.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

targets=()
core_head=false
for arg in "$@"; do
    case $arg in
        arch | deb | apk) targets+=("$arg") ;;
        --core-head) core_head=true ;;
        -h | --help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg (arch, deb, apk, --core-head)" >&2; exit 2 ;;
    esac
done
((${#targets[@]})) || targets=(arch deb apk)
want() { [[ " ${targets[*]} " == *" $1 "* ]]; }

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "note: uncommitted changes are not in the packages (built from HEAD)"
fi

short="$(git rev-parse --short HEAD)"
full="$(git rev-parse HEAD)"
gover="${GOVERSION:-$(curl -fsS --max-time 10 'https://go.dev/VERSION?m=text' 2>/dev/null | head -1 || true)}"
[[ -n "$gover" ]] || gover="$(go env GOVERSION)"
out="$root/build/packages"
mkdir -p "$out"
echo "tpm2-kira $short, Go $gover, into build/packages/"

# Check every target's tools before building anything.
if want arch; then command -v makepkg >/dev/null || die "makepkg not found: the Arch package is built on Arch Linux (or leave out 'arch')"; fi
if want deb; then command -v docker >/dev/null || die "docker not found: the Debian package is built in a container (or leave out 'deb')"; fi
marify="${MARIFY_SRC:-$root/../marify}"
if want apk; then
    [[ -x "$marify/android/gradlew" ]] || die "no Marify checkout at $marify (set MARIFY_SRC, or leave out 'apk')"
    [[ -n "${JAVA_HOME:-}" ]] && export PATH="$JAVA_HOME/bin:$PATH"
    command -v javac >/dev/null || die "no JDK: set JAVA_HOME to one (gomobile needs javac), or leave out 'apk'"
fi

if want arch; then
    step "Arch Linux package"
    version="$(git describe --tags --long HEAD | sed -e 's/^v//' -e 's/-\([0-9]\+\)-g/.r\1.g/' | tr '-' '_')"
    aur="$root/build/aur"
    mkdir -p "$aur"
    rm -rf "$aur"/tpm2-kira-* "$aur/PKGBUILD" "$aur/src" "$aur/pkg"
    git archive --format=tar.gz --prefix="tpm2-kira-$short/" -o "$aur/tpm2-kira-$short.tar.gz" HEAD
    digest="$(sha256sum "$aur/tpm2-kira-$short.tar.gz" | cut -d' ' -f1)"
    # The PKGBUILD in packaging/aur fetches the release tag; this one takes
    # the archive of HEAD instead.
    sed -e '/^_tag=/d' \
        -e "s/^pkgver=.*/pkgver=$version/" \
        -e "s/^source=.*/source=(\"tpm2-kira-$short.tar.gz\")/" \
        -e "s/^sha256sums=.*/sha256sums=('$digest')/" \
        -e "s/^_srcdir=.*/_srcdir=\"\$pkgname-$short\"/" \
        packaging/aur/PKGBUILD > "$aur/PKGBUILD"
    # The unit tests have their own run (AGENTS.md); --nocheck skips them here.
    (cd "$aur" && GOTOOLCHAIN="$gover" makepkg -f --nocheck)
    rm -f "$out"/tpm2-kira-*.pkg.tar.zst
    cp "$aur"/tpm2-kira-"$version"-*.pkg.tar.zst "$out/"
fi

if want deb; then
    step "Debian package"
    image="tpm2-kira-deb-build:$gover"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        docker build -t "$image" --build-arg GOVER="$gover" packaging/deb
    fi
    debver="$(packaging/deb-version.sh "$(git describe --tags HEAD)")"
    deb="$root/build/deb"
    mkdir -p "$deb"
    rm -f "$deb"/*.deb "$deb"/*.changes "$deb"/*.buildinfo "$deb"/tpm2-kira-*.tar.gz
    git archive --format=tar.gz --prefix="tpm2-kira-$short/" -o "$deb/tpm2-kira-$short.tar.gz" HEAD
    # The Go build cache stays in build/deb/.gocache across runs.
    docker run --rm -v "$deb:/out" -e SHORT="$short" -e DEBVER="$debver" -e OWNER="$(id -u):$(id -g)" \
        "$image" bash -ec '
            mkdir -p /build && cd /build
            tar xzf "/out/tpm2-kira-$SHORT.tar.gz" && cd "tpm2-kira-$SHORT"
            sed -i "1s/^tpm2-kira (.*)/tpm2-kira ($DEBVER)/" debian/changelog
            DEB_BUILD_OPTIONS=nocheck GOCACHE=/out/.gocache dpkg-buildpackage -us -uc -b
            cp ../tpm2-kira_*.deb ../*.changes ../*.buildinfo /out/
            chown -R "$OWNER" /out'
    rm -f "$out"/tpm2-kira_*.deb
    cp "$deb"/tpm2-kira_*.deb "$out/"
fi

if want apk; then
    step "Marify (Android)"
    props="$marify/core.properties"
    pinned="$(sed -n 's/^kira.commit=//p' "$props")"
    if [[ "$pinned" != "$full" ]]; then
        if $core_head; then
            sed -i "s/^kira.commit=.*/kira.commit=$full/" "$props"
            echo "core.properties now pins tpm2-kira $short: commit it in $marify"
        else
            echo "note: the app links tpm2-kira ${pinned:0:7}, not HEAD $short (--core-head pins HEAD)"
        fi
    fi
    KIRA_SRC="$root" "$marify/android/scripts/build-core.sh"
    (cd "$marify/android" && ./gradlew --quiet assembleDebug assembleRelease)
    apks="$marify/android/app/build/outputs/apk"
    rm -f "$out"/marify-*.apk
    cp "$apks/debug/app-debug.apk" "$out/marify-debug.apk"
    for f in "$apks"/release/*.apk; do
        cp "$f" "$out/marify-$(basename "$f" | sed 's/^app-//')"
    done
fi

step "Built"
ls -lh "$out"
