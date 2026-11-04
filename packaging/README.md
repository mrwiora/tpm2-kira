# Packaging

`make packages` (or [build-packages.sh](build-packages.sh)) builds everything
from the committed state in one run: the Arch package with `makepkg`, the
Debian package in a Debian 13 container ([deb/Dockerfile](deb/Dockerfile),
built on first use with the current Go release), and the Marify APKs next to
this checkout. `packaging/build-packages.sh deb` builds one; `--help` lists
the options. The results are in `build/packages/`.

Every release recipe runs [release-binary-check.sh](release-binary-check.sh) on what
it built: a release's binaries carry no Go build tag. `build-packages.sh --fast-kdf`
alone makes a test package, into `build/packages-fastkdf/`
([docs/TESTING.md](../docs/TESTING.md)).

| Target | Where |
|--------|-------|
| Arch Linux (AUR) | [aur/](aur/) |
| Debian / Ubuntu | [`debian/`](../debian/) — at the **repository root** |

`debian/` cannot live here. `dpkg-buildpackage` requires the packaging
directory at the top of the source tree and offers no way to point it
elsewhere. A symlink builds, but `dpkg-source` then walks both paths into the
native tarball, so the split is deliberate rather than an oversight.

[deb-version.sh](deb-version.sh) turns `git describe` into a version both
packaging systems accept, and is shared by `make deb` and the release workflow
so the two cannot drift apart.

The files that get *installed* by either package live in
[../initramfs/](../initramfs/), grouped by initramfs generator.
