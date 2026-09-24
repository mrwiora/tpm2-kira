# Packaging

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
