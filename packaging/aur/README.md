# AUR packaging

The PKGBUILD published as [tpm2-kira](https://aur.archlinux.org/packages/tpm2-kira)
on the AUR.

## How it is built

`tpm2-kira` is a fixed-version package: it builds a **release tarball** pinned by
checksum, not a git checkout. GitHub's tag tarball leaves out the
[aSSH](../../assh/README.md) submodule, so aSSH comes as a second source, the
commit the tag's submodule is at:

```bash
_tag=v0.5.0-rc1
_assh=<the commit of assh/ at the tag>
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/$_tag.tar.gz")
source+=("assh-$_assh.tar.gz::https://github.com/tpm2-trust/assh/archive/$_assh.tar.gz")
```

`pkgver` and `_tag` are separate because an Arch `pkgver` may not contain `-`,
while a prerelease tag (`v0.3.0-rc1`) can. The release workflow sets both, and
`_assh` from `git rev-parse HEAD:assh`.

The committed `sha256sums=('SKIP' 'SKIP')` are placeholders. CI replaces them
with the real hashes via `updpkgsums`, so what lands on the AUR is always
checksummed. The committed `pkgver`, `_tag` and `_assh` are the last release's
and the submodule's current commit; install from the AUR:

```bash
paru -S tpm2-kira      # or your preferred helper
```

`.SRCINFO` is deliberately **not** committed here. It is generated from the
PKGBUILD at publish time, which removes any chance of the two disagreeing — the
AUR reads dependencies from `.SRCINFO`, so a stale copy advertises wrong
dependencies.

## Publishing

`.github/workflows/release.yml` publishes automatically on a release tag. The
`publish-aur` job clones the AUR repository, copies the PKGBUILD that was
actually built and tested, regenerates `.SRCINFO`, verifies the version matches
the tag, and pushes. Prerelease tags are skipped.

It needs one repository secret:

| Secret | Value |
|---|---|
| `AUR_SSH_PRIVATE_KEY` | Private half of an SSH key registered at https://aur.archlinux.org/account/ |

To set it up: create a dedicated key (`ssh-keygen -t ed25519 -C aur-ci`), add the
public half to your AUR account, and store the private half as the secret. Verify
with `ssh aur@aur.archlinux.org` — it should greet you by username.

## Testing a build locally

```bash
cd packaging/aur
TAG=v0.6.0-rc1     # a released tag; its pkgver drops the '-'
sed -i "s/^pkgver=.*/pkgver=$(echo "${TAG#v}" | tr -d -)/; s|^_tag=.*|_tag=$TAG|; s|^_assh=.*|_assh=$(git rev-parse "$TAG:assh")|" PKGBUILD
updpkgsums
makepkg -si
```

Use an existing tag; the tarball must already be published on GitHub, and
the assh commit on aSSH's.

## What the package does and does not do

- Installs the binary, the mkinitcpio install and post hooks, the initrd units
  (`tpm2-kira.service`, `tpm2-kira-cap.service`, `tpm2-kira-unlock.socket`,
  `tpm2-kira-attest.service`) and `/etc/tpm2-kira/control.conf`.
- Does **not** enable the units on the host. The mkinitcpio install hook
  enables it inside the initramfs image, which is the only place it should run.
- Does **not** run `tpm2-kira setup` or `tpm2-kira slot add`. Sealing generates a
  new TOTP secret and writes to TPM NVRAM, which must never happen as a side
  effect of installing a package or building an image. Run both once by hand,
  then rebuild the initramfs.
