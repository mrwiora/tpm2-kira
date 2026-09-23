# AUR packaging

The PKGBUILD published as [tpm2-kira](https://aur.archlinux.org/packages/tpm2-kira)
on the AUR.

## How it is built

`tpm2-kira` is a fixed-version package: it builds a **release tarball** pinned by
checksum, not a git checkout.

```bash
_tag="v$pkgver"
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/$_tag.tar.gz")
```

`pkgver` and `_tag` are separate because an Arch `pkgver` may not contain `-`,
while a prerelease tag (`v0.3.0-rc1`) can. The release workflow sets both.

The committed `sha256sums=('SKIP')` is a placeholder. CI replaces it with the
real hash via `updpkgsums`, so what lands on the AUR is always checksummed.
That means **this file cannot be built directly from the repository** — `pkgver`
is `0.0.0` and no such tag exists. Install from the AUR instead:

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
sed -i 's/^pkgver=.*/pkgver=0.2.3/; s|^_tag=.*|_tag=v0.2.3|' PKGBUILD
updpkgsums
makepkg -si
```

Use an existing tag; the tarball must already be published on GitHub.

## What the package does and does not do

- Installs the binary, the mkinitcpio install and post hooks, and
  `tpm2-kira.service`.
- Does **not** enable the service on the host. The mkinitcpio install hook
  enables it inside the initramfs image, which is the only place it should run.
- Does **not** run `tpm2-kira setup`. That generates a new TOTP secret and writes
  to TPM NVRAM, which must never happen as a side effect of installing a package
  or building an image. Run it once by hand, then rebuild the initramfs.
