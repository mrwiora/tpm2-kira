# Installing tpm2-kira

## Requirements

**Hardware:**
- TPM 2.0 (discrete or firmware TPM)

**Software:**
- Linux with TPM 2.0 kernel support (`/dev/tpmrm0`; `/dev/tpm0` is used only when
  the kernel provides no resource manager)
- Go ≥ 1.26.0 (build only; the `go` line of go.mod is the minimum). The
  release builds and the acceptance runs use the Go release go.dev names as
  current, asked at build time, so no release ships a standard library with
  known vulnerabilities. Debian 13 ships 1.24: install the current Go from
  https://go.dev/dl into `/usr/local/go` and put `/usr/local/go/bin` first
  in `PATH`.

**Supported architectures:** x86_64, aarch64 (the Arch package is x86_64 only)

## Installation

```bash
sudo pacman -S base-devel go git    # Arch
# or
sudo apt install build-essential git    # Debian/Ubuntu, with Go from go.dev (Requirements)

git clone --recurse-submodules https://github.com/tpm2-trust/tpm2-kira.git
cd tpm2-kira
make build
sudo make install                   # tpm2-kira and tpm2-kira-boot, in /usr/local/bin
sudo make install-mkinitcpio        # Arch: the hooks, in /etc/initcpio
sudo make install-initramfs-tools   # Debian/Ubuntu: the hook and boot scripts, in /etc/initramfs-tools
```

There are two binaries: `tpm2-kira`, everything on the installed system,
and `tpm2-kira-boot`, what the boot image carries (the code screen and the
parts the image's plan names, the close, the keyscript) and nothing of the
administration. Built from source or from a package, both systems get the
same: the hooks find the binaries in `/usr/bin` or `/usr/local/bin`, the
image has `/usr/bin/tpm2-kira-boot` alone, and `tpm2-kira control` does the
rest the same way on both.

### Arch Linux (AUR)

```bash
paru -S tpm2-kira      # or your preferred AUR helper
```

The PKGBUILD in [packaging/aur/](../packaging/aur/) is a template: it builds a
checksummed release tarball, and its `pkgver` is filled in at publish time, so
it cannot be built straight from a clone. See
[packaging/aur/README.md](../packaging/aur/README.md) to build one locally.

After installing, run `sudo tpm2-kira control`, or by hand:

```bash
sudo tpm2-kira setup
sudo tpm2-kira slot add --totp    # the selection this boot evaluates to, see SLOT.md
sudo mkinitcpio -P
```

### Debian / Ubuntu (.deb)

```bash
sudo apt install build-essential debhelper dpkg-dev    # and Go from go.dev (Requirements)
make deb
sudo apt install ../tpm2-kira_*_amd64.deb
```

`make deb` derives the package version from `git describe`, so an untagged
checkout produces something like `0.2.3+9.g9d32210`.

The package installs the two binaries, the initramfs-tools hook and boot scripts, and
rebuilds the initramfs. It does **not** run `setup` or `slot add`, because sealing
generates a new TOTP secret and prints a QR code you need to scan:

```bash
sudo tpm2-kira setup
sudo tpm2-kira slot add --totp    # on GRUB: slot 0 0e,2e,4u,7e,8e,9e, slot 1 7e,8e,9e
sudo update-initramfs -u
```

The binaries are built statically (`CGO_ENABLED=0`), so the initramfs needs no
libraries and the package has no shared-library dependencies.

### Verify

```bash
tpm2-kira version
```

## The signing key and the first slot

`setup` makes the signing key that approves every PCR policy, and nothing else. It looks for a YubiKey first: with one plugged in it offers to take the key from a PIV slot (`--yubikey`, optionally `=SERIAL`, `--slot`, default 9a) so the private key never exists on the machine; without one, or with `--local`, it creates an ECDSA P-256 key pair at `/etc/tpm2-kira/keys/` (`seal.pub`, `seal.key`, root-only). `tpm2-kira yubikey list` shows the candidates; the trade-offs are in [PLAN-YUBIKEY.md](PLAN-YUBIKEY.md). `slot add` creates a TOTP key inside the TPM, approved for what this boot measured ([SLOT.md](SLOT.md#adding-a-slot-slot-add)); scan the QR codes it prints with your authenticator app, the fallback slot's too; the code then shows at the next boot's code screen, because a boot closed by PCR 15 computes none. A selection that leaves out the kernel, initrd and command line lets a modified initrd show a valid code, see [Choosing PCRs](SLOT.md#choosing-pcrs). `slot add` refuses to run until `setup` has created the keys (or you pass your own with `--privkey` / `--pubkey`).

The boot's side, on Arch and on Debian: [BOOT-INTEGRATION.md](BOOT-INTEGRATION.md).

## Uninstall

```bash
# Everything of tpm2-kira outside the disk first: the slots in the TPM,
# the boot settings, the SSH CA (EFI variable and ssh_ca.pub)
sudo tpm2-kira slot delete --yes

# Remove binary
sudo make uninstall

# Remove mkinitcpio hooks (if installed)
sudo make uninstall-mkinitcpio
sudo mkinitcpio -P

# Optionally remove signing keys
sudo rm -rf /etc/tpm2-kira/keys
```

On Arch:
```bash
sudo tpm2-kira slot delete --yes
sudo pacman -R tpm2-kira
```

On Debian:
```bash
sudo tpm2-kira slot delete --yes
sudo apt remove tpm2-kira
```

Purging the Debian package deliberately leaves `/etc/tpm2-kira/keys` in place:
the signing key is the only way to approve new PCR values for a key that may
still be sealed in the TPM. Delete the slot first, then the directory.
