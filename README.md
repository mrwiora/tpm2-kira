# tpm2-kira (Known Integrity Recognition Agent)

A TPM2 based tool to recognize modifications on your system !before! entering passphrases to unlock your disk.
Time-Based One-Time-Password Tokens calculated on Secrets, that the TPM2 reveals only when the device is in an unmodified state.

<p align="center">
  <img src=".github/ssh.gif" alt="tpm2-kira demo" />
</p>

**Successor/Extension to [tpm2-totp](https://github.com/tpm2-software/tpm2-totp).**

> [!CAUTION]
> tpm2-kira is currently in **alpha**. Expect breaking changes between versions.

## How It Works

tpm2-kira generates a TOTP secret and seals it inside TPM NVRAM, protected by a **PolicyOR** with two branches:

| Branch | When it works | Purpose |
|--------|--------------|---------|
| **PCR** | Boot measurements match the values recorded at seal time | Normal daily use — no keys or passwords needed |
| **PolicySigned** | You have the signing private key | Recovery after firmware/kernel/bootloader updates change PCR values |

On every boot, tpm2-kira asks the TPM to unseal the secret. If PCRs still match, you get a valid TOTP code. Compare it with the code in your authenticator app — if they match, your boot chain is intact.

When a system update changes PCR values (kernel update, initramfs rebuild, Secure Boot key rotation, etc.), the PCR branch fails. You use `reseal` with your signing key to re-seal the secret against the new PCR values.

For more details on the cryptographic design, see [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md).

## Requirements

**Hardware:**
- TPM 2.0 (discrete or firmware TPM)

**Software:**
- Linux with TPM 2.0 kernel support (`/dev/tpm0` or `/dev/tpmrm0`)
- Go ≥ 1.25 (build only)

**Supported architectures:** x86_64, aarch64

## Quick Start

```bash
# Build
git clone https://github.com/mrwiora/tpm2-kira.git
cd tpm2-kira
make build

# Install
sudo make install

# First-time setup: generates signing keys + seals a TOTP secret (PCRs 0,7)
sudo tpm2-kira setup

# Show the current TOTP code
tpm2-kira reveal
```

`setup` creates an ECDSA P-256 key pair at `/var/lib/tpm2-kira/keys/` and seals a TOTP secret bound to PCRs 0 and 7. Scan the QR code it prints with your authenticator app.

## Installation

### Build from Source

```bash
sudo pacman -S base-devel go git    # Arch
# or
sudo apt install build-essential golang git    # Debian/Ubuntu

git clone https://github.com/mrwiora/tpm2-kira.git
cd tpm2-kira
make build
sudo make install
```

### Arch Linux (AUR)

```bash
cd packaging/aur
makepkg -si
```

Or use your preferred AUR helper.

### Verify

```bash
tpm2-kira version
```

## Commands

If called without a command, tpm2-kira defaults to `reveal`.

| Command | Description |
|---------|-------------|
| `setup` | One-time initial setup: generate signing keys + seal a secret (PCRs 0,7) |
| `seal` | Generate and seal a new TOTP secret with custom PCR selection |
| `reseal` | Re-seal the existing secret against current PCR values |
| `reveal` | Show the current TOTP code (colored output) |
| `reveal-plain` | Show the current TOTP code (plain text, for scripts) |
| `run` | Continuously display TOTP codes (useful during boot) |
| `info` | Display metadata about the sealed secret (`--json` for machine-readable output) |
| `nvram list` | List NVRAM indices |
| `nvram status` | Show NVRAM index status |
| `nvram delete` | Delete sealed data from NVRAM |
| `pcrtips` | PCR reference guide — what each register measures |
| `version` | Print version |

## Global Options

```
--tpm PATH       TPM device path (default: /dev/tpm0)
--nvram INDEX    NVRAM slot: 0-15 maps to 0x01803010-0x0180301F,
                 or specify a full hex index like 0x01803010.
                 When omitted, commands auto-discover populated slots.
--debug          Verbose output
```

## Sealing Secrets

### Basic seal

```bash
# Uses default PCRs 0,2,7 read from TPM registers
tpm2-kira seal
```

### Custom PCRs

Each PCR index can have a **source suffix** that controls where the value comes from:

| Suffix | Source | Example | Notes |
|--------|--------|---------|-------|
| *(none)* or `r` | TPM register | `0`, `7r` | Reads current live value from the TPM |
| `e` | Eventlog | `0e`, `7e` | Calculates from `/sys/kernel/security/tpm0/binary_bios_measurements` (PCRs 0–12) |
| `u[:PATH]` | Unified kernel image | `11u`, `11u:/boot/EFI/Linux/arch-linux.efi` | Replays systemd-stub's section measurements natively (PCR 11 only) |

You can mix sources freely:

```bash
# PCR 0 and 7 from eventlog, PCR 2 from register
tpm2-kira seal --pcrs "0e,2,7e"

# Add a UKI-computed PCR 11
tpm2-kira seal --pcrs "0e,2e,7e,11u"
```

The `u` source parses the unified kernel image directly and reproduces what
systemd-stub measures: for each section, `H(name + NUL)` followed by
`H(section bytes)`, then the `enter-initrd` boot phase. It needs neither
`objcopy` nor `systemd-measure`, and nothing is executed as a subprocess.

### The measure point

tpm2-kira reads PCRs in the initrd, *after* systemd has already extended some
of them. `systemd-pcrosseparator.service` extends `os-separator` into PCRs
0–7, 9, 12, 13, 14, and `systemd-pcrphase-initrd.service` extends
`enter-initrd` into PCR 11 — both before `cryptsetup-pre.target`.

Eventlog-derived values describe the *end of firmware*, so tpm2-kira adds those
extends to reach the measure point. `--measure-point` controls this:

| Value | Behaviour |
|-------|-----------|
| `auto` (default) | Probes stable PCRs against the TPM to decide, and refuses if the result is ambiguous |
| `on` | Always apply |
| `off` | Reconstruct end-of-firmware values only |

The mkinitcpio install hook inspects the image being built and passes the right
value to `reseal`, which is what makes the first rebuild after these units
appear behave correctly.

### SHA-1 fallback

If your firmware doesn't provide SHA-256 eventlog digests:

```bash
tpm2-kira seal --sha1 --pcrs "0e,2e,7e"
```

### Custom signing keys

By default, `setup` generates keys at `/var/lib/tpm2-kira/keys/`. You can supply your own (RSA-2048, ECDSA P-256, or ECDSA P-384):

```bash
tpm2-kira seal --pubkey /path/to/key.pub --privkey /path/to/key.pem
```

Both key paths are stored in the sealed blob so that `reseal` can find them automatically.

### Multiple slots

tpm2-kira supports up to 16 NVRAM slots (0–15). Useful if you need separate secrets for different purposes:

```bash
tpm2-kira seal --nvram 0
tpm2-kira seal --nvram 1 --pcrs "0e,2e,7e"

tpm2-kira reveal --nvram 0
tpm2-kira reveal --nvram 1
```

## Resealing After Updates

When PCR values change (kernel update, initramfs rebuild, firmware update), the PCR branch will fail and `reveal` won't produce a valid code. Reseal to bind the secret to the new values:

```bash
# Auto-discovers the signing key from the stored blob metadata
tpm2-kira reseal

# Or specify the key explicitly
tpm2-kira reseal --privkey /var/lib/tpm2-kira/keys/seal.key
```

You can also change the PCR selection during reseal:

```bash
tpm2-kira reseal --pcrs "0e,2,4,7e"
```

## Inspecting Sealed Data

```bash
tpm2-kira info
tpm2-kira info --nvram 0
tpm2-kira info --json          # machine-readable
```

## Deleting Sealed Data

```bash
tpm2-kira nvram delete              # deletes all populated slots
tpm2-kira nvram delete --nvram 0    # deletes a specific slot
```

## Early Boot Integration (Arch Linux / mkinitcpio)

tpm2-kira can display TOTP codes during early boot — before you enter your disk encryption passphrase. This way you can verify the system hasn't been tampered with before typing your LUKS password.

### Install the hooks

```bash
sudo make install-mkinitcpio
```

This installs:
- `sd-tpm2-kira` — mkinitcpio install hook (systemd-based initramfs)
- A **post-generation hook** that automatically runs `tpm2-kira reseal` after every initramfs rebuild

### Configure mkinitcpio

Edit `/etc/mkinitcpio.conf` and add the hook **before** your encrypt hook:

```bash
# Systemd-based initramfs (recommended):
HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)
```

Then rebuild:

```bash
sudo mkinitcpio -P
```

The post-generation hook will automatically reseal so the next boot matches.

### How it works at boot

A systemd service (`tpm2-kira.service`) starts before the disk unlock prompt and runs `tpm2-kira run`, which continuously displays TOTP codes. Compare what's on screen with your authenticator app. If they match, your boot chain is clean — go ahead and type your LUKS passphrase.

See [mkinitcpio/mkinitcpio.conf.example](mkinitcpio/mkinitcpio.conf.example) for more HOOKS configurations (LVM, multiple encrypted devices, etc.).

## Eventlog PCR Calculator

The included Python script `calculate.py` can independently calculate PCR values from a TPM eventlog YAML file. Useful for debugging PCR mismatches:

```bash
# Calculate all PCRs from an eventlog
python3 calculate.py /path/to/eventlog.yaml

# Calculate a specific PCR
python3 calculate.py /path/to/eventlog.yaml 7
```

Requires PyYAML (`pip install pyyaml`).

## Testing

```bash
# Unit tests (no TPM required)
make test-unit

# Integration tests (requires swtpm + socat)
# Install: sudo apt install swtpm swtpm-tools socat
#      or: sudo pacman -S swtpm socat
make test-integration

# Everything
make test-all
```

## Troubleshooting

**TPM device not found:**
```bash
ls -la /dev/tpm*
sudo dmesg | grep -i tpm
```
Ensure TPM 2.0 is enabled in your BIOS/UEFI settings.

**Permission denied on `/dev/tpm0`:**
```bash
# Check current permissions
ls -la /dev/tpm0

# Your user needs access — either run as root or add a udev rule
```

**TOTP code doesn't match after update:**
```bash
tpm2-kira reseal
```
If reseal also fails, check `tpm2-kira info` to see which PCRs changed and verify you have the correct signing key available.

**Debug output:**
```bash
tpm2-kira --debug reveal
```

**Check current PCR values vs. sealed values:**
```bash
tpm2-kira info            # shows what was sealed
tpm2-kira pcrtips         # explains what each PCR measures
```

## Uninstall

```bash
# Remove sealed data first
tpm2-kira nvram delete

# Remove binary
sudo make uninstall

# Remove mkinitcpio hooks (if installed)
sudo make uninstall-mkinitcpio
sudo mkinitcpio -P

# Optionally remove signing keys
sudo rm -rf /var/lib/tpm2-kira
```

On Arch:
```bash
tpm2-kira nvram delete
sudo pacman -R tpm2-kira
```

## Project Structure

```
├── main.go                  # CLI entrypoint and command routing
├── cmd/                     # Command implementations
│   ├── seal.go              # Seal TOTP secret into TPM
│   ├── reseal.go            # Re-seal with new PCR values
│   ├── setup.go             # First-time setup (keygen + seal)
│   ├── info.go              # Inspect sealed blob metadata
│   ├── scan.go              # Multi-slot NVRAM scanning
│   ├── blob.go              # Sealed blob serialization format
│   ├── policy_or.go         # PolicyOR digest computation
│   ├── eventlog_utils.go    # TPM eventlog parsing
│   ├── predict_utils.go     # External PCR prediction
│   ├── totp_utils.go        # TOTP generation and display
│   ├── tpm_utils.go         # Low-level TPM operations
│   ├── pcrtips.go           # PCR reference information
│   └── constants.go         # Default paths and constants
├── calculate.py             # Standalone eventlog PCR calculator
├── mkinitcpio/              # Early boot hooks for Arch Linux
│   ├── install/sd-tpm2-kira # mkinitcpio install hook
│   ├── post/sd-tpm2-kira    # Post-generation reseal hook
│   └── mkinitcpio.conf.example
├── systemd/system/          # systemd service for boot-time TOTP display
├── packaging/aur/           # Arch Linux PKGBUILD
└── Makefile
```

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) for an in-depth description of the cryptographic design, threat model, and trust boundaries.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
