# tpm2-kira (Known Integrity Recognition Agent)

<p align="center">
  <img src=".github/tpm2-kira_300x300.png" alt="tpm2-kira logo" />
</p>

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
- Go ≥ 1.24 (build only)

**Supported architectures:** x86_64, aarch64

## Quick Start

```bash
# Build
git clone https://github.com/mrwiora/tpm2-kira.git
cd tpm2-kira
make build

# Install
sudo make install

# Create the signing key (one step)
sudo tpm2-kira setup

# Seal a TOTP secret against PCRs 0 and 7 (the other step)
sudo tpm2-kira seal --pcrs "0,7"

# Show the current TOTP code
tpm2-kira reveal
```

`setup` creates an ECDSA P-256 key pair at `/var/lib/tpm2-kira/keys/` and stops
there. `seal` generates the TOTP secret, binds it to the PCRs you name, and
prints a QR code to scan with your authenticator app.

The two are deliberately separate. Creating a key is cheap and repeatable;
sealing writes to TPM NVRAM and mints a secret you have to enrol, and it is the
step where the PCR choice is made. Keeping them apart means you can re-run
either without having to think about the other.

If a YubiKey is plugged in, `setup` notices and offers to put the signing key on
it instead — a key file remains the default, so pressing Enter keeps the
behaviour above. See [Signing key on a YubiKey](#signing-key-on-a-yubikey).

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
paru -S tpm2-kira      # or your preferred AUR helper
```

The PKGBUILD in [packaging/aur/](packaging/aur/) is a template: it builds a
checksummed release tarball, and its `pkgver` is filled in at publish time, so
it cannot be built straight from a clone. See
[packaging/aur/README.md](packaging/aur/README.md) to build one locally.

After installing, create the key, seal a secret, and rebuild the initramfs:

```bash
sudo tpm2-kira setup
sudo tpm2-kira seal --pcrs "0,7"
sudo mkinitcpio -P
```

### Debian / Ubuntu (.deb)

```bash
sudo apt install build-essential debhelper dpkg-dev golang-go
make deb
sudo apt install ../tpm2-kira_*_amd64.deb
```

`make deb` derives the package version from `git describe`, so an untagged
checkout produces something like `0.2.3+9.g9d32210`.

The package installs the binary, the initramfs-tools hook and boot scripts, and
rebuilds the initramfs. It runs neither `setup` nor `seal`: sealing generates a
new TOTP secret and prints a QR code you need to scan, which must not happen as
a side effect of installing a package.

```bash
sudo tpm2-kira setup
sudo tpm2-kira seal --pcrs "0,7"
sudo update-initramfs -u
```

The binary is built statically (`CGO_ENABLED=0`), so the initramfs needs no
libraries and the package has no shared-library dependencies.

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
| `nvram restore` | Write back a blob that a failed NVRAM write left on disk |
| `yubikey list` | Show connected YubiKeys, their PIV slots and policies |
| `yubikey adopt` | Register an existing PIV slot key and cache its public key |
| `yubikey status` | Check whether the enrolled token is present |
| `yubikey export-pubkey` | Write a slot's public key to a PEM file |
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

Environment:

```
TPM2_KIRA_PIN    PIN for a signing key held in a YubiKey PIV slot.
                 Only read when the key reference names a token.
```

## Sealing Secrets

### Basic seal

Run `seal` with no `--pcrs` from a terminal and it looks at the machine first,
then suggests a selection to match:

```bash
sudo tpm2-kira seal
```

```
What was found:
  Firmware: UEFI
  Secure Boot: enabled
  Event log: present, with SHA-256 digests
  Unified kernel image: /boot/EFI/Linux/arch-linux.efi

Suggested NVRAM slot: #0 (0x01803010), which is free

Suggested selection: 0,7
  PCR 0  firmware code — changes when you update the firmware
  PCR 7  Secure Boot policy — changes if the keys are rotated or Secure Boot is turned off

Also possible here:
  11u  the unified kernel image. The strongest measurement of the exact kernel that
       will run, but it changes on every kernel update, so each one needs a reseal.
  ...

Worth knowing:
  - PCR 0 on its own would identify a firmware build, not this machine — every device
    running the same firmware version holds the same value. ...

  [Enter]      seal slot #0 (0x01803010) with PCRs 0,7
  <selection>  type your own, for example "0,2,7" or "0e,7e,11u"
  [?]          show the full PCR reference and stop
  [q]          quit without sealing
```

The advice tracks the machine rather than being boilerplate. With Secure Boot
enabled, PCRs 0 and 7 are enough and need no reseal after a kernel update. With
Secure Boot **off**, nothing verifies which kernel runs, so the suggestion adds
whatever this system measures the boot components with — `11u` for a unified
kernel image, `8,9` for GRUB, `4` otherwise — and says what that costs in
resealing. A free NVRAM slot is suggested, and slots already in use are listed so
an enrolled secret is not overwritten by accident.

**Passing `--pcrs` skips all of it** and seals exactly what you asked for:

```bash
tpm2-kira seal --pcrs "0,2,7"
```

So does running without a terminal — a package hook or script gets the
documented default (`0,2,7`) silently, with no prompt to hang on.

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

`seal` checks that computation against the current boot's firmware event log,
measurement by measurement. What happens on a mismatch depends on what kind it
is:

| Mismatch | Meaning | Result |
|---|---|---|
| Section set or order differs | tpm2-kira models systemd-stub wrongly | **fails** |
| Section content differs, image rebuilt after boot | cannot be checked yet | warns, proceeds |
| Section content differs, image unchanged since boot | the computation is wrong | **fails** |

The middle case is the normal one right after a kernel or initramfs update: the
image on disk is not the one that booted, so there is nothing to verify against.
PCR 11 becomes correct once you boot that image. Pass `--verify-uki=false` to
skip the check entirely.

### Warnings about weak selections

`seal` and `reseal` report selections that attest less than they appear to.
These are advisory — the secret is still sealed.

**PCR 0 on its own** identifies a firmware *build*, not a machine. It measures
firmware code only (configuration lives in PCR 1), so every device running the
same firmware version holds the same value and an attacker can reproduce it on
their own hardware.

**PCR 7 while Secure Boot is off or the platform is in Setup Mode.** PCR 7
records the Secure Boot state and policy. With Secure Boot disabled it faithfully
records "disabled" and nothing verifies which bootloader or kernel runs, so a
matching PCR 7 does not mean the boot chain was checked. In Setup Mode the keys
can be replaced without physical presence, so the policy it attests is one any
root user can rewrite. The state is read from
`/sys/firmware/efi/efivars`; if that is unavailable, tpm2-kira says so rather
than staying silent.

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

### TPMs whose event log has no SHA-256 digests

Some firmware writes a SHA-1-only event log even when the TPM has a SHA-256 PCR
bank. The `e` source then has nothing to replay in the selected bank, and
tpm2-kira refuses rather than sealing the resulting all-zero value:

```
Error: PCR 0 has no SHA-256 digests in the event log ... (digests present for this PCR: SHA-1).
Replaying it would yield an all-zero value that this system will never produce.
```

Two ways forward:

```bash
# Preferred: keep SHA-256, drop eventlog reconstruction for these PCRs.
# PCRs 0-7 do not change between the measure point and seal time, so the
# register source produces exactly the same value.
tpm2-kira seal --pcrs "0,7"

# Or reconstruct from the SHA-1 log. Requires a SHA-1 PCR bank on the TPM,
# and binds the policy to SHA-1 PCR values.
tpm2-kira seal --sha1 --pcrs "0e,7e"
```

The SHA-256 value cannot be derived from a SHA-1 log — different banks hold
different values, and several event types have digests that are not a plain
hash of the logged payload, so re-hashing the payloads would be wrong.

### Custom signing keys

By default, `setup` generates keys at `/var/lib/tpm2-kira/keys/`. You can supply
your own — **RSA-2048, ECDSA P-256 or ECDSA P-384**:

```bash
tpm2-kira seal --pubkey /path/to/key.pub --privkey /path/to/key.pem
```

`--pubkey` accepts a raw public key or an X.509 certificate. Both paths are
stored in the sealed blob, so later `reseal` calls need no flags.

**Keep the private key mode 0400, owned by root.** That is what `setup` writes,
and whenever the key is opened for signing — `seal`, `reseal`, `nvram restore` —
tpm2-kira checks it and reports anything looser:

```
WARNING: the signing key /var/lib/tpm2-kira/keys/seal.key is mode 0644.
  Other accounts on this machine can read it. The signing key is the recovery
  master key: whoever holds it can unseal the secret whatever the PCRs say, so
  its only protection on disk is this mode.
      sudo chmod 400 /var/lib/tpm2-kira/keys/seal.key
```

It is a warning rather than a refusal: a loose key still works, because being
unable to reseal at the moment you need to would be worse. A key that is merely
owner-writable (0600) gets a one-line note instead, since that exposes it to
nobody.

**RSA-4096 does not work.** The PolicySigned branch needs the public key loaded
into the TPM with `TPM2_LoadExternal`, and TPMs reject 4096-bit RSA there — so
does swtpm. tpm2-kira fails at seal time with a hint rather than leaving you to
discover it during a recovery. Check a key before committing to it:

```bash
openssl rsa -in key.pem -noout -text | head -1     # "Private-Key: (2048 bit)"
```

### Sharing the signing key with sbctl (Secure Boot)

The same key that signs your boot components can authorise TOTP resealing, so
there is no second secret to manage. It needs one preparation step, because
**sbctl's own keys cannot be used**: `sbctl create-keys` generates RSA-4096, and
sbctl offers no option to change that.

Check what you have:

```bash
sudo openssl rsa -in /var/lib/sbctl/keys/db/db.key -noout -text | head -1
```

If it says 4096, either keep a dedicated tpm2-kira key (the default, and the
simplest choice) or create a Secure Boot db key that both tools can use. RSA-2048
is the right size: it is what UEFI firmware expects for a db entry, and it is
universally supported by TPMs.

```bash
# Generate an RSA-2048 db key and self-signed certificate.
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout db.key -out db.pem -subj "/CN=my Secure Boot db/"

# Hand it to sbctl, which will use it to sign boot components.
sudo sbctl import-keys --db-key db.key --db-cert db.pem
# ...then enroll and sign as usual: sbctl enroll-keys, sbctl sign-all

# Point tpm2-kira at the same key.
sudo tpm2-kira seal --pcrs "0,7" \
    --pubkey /var/lib/sbctl/keys/db/db.pem \
    --privkey /var/lib/sbctl/keys/db/db.key
```

Two consequences worth knowing before you choose this:

**One key now gates two things.** Compromise or loss costs both Secure Boot
signing and TOTP recovery. That is the trade you are making for having one
secret instead of two.

**Rotating Secure Boot keys has a mandatory order.** Enrolling new keys moves
PCR 7 *and* invalidates the PolicySigned branch, which is bound to the old key.
Do both before resealing and nothing can unseal the blob. Reseal onto the new
key while PCR 7 has not moved yet, so the PCR branch still opens on its own:

```
1. create the new key pair, and sbctl import-keys it
2. sudo tpm2-kira reseal --pubkey <new db.pem> --privkey <new db.key>
3. sudo sbctl enroll-keys        # PCR 7 moves now
4. reboot, then sudo tpm2-kira reseal
```

Step 2 is the one that must not be skipped: it is the only moment when the blob
can be re-pointed at the new key without needing the old one. Attempting it
later fails cleanly — reseal checks that the key it was given matches the key
being sealed against — but the blob is then only recoverable with the old key.

A YubiKey avoids the size problem entirely, since an ECC P-256 slot key is
universally supported: see [docs/YUBIKEY.md](docs/YUBIKEY.md).

### Signing key on a YubiKey

The signing key can live in a YubiKey PIV slot instead of a PEM file, so it is
never readable and using it needs the physical token plus a PIN. A key file on
disk stays the default; this is opt-in.

The token is needed only for `seal`, `setup` and `reseal`. `reveal` and `run` —
everything that happens at boot — never touch the signing key, so no token is
needed to see a TOTP code.

```bash
sudo pacman -S pcsclite yubikey-manager     # or: apt install pcscd yubikey-manager
sudo systemctl enable --now pcscd
```

On pcsc-lite 2.x (Arch, Debian trixie) `pcscd` asks polkit before accepting a
client, and the shipped policy allows only active login sessions — with no
exemption for root. Interactive `sudo` is fine; a systemd unit, a timer or cron
is not. That needs a one-file polkit rule, and an unattended reseal needs the
PIN somewhere the hook can read it. Both are covered in
[docs/YUBIKEY.md](docs/YUBIKEY.md#pcsc-lite-2x-asks-polkit-first): on Arch the
PIN goes in a 0600 drop-in under `/etc/mkinitcpio.conf.d/`, which mkinitcpio
sources but never copies into the image. **Not** in Debian's `initramfs.conf`,
which *is* copied into the image and so lands on unencrypted `/boot`.

**Prepare the key.** tpm2-kira never writes to a token: it reads a slot's public
key, verifies the PIN, and asks the card to sign. Creating the key is `ykman`'s
job, which keeps tpm2-kira from being able to damage a key the slot may share
with something else.

```bash
# Generate an ECC P-256 key inside the token, in slot 9a.
#   ONCE  — one PIN check covers a whole reseal
#   NEVER — no touch required; the reseal after an initramfs rebuild is unattended
ykman piv keys generate --algorithm ECCP256 \
    --pin-policy ONCE --touch-policy NEVER 9a /tmp/seal.pub

# PIV exposes a public key through the slot certificate, so give the slot one.
ykman piv certificates generate --subject "CN=tpm2-kira" 9a /tmp/seal.pub
rm /tmp/seal.pub

ykman piv access change-pin                  # the factory default is 123456
```

**Then just run setup.** On a terminal it looks for connected tokens, lists the
keys it finds, and offers them — a key file stays the default, so pressing Enter
gives you the behaviour from [Quick Start](#quick-start):

```
Looking for a hardware token that could hold the signing key...

The signing key authorises resealing after a firmware or kernel update.
It is only needed then — never at boot — so it can live on a token that
you unplug the rest of the time.

Found these keys on connected tokens:
  1) YubiKey 12345678, slot 9a (PIV Authentication) — ECDSA-P-256
       PIN once per session, touch never

Where should the signing key live?
  [Enter]  a key file at /var/lib/tpm2-kira/keys/seal.key  (default)
  [1]      the token slot above

Choice [Enter]:
```

Choosing the slot validates it, checks your TPM can load the key for
PolicySigned, and caches the public key so later commands work with the token
unplugged — no separate `adopt` step. Only the public key is written to disk.

setup stops there and prints the `seal` command to run next, with the key
reference already filled in. It needs no PIN, because reading a public key from
a slot does not require one; sealing does.

If a token is connected but none of its slots holds a key, setup prints the
`ykman` commands above and lets you stop there to run them; nothing is created,
so `setup` can simply be run again.

Two flags skip the question, for scripts and for anyone who already knows:

```bash
sudo tpm2-kira setup --yubikey                  # first token found
sudo tpm2-kira setup --yubikey 'yubikey:slot=9c'
sudo tpm2-kira setup --local                    # a key file, no questions
```

Setup never asks when it is not run from a terminal — a package hook gets the
key-file default silently, exactly as before.

**Adopting a slot for an existing installation.** `setup` declines once
`/var/lib/tpm2-kira/keys` exists, so to move an already-configured system onto a
token, register the slot and reseal onto it:

```bash
sudo tpm2-kira yubikey adopt --key 'yubikey:slot=9a'

export TPM2_KIRA_PIN=12345678
sudo -E tpm2-kira reseal \
    --privkey 'yubikey:serial=12345678;slot=9a' \
    --pubkey /var/lib/tpm2-kira/keys/seal.pub
```

`adopt` is read-only: it reports the slot's key and policies, checks the TPM can
load it, and caches the public key. Resealing preserves the TOTP secret, so your
authenticator keeps working. Once it succeeds, shred the old key file.

Already have a key in a slot — the one sbctl uses to sign your Secure Boot
components, say? Skip the generation step and `adopt` it directly. Any key the
TPM can load works (ECC P-256/P-384, RSA-2048).

**Variant: importing a key generated outside the YubiKey.** Use this when the
key already exists — an RSA-2048 Secure Boot db key that sbctl keeps using from
a file, for instance — or when you want an offline backup of the recovery key,
which generating on the token cannot give you.

```bash
# An existing key, or a fresh one made off the token:
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out seal.key
#   ...or reuse /var/lib/sbctl/keys/db/db.key, if it is RSA-2048

# Import it, setting the policies at the same time.
#   --password is needed if the key file is encrypted.
ykman piv keys import --pin-policy ONCE --touch-policy NEVER 9a seal.key

# PIV exposes a public key through the slot certificate, so the slot needs one.
# Either import a certificate you already have, verifying it matches the key...
ykman piv certificates import --verify 9a db.pem
# ...or generate a self-signed one from the public half.
openssl pkey -in seal.key -pubout -out seal.pub
ykman piv certificates generate 9a seal.pub

sudo tpm2-kira yubikey adopt --key 'yubikey:slot=9a'
```

`adopt` and `yubikey list` report `Origin: imported — this key has existed
outside the token`, so the distinction stays visible later; `ykman piv keys info
9a` says the same.

Then decide what happens to the key file, because that is now where the security
of the whole arrangement rests:

- **Shred it** (`shred -u seal.key`) if the token is meant to be the only copy.
  You get the same protection as an on-token key, minus the guarantee that it
  never existed elsewhere — whether it reached a backup, a snapshot or an
  unencrypted disk before you deleted it is a question only you can answer.
- **Keep it offline** if you would rather have a backup. Losing the token
  otherwise means losing the recovery key, and re-sealing with a new TOTP secret
  and a fresh authenticator enrolment. An imported key is the straightforward
  answer to that, at the cost of a file existing somewhere.

Generating on the token (above) is still the better default when you have no
reason to hold a copy.

**Without the token, `reseal` warns and changes nothing:**

```
tpm2-kira: SKIPPED: resealing did not happen — the signing key was not available.
  Reason:        no YubiKey with serial 12345678 is present
  Consequence:   ... at the next boot tpm2-kira will report a PCR MISMATCH
                 and show no TOTP code. That is expected here — it is not
                 evidence of tampering.
  Affected PCRs: 0 (register), 7 (register)
```

The sealed secret is left untouched. Plug the token in, reseal, and the next boot
shows a code again. `--require-key` turns the warning into a failure for scripts.

See **[docs/YUBIKEY.md](docs/YUBIKEY.md)** for slot and policy trade-offs, PIN
handling and lockout safety, the mandatory ordering when rotating a Secure Boot
key that lives in the same slot, backup strategy, and troubleshooting.

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

`--json` always emits an array of slot objects, one per populated slot, even
when there is only one. Each entry carries `slot_number`, `nvram_index` and the
blob itself, so consumers never have to branch on the slot count.

## Recovering an interrupted NVRAM write

Replacing an NVRAM index means undefining it first, and TPM 2.0 has no atomic
replace. `seal` and `reseal` do everything that can fail *before* that point —
loading the key, computing the write policy, and a test signature — so the window
is narrow. But a TPM error, or a hardware token unplugged mid-write, can still
leave the index empty.

When that happens the blob is written to `/var/lib/tpm2-kira/recovery/` and the
error says so. That file is not a consolation prize: the sealed object's private
area is wrapped by this TPM's storage primary key, which is re-derived
deterministically, so **the secret survives in those bytes**. Write them back:

```bash
sudo tpm2-kira nvram restore --nvram 0
sudo tpm2-kira nvram restore --nvram 0 --from /var/lib/tpm2-kira/recovery/slot-0x01803010-1700000000.blob
```

Restore needs the signing key, because the index's write policy is PolicySigned —
it uses the reference stored in the blob, so usually no flags are needed. Before
writing anything it verifies the blob's signature, checks the key is the one the
blob was sealed with, and loads the sealed object to confirm the blob belongs to
this TPM. It refuses to overwrite a *different* blob already in the index, since
that may be a newer secret you sealed in the meantime; `--force` overrides.

The restored policy binds the PCR values from when the blob was written, so
`reseal` afterwards if the current state has moved on.

**Power loss during the write is an accepted risk, not a covered one.** The
stash is written by the same process doing the NV write, so a machine that loses
power mid-write does not get one, and the secret is gone — `seal` again and
re-enrol your authenticator. TPM 2.0 has no atomic replace, so the window cannot
be closed; and a machine that dies partway through a root-privileged write
probably has a half-written initramfs too. The TOTP secret is among the easier
things to rebuild.

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

See [initramfs/mkinitcpio/mkinitcpio.conf.example](initramfs/mkinitcpio/mkinitcpio.conf.example) for more HOOKS configurations (LVM, multiple encrypted devices, etc.).

## Early Boot Integration (Debian / initramfs-tools)

Debian's stock initramfs has no systemd in it, so the systemd unit used on Arch
does not apply. The `.deb` installs two scripts instead:

| Path | Role |
|---|---|
| `/usr/share/initramfs-tools/hooks/tpm2-kira` | copies the binary into the image |
| `/usr/share/initramfs-tools/scripts/init-premount/tpm2-kira` | starts the display at boot |
| `/usr/share/initramfs-tools/scripts/init-bottom/tpm2-kira` | stops it before the real root takes over |
| `/etc/tpm2-kira/initramfs.conf` | display mode |

`/init` runs `init-premount` before `local-top/cryptroot` asks for the
passphrase, which is what puts the code on screen first.

### Display mode

`/etc/tpm2-kira/initramfs.conf` selects what happens at boot:

| `TPM2_KIRA_INITRAMFS_MODE` | Behaviour |
|---|---|
| `run` (default) | Keeps showing codes until the disk is unlocked |
| `once` | Prints a single code and carries on booting |

In `run` mode the display refreshes once per 30-second TOTP window, writing to
the same console as the passphrase prompt. The prompt scrolls up as codes
arrive; typing is unaffected, since the passphrase is not echoed anyway. The
`init-bottom` script stops the process before `run-init` replaces the initramfs,
so nothing is left holding it open.

Edit the file and run `sudo update-initramfs -u` to apply a change.

### Choosing PCRs on Debian

There is no UKI, so PCR 11 is empty and the `11u` and `11e` sources do not
apply. GRUB carries the equivalent measurements instead:

| PCR | Measures | Changes when |
|---|---|---|
| 0, 2 | firmware code and option ROMs | firmware update |
| 4 | the GRUB EFI binary the firmware loaded | `grub-install`, shim/GRUB package update |
| 7 | Secure Boot state and policy | key rotation, enabling/disabling Secure Boot |
| 8 | every command GRUB runs (`grub_cmd: ...`) | `update-grub`, kernel version change |
| 9 | contents of every file GRUB reads (grub.cfg, modules, kernel, initrd) + EFI LoadOptions | **every kernel or initramfs update** |

```bash
# Stable across kernel updates - a good default
tpm2-kira seal --pcrs "0e,2e,4e,7e"

# Adds kernel and initrd integrity, at the cost of the workflow below
tpm2-kira seal --pcrs "0e,2e,4e,7e,8e,9e"
```

### If you seal PCR 8 or 9: reseal *after* the reboot

Every PCR source on Debian is read from the **running** system. `reseal` binds
to the kernel and initrd you booted, so running it right after
`update-initramfs` would bind to the image you are about to leave. Only a reseal
after the next boot is correct:

```
update-initramfs / kernel update
        |
        v
    reboot  ->  no TOTP code shown        <- expected, not a compromise
        |
        v
  unlock with your passphrase as usual
        |
        v
  sudo tpm2-kira reseal                    <- re-binds to the new state
```

`/etc/initramfs/post-update.d/tpm2-kira` prints this reminder after a rebuild,
but only when the sealed policy actually contains PCR 8 or 9. It deliberately
does **not** reseal.

This is a genuine trade-off rather than an oversight. Auto-resealing on every
boot would remove the churn, but it would also turn a tampered kernel into a
trusted baseline after a single reboot: unlock once, and the new state is
sealed. Keeping a human in the loop is the point.

## Eventlog PCR Calculator

`tools/pcrtool.py` independently reconstructs PCR values, which is the first
thing to reach for when a sealed policy stops matching. It reads the live
firmware event log directly, or a `tpm2_eventlog` YAML dump:

```bash
# All PCRs from the running system's event log
sudo python3 tools/pcrtool.py replay

# A specific PCR, showing every extension step
sudo python3 tools/pcrtool.py replay --pcr 7 --verbose

# From a dump, which needs neither root nor a TPM
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > evlog.yaml
python3 tools/pcrtool.py --eventlog evlog.yaml replay

# The SHA-1 bank
sudo python3 tools/pcrtool.py --bank sha1 replay
```

The `extends` column counts how many events actually extended each PCR. A zero
there means the log carries no digests for that PCR **in the selected bank**, so
the value shown is only the reset value — the tool warns and exits non-zero
rather than letting that pass as a measurement.

Requires PyYAML (`pip install pyyaml`) and tpm2-tools.

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

# Everything, plus a real pcscd and a virtual YubiKey, in a container.
# This is the only way to exercise the token path end to end without hardware.
# BASE selects the pcsc-lite generation: 2.x by default, 1.9.x for bookworm.
make test-docker
make test-docker-all
```

`internal/virtualpiv` emulates a YubiKey PIV application and attaches to the
vsmartcard virtual reader, so `pcscd` sees an ordinary card. See
[docs/YUBIKEY.md](docs/YUBIKEY.md#testing-without-hardware).

## Troubleshooting

**TPM device not found:**
```bash
ls -la /dev/tpm*
sudo dmesg | grep -i tpm
```
Ensure TPM 2.0 is enabled in your BIOS/UEFI settings.

**Permission denied, or "needs root":**

The TPM device is root-only, deliberately: anything able to open it can ask the
TPM to unseal the secret while the PCR values still match, so the threat model
places non-root userspace outside the trust boundary
([SECURITY-BACKGROUND.md §8](docs/SECURITY-BACKGROUND.md)). **Do not loosen the
permissions on `/dev/tpm0`** — that moves the boundary rather than working around
it, and is not a supported configuration.

So every command that talks to the TPM needs `sudo`, and says so rather than
reporting a bare syscall error:

```
tpm2-kira: FAILED: /dev/tpm0 is a TPM device, which only root may open.
  That is deliberate: anything able to reach the TPM can ask it to unseal the
  secret while the PCR values still match, so the device is root-only and the
  permissions on it should not be loosened.
  Run the command with sudo:
      sudo tpm2-kira reveal ...
  Current user has UID 1000.
```

The requirement comes from the **device**, not from the verb. A software TPM
reached over a unix socket — `--tpm /path/to/swtpm.sock`, which is how the test
suite runs — belongs to whoever started it and needs no privilege at all.

`setup` needs root regardless, because it writes the signing key under
`/var/lib/tpm2-kira`. `version`, `help`, `pcrtips` and the `yubikey` subcommands
that only inspect a token through `pcscd` need nothing.

As always the exit status is 0, so judge success from the output.

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

On Debian:
```bash
tpm2-kira nvram delete
sudo apt remove tpm2-kira
```

Purging the Debian package deliberately leaves `/var/lib/tpm2-kira` in place:
the signing key is the only recovery path for a secret that may still be sealed
in the TPM. Delete the slot first, then the directory.

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
│   ├── measurepoint.go      # Userspace extends before tpm2-kira reads PCRs
│   ├── ukipredict.go        # Native PCR 11 computation from a UKI
│   ├── pcr.go               # PCR spec parsing, reading and comparison
│   ├── pcrwarn.go           # Warnings for PCR selections that attest little
│   ├── nvram.go             # NVRAM read/write/scan operations
│   ├── signer.go            # Key references and the SigningKey abstraction
│   ├── yubikey.go           # YubiKey PIV signing backend and subcommands
│   ├── pin.go               # PIN resolution for token-held keys
│   ├── totp_utils.go        # TOTP generation and display
│   ├── tpm_utils.go         # Low-level TPM operations
│   ├── pcrtips.go           # PCR reference information
│   └── constants.go         # Default paths and constants
├── test/
│   ├── integration/         # CLI tests driving the built binary (build-tagged)
│   └── docker/              # Container with swtpm, pcscd and a virtual reader
├── internal/
│   ├── pcsc/                # cgo-free pcscd client (Unix socket protocol)
│   ├── piv/                 # PIV applet: read a slot, verify a PIN, sign
│   └── virtualpiv/          # Virtual YubiKey for tests (never linked into the binary)
├── tools/
│   ├── pcrtool.py            # PCR replay and full-chain diagnosis
│   └── tpm2-pcr11predict     # Independent cross-check of the built-in PCR 11 computation
├── docs/
│   ├── YUBIKEY.md                # Signing key on a YubiKey PIV slot
│   ├── PLATFORM-OBSERVATIONS.md  # Measured facts about Arch and Debian boots
│   ├── pentest1/, pentest2/      # Security review findings and mitigations
│   └── *.issue                   # Write-ups of specific bugs
├── initramfs/               # Everything that goes into, or builds, an initramfs
│   ├── systemd/tpm2-kira.service   # Unit, pulled into systemd-based images
│   ├── mkinitcpio/                 # Arch
│   │   ├── install/sd-tpm2-kira    # Build hook: puts the binary in the image
│   │   ├── post/sd-tpm2-kira       # Reseal after the image is written
│   │   └── mkinitcpio.conf.example
│   └── initramfs-tools/            # Debian
│       ├── hooks/tpm2-kira         # Build hook: copies the static binary
│       ├── scripts/init-premount/tpm2-kira  # Shows the code before unlock
│       ├── scripts/init-bottom/tpm2-kira    # Stops it before switching root
│       ├── post-update.d/tpm2-kira          # Reseal reminder
│       └── initramfs.conf          # Display mode (run / once)
├── debian/                  # Debian package definition (must sit at the root)
├── packaging/
│   ├── aur/                 # Arch Linux PKGBUILD
│   └── deb-version.sh       # git describe -> a Debian-valid version
└── Makefile
```

## Diagnosing PCR mismatches

If the displayed PCR values differ from what was sealed, reconstruct the whole
chain before changing anything:

```bash
# Replays the firmware event log AND systemd's own measurement log,
# then explains every difference against the live registers.
sudo python3 tools/pcrtool.py verify
```

Each PCR is reported as `unchanged since firmware`, `os-separator (x1)`,
`explained: <words>`, or `UNEXPLAINED`. Anything unexplained on a sealed PCR is
a real finding.

Two things to keep in mind while reading any PCR output:

- `tpm2_eventlog`'s trailing `pcrs:` block is a **replay of the log**, not a
  read of the TPM. Comparing it against `tpm2_pcrread` is comparing a
  calculation against a measurement — and that difference is usually the answer.
- The **post-boot register is not the measure-point value** for PCRs 9, 11 and
  15. They keep being extended after the initrd, so a mismatch there is expected
  and not evidence of tampering.

See [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §5.6–5.8 for the full
reconstruction rules and constants.

## Exit status

**tpm2-kira always exits 0, including on failure.** This is deliberate: it is
meant to be chainable in a boot sequence, so a TPM or NVRAM problem must not
stop the commands after it.

```bash
tpm2-kira && cryptsetup open /dev/nvme0n1p2 cryptroot
```

Scripts must therefore judge success from the **output**, not the exit status.
Failures are printed to stderr with a fixed marker:

```
tpm2-kira: FAILED: <reason>
```

The mkinitcpio post hook does exactly this — it greps the output for the success
line rather than testing `$?`.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and [SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) for an in-depth description of the cryptographic design, threat model, and trust boundaries.

## History

[HISTORY.md](HISTORY.md) records superseded formats, removed features and the
reasoning behind them, so the source can describe what it is rather than what it
used to be. This project is in development: **no backwards compatibility is
maintained**, and blob formats, on-disk layouts and CLI flags may change without
a migration path.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
