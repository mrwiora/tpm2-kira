# Project structure

Where things are in the repository, and how the tests are run.

## Project Structure

```
├── main.go                  # CLI entrypoint and command routing
├── attest/                  # Remote attestation core: protocol, Noise, Verify(); no device access
│   └── attesttest/          # Software TPM, in-memory pipe and simulated phone for tests
├── transport/
│   ├── frame/               # Record fragmentation for BLE (shared with the phone)
│   └── ble/                 # Pure-Go BLE peripheral over an HCI user channel
├── mobile/
│   ├── kiracore/            # gomobile binding: the phone's verifier core
│   └── kiratest/            # gomobile binding: a simulated machine for app tests
├── cmd/                     # Command implementations
│   ├── control.go           # The guided way: analysis, the protections, the step to run
│   │                        #   (forms by huh v2, charm.land, the one TUI dependency)
│   ├── status.go            # The overview: slots, phone, unlock mode, keyslots, notes
│   ├── luks.go, route.go    # LUKS keyslots and tokens; where the initrd takes the key from
│   ├── default_pcrs.go      # What 'seal' seals to by default, and the fallback slot
│   ├── seal.go              # Create the TOTP key in the TPM and approve PCR values
│   ├── reseal.go            # Approve new PCR values, revoke older approvals
│   ├── setup.go             # First-time setup (keygen)
│   ├── info.go              # Inspect sealed blob metadata
│   ├── scan.go              # Multi-slot NVRAM scanning
│   ├── blob.go              # Sealed blob serialization format
│   ├── totpkey.go           # TOTP key object, PolicyAuthorize, generation, cap
│   ├── signingkey.go        # Signing key loading, PolicySigned for NV writes
│   ├── keyfile.go           # Key file checks (owner, mode, symlinks)
│   ├── untrusted.go         # Printing strings from unverified blobs
│   ├── eventlog_utils.go    # TPM eventlog parsing
│   ├── measurepoint.go      # Userspace extends before tpm2-kira reads PCRs
│   ├── ukipredict.go        # Native PCR 11 computation from a UKI
│   ├── pcr.go               # PCR spec parsing, reading and comparison
│   ├── pcrwarn.go           # Warnings for PCR selections that attest little
│   ├── attest.go            # attest enrol/gate/status/quote/verify/unenrol
│   ├── attest_blob.go       # A slot's phone enrolment (AK, pinned phones), a section of its blob
│   ├── attest_tpm.go        # AK/EK, TPM2_Quote, ActivateCredential
│   ├── nvram.go             # NVRAM read/write/scan operations
│   ├── totp_utils.go        # Code truncation, QR code and display
│   ├── tpm_utils.go         # Low-level TPM operations
│   ├── pcrtips.go           # PCR reference information
│   └── constants.go         # Default paths and constants
├── tools/
│   ├── acceptance.py         # The acceptance run on a machine: package, install, checks, reboot, report
│   ├── pcrtool.py            # PCR replay and full-chain diagnosis
│   ├── tpm2-pcr11predict     # Independent cross-check of the built-in PCR 11 computation
│   ├── vulncheck.py          # govulncheck that fails on what the code calls into, minus vulncheck-ignore
│   └── vulncheck-ignore      # Records the Go vulnerability database has wrong, with the proof
├── docs/
│   ├── PROTOCOL-BLE.md           # Phone <-> machine protocol: the interface definition
│   ├── PLAN-*.md                 # Designs: remote attestation, BLE, remote unlocking, factor release, the test host (PLAN-BLE-TESTING)
│   ├── mobile/                   # Agent prompts for the Android and iOS apps
│   ├── PLATFORM-OBSERVATIONS.md  # Measured facts about Arch and Debian boots
│   ├── pentest1/, pentest2/      # Security review findings and mitigations
│   └── *.issue                   # Write-ups of specific bugs
├── initramfs/               # Everything that goes into, or builds, an initramfs
│   ├── common/control.conf          # The one configuration file: unlock mode, radio, YubiKey PIN
│   ├── systemd/tpm2-kira.service   # Shows the code in systemd-based images
│   ├── systemd/tpm2-kira-cap.service  # Runs 'cap' when leaving the initrd
│   ├── systemd/tpm2-kira-attest.service  # Lazy Bluetooth attestation gate
│   ├── mkinitcpio/                 # Arch
│   │   ├── install/sd-tpm2-kira    # Build hook: puts the binary in the image
│   │   ├── post/sd-tpm2-kira       # Reseal after the image is written
│   │   └── mkinitcpio.conf.example
│   └── initramfs-tools/            # Debian
│       ├── hooks/tpm2-kira         # Build hook: copies the static binary
│       ├── scripts/init-premount/tpm2-kira  # Shows the code before unlock
│       ├── scripts/init-bottom/tpm2-kira    # Stops it and caps before switching root
│       ├── post-update.d/tpm2-kira          # Reseal reminder
│       └── initramfs.conf          # Display mode (run / once)
├── debian/                  # Debian package definition (must sit at the root)
├── packaging/
│   ├── aur/                 # Arch Linux PKGBUILD
│   └── deb-version.sh       # git describe -> a Debian-valid version
└── Makefile
```

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

# The acceptance run on a machine of one distribution: builds the package
# of the checked-out commit on the target, installs it, checks the
# installed system and its initramfs, reboots when you say so, asks what
# the console showed, checks the booted system and its journal, and
# writes a report with every log into one directory.
tools/acceptance.py --distro arch   --host 172.17.2.198 --user pix --ask-password
tools/acceptance.py --distro debian --host 172.17.2.196 --user pix --password-file ~/.vm-pw --luks /dev/vda3

# Known vulnerabilities the code calls into (what the Vulnerability Scan
# workflow runs: the source on every push, the release binary daily)
tools/vulncheck.py ./...
```

The machines this run should have - installed by a script, in a frozen
state, with a serial console the harness reads and the phone in the
Android emulator - are the plan in `docs/PLAN-BLE-TESTING.md`.
