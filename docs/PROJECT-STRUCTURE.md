# Project structure

Where things are in the repository, and how the tests are run.

## Project Structure

```
├── main.go, help.go         # tpm2-kira, the installed system's command line: routing and the help pages
├── cmd/tpm2-kira-boot/      # tpm2-kira-boot, what the boot image carries: run, cap, unlock-key, gate, ssh-child
├── attest/                  # Phone attestation core: protocol, Noise, Verify(); no device access
│   └── attesttest/          # Software TPM, in-memory pipe and simulated phone for tests
├── vaultproto/              # The contract with tpm2-kira-vault: REST messages, the release check
├── assh/                    # aSSH, a git submodule: the SSH server, the SSH CA and host keys in the TPM
├── transport/
│   ├── frame/               # Record fragmentation for BLE (shared with the phone)
│   └── ble/                 # Pure-Go BLE peripheral over an HCI user channel
├── mobile/
│   ├── kiracore/            # gomobile binding: the phone's verifier core
│   └── kiratest/            # gomobile binding: a simulated machine for app tests
├── internal/                # The packages, by layer; each knows only those below it
│   ├── tpmdev/              # Opening the TPM, the storage primary, flushing, NV reads
│   ├── measure/             # PCR specs and banks, the event log, the measure point,
│   │                        #   the UKI and GRUB predictions, PCR descriptions and warnings
│   ├── signing/             # The signing key: files, YubiKey, the PIN file
│   ├── nvslot/              # The slot: blob format, NV layout, generation, approved policy,
│   │                        #   cap, signed NV writes, the boot settings
│   ├── totp/                # Who checks the boot by its code: the TOTP key, the code screen's lines
│   ├── phonegate/           # The phone at boot: the coordinator, quotes, boot key, EK,
│   │                        #   the record check, the factor of the phone salt
│   ├── diskkey/             # The disk's key: the LUKS2 token and its recipe, the combiner,
│   │                        #   the unlock socket, the passphrase prompt, the Debian keyscript
│   ├── vaultkey/            # The disk's key from a vault at boot
│   ├── sshscreen/           # The code screen over SSH: aSSH's server, sessions, the agent,
│   │                        #   the per-boot host key; ssh-child, the unprivileged half
│   ├── imageplan/           # What a boot image carries (its parts) and what run starts
│   ├── bootrun/             # 'run': the code screen's hold, and the parts the plan names
│   │                        #   (parts.go: phone, SSH, vault, the disk's key, the console),
│   │                        #   which share what they offer on a board, not by calling each other
│   ├── journal/, screen/    # The boot's narration; the [ KIRA ] tag
│   ├── untrusted/, wipe/    # Quoting unverified strings; overwriting secrets
│   ├── unixsock/            # The boot's private sockets (the gate's, the disk key's)
│   ├── piv/, pcsc/          # The YubiKey's PIV applet over PC/SC
│   └── admin/               # Everything on the installed system: control (the guided
│                            #   way), setup, slot add/approve/delete, status, info, phone
│                            #   and phone salt enrolment, luks, vault enrolment, the boot
│                            #   plan and the image build ('initramfs plan')
├── tools/
│   ├── acceptance.py         # The acceptance run on a machine: package, install, checks, reboot, report
│   ├── vmtest.py             # The VM test: fresh encrypted VMs through install, control, reboots over SSH, the vault
│   ├── vmtest.conf.example   # Its VMs and the vault (copy to vmtest.conf, not in git)
│   ├── vmtest-vault/         # The vault of the VM test: tpm2-kira-vault with swtpm, in a container
│   ├── pcrtool.py            # PCR replay and full-chain diagnosis
│   ├── tpm2-pcr11predict     # Independent cross-check of the built-in PCR 11 computation
│   ├── vulncheck.py          # govulncheck that fails on what the code calls into, minus vulncheck-ignore
│   └── vulncheck-ignore      # Records the Go vulnerability database has wrong, with the proof
├── docs/
│   ├── ARCHITECTURE.md           # The projects, the three checks, the binaries and packages, the boot, what is kept where
│   ├── TESTING.md                # Unit, integration, the VM test and the acceptance run: what each needs, how to run it
│   ├── SLOT.md                   # The slot: a boot state the signing key approved; choosing PCRs, approving, deleting
│   ├── SEALING.md                # The details of sealing: the measure point, SHA-1, own keys, several slots
│   ├── CODE.md                   # The TOTP code: when the TPM computes it, the code screen, the cap, the clock
│   ├── PHONE.md                  # The phone (Marify) verifies the boot over Bluetooth LE
│   ├── SSH.md                    # SSH in the boot image: the code screen over the network
│   ├── DISK-KEY.md               # The disk's key: the four cases, the token, the route, how systemd takes the key
│   ├── VAULT.md                  # tpm+vault: the disk's key from this TPM and tpm2-kira-vault
│   ├── PROTOCOL-BLE.md           # Phone <-> machine protocol: the interface definition
│   ├── PLAN-*.md                 # Designs: the phone (PLAN-PHONE, PLAN-BLE), the phone salt, the vault, LUKS, YubiKey, the test host (PLAN-BLE-TESTING)
│   ├── mobile/                   # Agent prompts for the Android and iOS apps
│   ├── PLATFORM-OBSERVATIONS.md  # Measured facts about Arch and Debian boots
│   ├── pentest1/, pentest2/      # Security review findings and mitigations
│   └── *.issue                   # Write-ups of specific bugs
├── initramfs/               # Everything that goes into, or builds, an initramfs
│   ├── common/control.conf          # tpm2-kira's configuration: what the image is built with (radio, network, SSH); aSSH's is assh.conf beside it
│   ├── systemd/tpm2-kira.service   # Shows the code in systemd-based images
│   ├── systemd/tpm2-kira-cap.service  # Runs 'cap' when leaving the initrd
│   ├── mkinitcpio/                 # Arch
│   │   ├── install/sd-tpm2-kira    # Build hook: puts the binary in the image
│   │   ├── post/sd-tpm2-kira       # Approve after the image is written
│   │   └── mkinitcpio.conf.example
│   └── initramfs-tools/            # Debian
│       ├── hooks/tpm2-kira         # Build hook: copies the static binary
│       ├── scripts/init-premount/tpm2-kira  # Shows the code before unlock
│       ├── scripts/init-bottom/tpm2-kira    # Stops it and caps before switching root
│       └── post-update.d/tpm2-kira          # slot approve for the new image
├── debian/                  # Debian package definition (must sit at the root)
├── packaging/
│   ├── aur/                 # Arch Linux PKGBUILD
│   └── deb-version.sh       # git describe -> a Debian-valid version
└── Makefile
```

## Testing

```bash
make test-unit            # no TPM
make test-integration     # swtpm and socat
tools/vmtest.py --target both     # the whole life on fresh, encrypted test VMs, with a vault
```

The levels, what each needs and how to run them: [TESTING.md](TESTING.md).
