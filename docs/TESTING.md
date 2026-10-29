# Testing

Four levels, from seconds to a whole boot:

| Level | What it needs | What it shows |
|---|---|---|
| unit | Go | the logic: blobs, policies, recipes, the board, the parsers |
| integration | Go, swtpm, socat | the binaries against a software TPM: sealing, codes, run, the unlock socket, SSH |
| the VM test (`tools/vmtest.py`) | fresh, encrypted VMs; docker; the built packages | tpm2-kira's whole life on a real machine: install, `control`, reboots unlocked over SSH, the vault |
| the acceptance run (`tools/acceptance.py`) | a machine you watch | the same install checks, with you at the console for the reboot |

## Unit and integration tests

```bash
make test-unit              # no TPM; tpm2-kira's packages, then the core's (core/, a module of its own)
make test-integration       # swtpm and socat: sudo pacman -S swtpm socat (apt install swtpm swtpm-tools socat)
make test-all
make fuzz                   # the parsers of untrusted input, FUZZTIME per target (30s)
tools/vulncheck.py ./...    # known vulnerabilities the code calls into
```

Tests run with `-count=1` and wait for a state, never for a time
(AGENTS.md). The integration suite builds both binaries, `tpm2-kira` and
`tpm2-kira-boot`, as they ship (static, no cgo) and runs them as a user
against swtpm (`TPM2_KIRA_UNPRIVILEGED=1`).

## The VM test

`tools/vmtest.py` takes fresh, encrypted test VMs through everything a
person does with tpm2-kira, answers every prompt as a person would, and
writes a report per machine with every session's transcript.

### What it needs

- **The VMs.** Each with its root on LUKS (the passphrase known), a TPM
  2.0 (swtpm is fine), sshd, and a user with sudo; tpm2-kira not
  installed, kept as a snapshot the run goes back to (`reset` below): the
  run installs packages, writes the TPM's NV, an SSH CA into an EFI
  variable, keyslots and a new boot image. (The EFI variable survives
  most snapshots; the run then makes the SSH CA again, and says so.)
- **What the packages are built with**: makepkg here, docker for the
  Debian package (`packaging/build-packages.sh`, which the run calls) -
  nothing is built on a VM.

- **docker**, and the tpm2-kira-vault source beside this repository
  (`../tpm2-kira-vault`): the run starts the vault itself (below).
- **`tools/vmtest.conf`** - copy `tools/vmtest.conf.example` (it is not in
  git):

  ```ini
  [defaults]
  password_file = ~/.vm-pw       # the VMs' user password; or $VMTEST_PASSWORD

  [arch]
  host = 172.17.2.198
  user = pix
  # back to the snapshot, on the hypervisor; VMTEST_NAME, VMTEST_HOST are set
  reset = virsh -c qemu+ssh://root@hv/system snapshot-revert vmtest-arch fresh --running

  [debian]
  host = 172.17.2.196
  user = pix
  reset = ssh root@pve 'qm rollback 196 fresh && qm start 196'

  [vault]
  src = ../tpm2-kira-vault
  url = https://172.17.2.174      # where the VMs reach this machine
  port = 443
  ```

  The LUKS passphrase is `luks_passphrase` of a machine's section,
  `$VMTEST_LUKS_PASSPHRASE`, or else the user's password.

### Running it

```bash
tools/vmtest.py --target both               # or arch, or debian (in parallel)
tools/vmtest.py --target both --cycles 3    # reboots unlocked over SSH (default 2)
tools/vmtest.py --target arch --no-vault    # without the vault
```

A run needs nobody at the keyboard, and starts from a defined state:

1. **The packages of HEAD**: it builds them (`packaging/build-packages.sh`:
   the committed state, aSSH as pinned) and installs exactly those - by
   the commit in their names, never a package of another commit.
   Uncommitted changes are not tested; it says so. `--no-build` takes
   HEAD's packages already in `build/packages`.
2. **Each machine reset**: the `reset` command of its section in
   `vmtest.conf` - going back to its snapshot on the hypervisor - and
   then its ssh is waited for. Without one (or with `--no-reset`) the
   machine must be fresh already; one that is not is refused before
   anything is changed.
3. The steps below, both machines at once, and the vault in its
   container.

It ends with `ALL PASS` (exit 0) or `FAILED` and the run's directory
(`./vmtest-<time>`, or `--run-dir`): per machine `report.txt`, the
transcript, a log per command and session (`session-*-control.log`,
`boot-1.log`, ...), and the boot logs; the vault's log and audit in
`vault/`.

### What it checks

1. **Preflight:** the machine answers, runs the distribution, is fresh,
   has a TPM and a LUKS device that the passphrase opens.
2. **Install** the package with `dpkg -i` or `pacman -U`; both binaries
   of one version; the root gates.
3. **`setup --local`, `slot add`;** the TPM's code against the one
   computed from the secret `slot add` shows - what your authenticator
   does (on a systemd initrd the running system is past the separator:
   locked until the next boot, by design).
4. The commands that read: `status`, `slot info|list|status`, `phone
   ekcert`, `luks status`, `initramfs plan`, help pages.
5. **`luks enrol --mode password+salt`** with a test password and salt.
6. **`control`, answered line by line** (`ACCESSIBLE=1`): step 1's
   adoptions (the mkinitcpio hook, the key's route), the image's network
   (DHCP, as proposed), the SSH server at boot (port 2222, a 600 s hold)
   with its SSH CA, debug at boot, the image rebuilt when control is left.
   The key that may log in at boot is a test key the run makes; the CA's
   `@cert-authority` line goes into the run's own known_hosts.
7. **The image:** `tpm2-kira-boot` and no `tpm2-kira`, no control.conf,
   the plan's parts, no unit or script that starts a gate (`run` starts
   its children itself).
8. **Reboots** (`--cycles`): the boot SSH server answers; its host key is
   checked against the CA (`StrictHostKeyChecking=yes`); both slots'
   codes against the computed ones; Enter, the password and the salt in
   the session; the session ends with the server's last line; after the
   boot the cap ran, the key was answered, `ssh-child` ran confined
   (nobody, no new privileges, no executable memory, Landlock, seccomp), and
   the boot's log has no error.
9. **Remote attestation over TLS, the vault:** a token from the vault,
   `luks enrol --mode tpm+vault`, the image rebuilt with the vault; a boot
   that nobody touches, unlocked by the vault's release to the TPM's
   quote; a boot with the device revoked on the vault, where the screen
   and the prompt say the vault gave no key and the password+salt keyslot
   is the fallback, typed over SSH; then unrevoked.
10. **A slot's life:** `slot approve`, `slot add --nvram 2`, `slot delete`
    (blob and generation index gone).
11. **Removal:** `control` switches the SSH server off and asks before it
    removes the SSH CA - No keeps the EFI variable and `ssh_ca.pub`;
    `slot delete --yes` then takes everything of tpm2-kira: no index of
    its range is left in the TPM, the `KIRAasshCA` variable and
    `ssh_ca.pub` are gone, and a second run finds nothing.

### The vault of the run

The run builds tpm2-kira-vault from `[vault] src` and starts it in a
container (`tools/vmtest-vault/`: Arch with swtpm as the vault's TPM),
listening on `[vault] port` of this machine, created for the run and
removed after it - the VMs reach it at `[vault] url`. By hand:

```bash
docker logs tpm2-kira-vmtest-vault                       # the pin and the recovery key of init
docker exec tpm2-kira-vmtest-vault tpm2-kira-vault devices
docker exec tpm2-kira-vmtest-vault tpm2-kira-vault audit
```

The image is built with the host's network (`docker build --network
host`): name resolution inside a build container depends on docker's
firewall rules, which another program reloading the firewall (libvirt's,
when its VMs restart) can take away.

## The acceptance run

`tools/acceptance.py` is the run for a person at the machine: it builds
the package of a commit on the target, installs it, checks what can be
checked over ssh, reboots when you say so, asks what the console showed,
and checks the booted system and its journal.

```bash
tools/acceptance.py --distro arch   --host 172.17.2.198 --user pix --ask-password
tools/acceptance.py --distro debian --host 172.17.2.196 --user pix --password-file ~/.vm-pw --luks /dev/vda3
tools/acceptance.py --distro debian --host 172.17.2.196 --no-build --no-reboot   # what is installed
```

The machines a fully unattended run would want - installed by a script,
frozen, with a serial console the harness reads and the phone in the
Android emulator - are the plan in [PLAN-BLE-TESTING.md](PLAN-BLE-TESTING.md).
