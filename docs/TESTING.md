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
- **The machines on this host instead:** `tools/localvm.py` runs both with
  qemu, swtpm and OVMF, with no hypervisor and no root, and resets them to
  their snapshot. See `tools/LOCALVM.md` for setting them up from an
  export, the serial console, and the pitfalls. `tools/serialtest.py`
  tests the recipes at their console.
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

Every step is timed: its seconds in the output as it ends, a table with
the laps inside the boots and the slowest steps in each `report.txt`, the
same as `times.json`, and the slowest steps over both machines before the
result. `tools/hibernatetest.py` does the same.

### Iterating from a saved setup

A final proof starts from the snapshot `fresh`. To work on a step, on the
machines of `tools/localvm.py`, the setup can be kept:

```bash
tools/vmtest.py --config ../.local/vms/vmtest-local.conf --target both --save-setup   # up to the first reboot: the snapshot "setup"; ends
tools/vmtest.py --config ../.local/vms/vmtest-local.conf --target both --from-setup   # the rest, from it, without building
tools/hibernatetest.py --target both --save-setup      # "setup" when it fits (else made on the way), then its own: "hib-setup"; ends
tools/hibernatetest.py --target both --from-setup      # every V step, from it, without building
tools/hibernatetest.py --target both --only V4,V8      # those steps alone
tools/hibernatetest.py --target both --drop-setup      # removes both snapshots (the VM test's flag removes "setup")
```

A run from a saved setup says on its report's first line that it is no final
proof. A snapshot holds the commit that made it and is refused once anything
but `tools/` and documentation has changed since. `fresh` and `export` are
never written: `tools/localvm.py` refuses to replace or remove them without
`--overwrite`, by hand.

### A test build: `--fast-kdf`

```bash
tools/vmtest.py --config ../.local/vms/vmtest-local.conf --target both --fast-kdf
```

**Such a run is no final proof.** It says so in the output and on the first line
of every report. Argon2id's production cost (1 GiB, 16 passes, 4 lanes) is a
constant in `internal/diskkey/combine.go`; a Go build tag alone,
`kira_test_fast_kdf`, selects a test's (`combine_cost_fast.go`: 16 MiB, 1 pass) -
not a flag, an environment variable, a config or a LUKS token: anything at run time
would be a downgrade an attacker could reach. `packaging/build-packages.sh
--fast-kdf` edits its copies of the recipes to pass the tag, marks the version
`.fastkdf` and writes to `build/packages-fastkdf/`. Every step, the typed recipes'
prompts, keyslots and boots included, runs as always; what is not shown is the
real cost, its memory and its time. Keyslots enrolled with one cost do not open with
the other, and a saved setup is refused by a run of the other kind.

What keeps the tag out of a release: `packaging/aur/PKGBUILD`, `debian/rules` and
`release.yml` never name it and run `packaging/release-binary-check.sh` on what they
built, which refuses a binary Go recorded a build tag for or that holds the test
build's mark; `internal/diskkey/release_test.go` holds the recipes to that, and shows
it on real builds of both kinds; every VM test checks its package the same way before
it touches a machine, and that `tpm2-kira version` says nothing of a test build. A
test build says what it is in `version` and in `tpm2-kira status`. The vault, the
phone, aSSH and safearch derive nothing with this cost: they hand over salts,
parts and peppers; only `diskkey.Combine` runs it, in the two binaries of one package.

### What a run costs

Seconds, measured from `fresh` (2026-11-02, both machines in parallel, one process;
`times.json` of each run). Before is the code before the timing work; after has the
state waits; `--fast-kdf` is the test build's cost on top of that.

| | Arch before | after | `--fast-kdf` | Debian before | after | `--fast-kdf` |
|---|---:|---:|---:|---:|---:|---:|
| VM test, all | 957 | 833 | 686 | 1048 | 922 | 696 |
| a typed boot (reboot 1) | 68 | 48 | 38 | 81 | 59 | 49 |
| a boot, wrong pepper then right | 96 | 82 | 60 | 127 | 110 | 66 |
| hibernate test, all | 1240 | 1064 | 1002 | 1171 | 1074 | 919 |
| V2 | 272 | 231 | 212 | 76 | 68 | 52 |
| V4 | 502 | 421 | 388 | 199 | 191 | 158 |
| V5 | 23 | 3.5 | 3.6 | 23 | 3.9 | 3.9 |
| V8 | 55 | 52 | 82 | 101 | 94 | 81 |

The VM test's whole run, with the build and the vault's container: 1117 s before,
967 after, 739 with `--fast-kdf`. A hibernate test from `hib-setup` skips a further
4-5 minutes of setup; it is no final proof. The guest's memory stays 4096 MiB: lower
gained nothing and fails (`tools/LOCALVM.md`, "Memory").

What is left is mostly the machines and the product:
- the V4 and V9 boots without a TPM's answer (Arch's silent TPM alone 240 s) wait for
  the close's own timeouts;
- Arch's V2 spends about 205 s between the prompts and ssh, on the first resume after
  the setup, about 30 s from `hib-setup`: not explained, and not Argon2id (212 s with
  `--fast-kdf`);
- firmware to the boot SSH server is 18-20 s on Arch and 28 s on Debian (GRUB's timeout
  is `fresh`'s), the initrd's end to ssh 6 and 10-16 s;
- Argon2id itself is 11-17 s per derivation on the 2 vCPUs.

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
5. **`luks enrol --salt typed`** (the recovery recipe) with a test password and salt.
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
   boot the close ran (every slot closed: PCR 15 extended, slot 0's TOTP
   key refuses), the key was answered, `ssh-child` ran confined
   (nobody, no new privileges, no executable memory, Landlock, seccomp), and
   the boot's log has no error.
9. **Remote attestation over TLS, the vault:** a token from the vault,
   `luks enrol --password tpm --salt vault`, the image rebuilt with the vault; a boot
   that nobody touches, unlocked by the vault's release to the TPM's
   quote; a boot with the device revoked on the vault, where the screen
   and the prompt say the vault gave no key and the recovery recipe's
   keyslot is the fallback, typed over SSH; then unrevoked; the keyslot
   enrolled again with a pepper, a boot approved over the operator
   interface first with a wrong pepper, then with the right one.
10. **A slot's life:** `slot approve`, `slot add --nvram 2`, `slot delete`
    (blob and generation index gone). Between them slot 2 gets a phone channel
    sealed to a PCR 7 of another day (`channel-fixture`: `go test -c -tags
    kira_vm_fixture ./internal/admin`, on the machine for the run, never in a package;
    no VM has a phone, and a register extended by hand moves nothing here, since the next
    boot's value comes from the event log). The real hook scripts, `--if-moved` and a run with
    no terminal leave it and say so with old, new and the event log's names; no at a
    terminal leaves it; yes and `control`'s line seal it. A gate refusing it is
    `TestChannelFollowsPCR7`'s, with PCR 7 extended by hand on swtpm.
    Throughout, Secure Boot's warning, from the machine's own variables (the
    fresh VMs are in Setup Mode): once in `slot add`, `slot approve` and `status`,
    per image in the hook's output, red in `control`'s two steps, and at each boot on
    the console (the serial log), in the SSH session and in the boot's log.
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
