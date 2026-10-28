# Notes for agents working on tpm2-kira

## No backwards compatibility

This project is in development and has no installed base to protect. Do not
spend code, tests or documentation on older versions of anything.

- **One format, the current one.** A blob, file or message of another version
  is an error that says what to do now (seal again, enrol again). Do not read
  old formats, convert them, or accept several versions side by side.
- **No migration paths.** When a format, an NV index layout, a CLI flag or a
  unit changes, the old one is gone in the same change. No fallbacks, no
  "also accept the old name", no cleanup code for what earlier versions left
  behind, no deprecation periods.
- **No compatibility with older or newer builds of tpm2-kira itself.** Do not
  design a change so that a previous build keeps working with new data, or
  the other way round.
- **Say what it is, not what it was.** Code comments, help texts and
  documentation describe the current design only. If a superseded design is
  worth remembering, put the reasoning in `HISTORY.md` and nowhere else.
- **Tell the user plainly** when a change means sealing or enrolling again.
  That is acceptable; silently keeping an old path alive is not.

This does not make extensibility wrong: a structure may leave room for what
comes next (the blob's attestation part has typed methods for that reason).
It may not carry what came before.

## Other standing decisions

- **One binary.** Everything is the single `tpm2-kira` executable; processes
  that must be separated (the confined radio worker, the SSH server's
  unprivileged half) are the same binary run with other arguments, never a
  second executable.
- **The SSH server and the TPM host keys are aSSH's**
  (`assh/`, a git submodule; `github.com/tpm2-trust/assh`, a project of its
  own that other projects use too): the privilege-separated server
  (`assh/server`), the SSH CA in the TPM and the per-boot host keys it
  certifies (`assh/hostkey`). tpm2-kira uses it as a library (`replace`
  in go.mod to the submodule; clone with `--recurse-submodules`) and
  keeps only what is its code screen's: sessions, prompts, the console,
  the CA's approval for the
  measure point. A change to the SSH protocol side or to how keys are held
  in the TPM goes into aSSH, with its tests there. No host key and no
  secret of one is ever stored, in the image or on the disk.
- **SHA-1 only when asked.** The SHA-1 PCR bank is used only with `--sha1`,
  with a warning at slot add and slot approve (control's overview carries the risk
  instead, so its steps say nothing twice); nothing falls back to it on
  its own. Workarounds for old
  TPMs must not change the SHA-256 path.
- **Tests must run against the current code.** Use `-count=1` for the
  integration suite; a result marked `(cached)` has tested nothing.
- **Tests and test runs are fast, and they wait for a state, never for a
  time.** Poll for the status you need (a process gone, ssh answering, a
  file written) and go on the moment it is there; a timeout is an upper
  bound for a failure, not a wait. A run never does the same work twice:
  the acceptance run (`tools/acceptance.py`) builds the package without
  its unit tests (`makepkg --nocheck`, `DEB_BUILD_OPTIONS=nocheck`: they
  have their own run), keeps the Go build cache across runs
  (`GOCACHE` from the environment, `debian/rules`), installs build
  dependencies only when they are missing, and fails at once at a prompt
  it cannot answer instead of sitting at it. What this meant in numbers
  (2026-10-08): the Arch run went from 3 min to 25 s, the Debian run from
  over 4 min to 65 s, by removing a duplicate test run, a thrown-away
  cache and an `apt-get install` of what was installed.
- **A test machine's own defect is reported, not repaired.** When a VM is
  misconfigured (an empty `/etc/resolv.conf`, say), the run fails with the
  advice and the owner fixes the machine by hand, so the defect does not
  come back unnoticed.
- **Builds use the current Go release, asked from go.dev at build time.**
  The workflows set it up through `.github/actions/go-latest`, the Arch
  package build and the acceptance runs through `GOTOOLCHAIN`, so no release
  ships a standard library with known vulnerabilities and nobody has to
  bump anything when Go releases. go.mod's `go` line is the minimum the
  code builds with, nothing more. The vulnerability scan
  (`tools/vulncheck.py`, run by the Vulnerability Scan workflow) fails on
  what the code calls into; a record the database has wrong goes into
  `tools/vulncheck-ignore` with its proof, never silenced elsewhere.
- **No enforced mode; the passphrase can always be entered by hand.**
  tpm2-kira adds ways to unlock (its prompt, later a phone-released
  factor) and informs; it never withholds systemd's own prompt, which is
  the fallback after a wrong or missing answer (docs/DISK-KEY.md, "When the answer is wrong").
  Do not build a mode that holds the boot on the phone's verdict.
- **Two configuration files, tpm2-kira's and aSSH's, and only `control`
  writes them.** `/etc/tpm2-kira/control.conf` is tpm2-kira's; beside it
  `/etc/tpm2-kira/assh.conf` is aSSH's own format (`ASSH_*`, parsed by
  `assh/config`): the SSH CA and its slots and their PCRs, the port, the
  keys that may log in, the host certificate's name. Keep them apart: a
  setting of what aSSH does goes into assh.conf (and into aSSH, if it has
  no key for it), one of tpm2-kira's - the network, whether the server
  runs, the hold - into control.conf. control.conf holds what the boot
  image is built with, and
  nothing else: the radio settings and the boot image's network and SSH
  server (TPM2_KIRA_NET_*, TPM2_KIRA_SSH_*: the one part the image build
  turns into files of the image - a networkd file, a unit drop-in -
  through the boot plan; the file itself never goes in, docs/SSH.md)
  (nothing else of it reaches the boot image: the gate there takes the
  adapter that comes up, waits as long as the code screen holds, and
  logs every step when "Debug at boot" is on - a switch in the TPM, NV
  index 0x01803000, written by `control` with the signing key).
  Beside it, also written by `control` alone: the YubiKey's PIN
  (`/etc/tpm2-kira/pin`, root's alone, never in the image) and the keys
  that may log in at boot (`/etc/tpm2-kira/authorized_keys`, part of the
  SSH server's settings in the boot plan). assh.conf goes into the image
  as a copy (the SSH part's digest names it); the slots in it are made
  the CA's by slot approve and control before they approve.
  How the
  disk's key is made is not configured anywhere: the boot reads it from
  each volume's own LUKS2 header - the tpm2-kira token of a keyslot names
  the recipe (internal/diskkey/header.go), so an enrolment needs no mode set and
  no rebuild for one. `setup`, `slot add`, `luks enrol` and the rest do their
  one thing; `tpm2-kira control` checks the prerequisites of a working
  setup. Every other file on the system - the kernel command line,
  crypttab - is advised by `control`, never edited, with two exceptions,
  each asked for every time, both in control's step 1 (the boot chain):
  the HOOKS of `/etc/mkinitcpio.conf` (its mkinitcpio step writes
  sd-tpm2-kira in when the person says so), and the key's route (the route step writes the shown line into
  the cmdline file, a boot entry's options or crypttab when the person
  says so). Step 2 is submenus whose options are greyed with the reason
  while the machine cannot have them; what changes the image there only
  marks it out of date, and the image is built once, when `control` is
  left, after the person says yes. `control`'s status
  judges line by line - green what is good, red what is not with the
  risk in brackets (SHA-1, Secure Boot off or in Setup Mode, an unvouched
  endorsement key, a selection without the kernel, a loose file holding
  the PIN, an empty passphrase, a vault that does not answer); there is
  no separate risks list.
- **The boot image carries what the machine uses, by the boot plan**
  (internal/admin/bootplan.go, `tpm2-kira initramfs plan`). The disk unlock is always
  in it; every other part - the TOTP codes, the phone's Bluetooth gate, the
  vault, the network, the SSH server - only while something uses it (a
  sealed slot, an enrolled phone, a setting of control.conf), and what
  needs the TPM stays out without one. The decision is made once, at the
  build, from the machine: the hooks add the units and drivers of the parts
  the plan names, and `run` and the boot scripts start only those
  (`run --plan`), so the boot touches no TPM and loads no radio it was not
  built for. The image names its parts in `/etc/tpm2-kira/plan/<part>/<digest
  of its settings>`; `control` reads that from the image's listing. A part
  in use and not in the image, or in it with other settings, is a reason
  to rebuild; a part the image carries for nothing is not - the next build
  leaves it out. Do not decide what the image carries in a hook's shell
  or at boot: add the rule to the plan.
- **Root for everything but the help.** Every command refuses to run as a
  user (`main.go` `requireRoot`); `control` says so on its own screen. The
  test suite's exception is `TPM2_KIRA_UNPRIVILEGED=1` for the binary
  against a software TPM.
