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
  that must be separated (the confined radio worker) are the same binary run
  with other arguments, never a second executable.
- **SHA-1 only when asked.** The SHA-1 PCR bank is used only with `--sha1`,
  with a warning at seal and reseal (control's overview carries the risk
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
  the fallback after a wrong or missing answer (docs/UNLOCK-DISK.md §4).
  Do not build a mode that holds the boot on the phone's verdict.
- **One configuration file, `/etc/tpm2-kira/control.conf`, and only
  `control` writes it.** It holds the radio settings and the YubiKey's PIN
  (the hooks copy it into the initramfs without the PIN line). How the
  disk's key is made is not configured anywhere: the boot reads it from
  each volume's own LUKS2 header - the tpm2-kira token of a keyslot names
  the recipe (cmd/luks_header.go), so an enrolment needs no mode set and
  no rebuild for one. `setup`, `seal`, `luks enrol` and the rest do their
  one thing; `tpm2-kira control` checks the prerequisites of a working
  setup. Every other file on the system - the kernel command line,
  crypttab - is advised by `control`, never edited, with two exceptions,
  each asked for every time: the HOOKS of `/etc/mkinitcpio.conf` (its
  mkinitcpio step writes sd-tpm2-kira in when the person says so, and runs
  mkinitcpio -P when asked), and the key's route (the route step writes
  the shown line into the cmdline file, a boot entry's options or
  crypttab when the person says so). `control`'s status judges line by line - green
  what is good, red what is not with the risk in brackets (SHA-1, Secure
  Boot off or in Setup Mode, an unvouched endorsement key, a selection
  without the kernel, a loose file holding the PIN); there is no separate
  risks list.
- **Root for everything but the help.** Every command refuses to run as a
  user (`main.go` `requireRoot`); `control` says so on its own screen. The
  test suite's exception is `TPM2_KIRA_UNPRIVILEGED=1` for the binary
  against a software TPM.
