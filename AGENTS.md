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
  with a warning; nothing falls back to it on its own. Workarounds for old
  TPMs must not change the SHA-256 path.
- **Tests must run against the current code.** Use `-count=1` for the
  integration suite; a result marked `(cached)` has tested nothing.
- **No enforced mode; the passphrase can always be entered by hand.**
  tpm2-kira adds ways to unlock (its prompt, later a phone-released
  factor) and informs; it never withholds systemd's own prompt, which is
  the fallback after a wrong or missing answer (docs/UNLOCK-DISK.md §4).
  Do not build a mode that holds the boot on the phone's verdict.
- **One configuration file, `/etc/tpm2-kira/control.conf`, and only
  `control` writes it.** It holds the unlock mode, the radio settings and
  the YubiKey's PIN (the hooks copy it into the initramfs without the PIN
  line). `setup`, `seal`, `luks enrol` and the rest do their one thing and
  say what the file would need; `tpm2-kira control` sets it and checks the
  prerequisites of a working setup. Every other file on the system - the
  kernel command line, crypttab, `/etc/mkinitcpio.conf` - is advised by
  `control`, never edited. What weakens the protections (SHA-1, Secure Boot
  off or in Setup Mode, an unvouched endorsement key, a selection without
  the kernel) is shown on `control`'s overview under Risks.
- **Root for everything but the help.** Every command refuses to run as a
  user (`main.go` `requireRoot`); `control` says so on its own screen. The
  test suite's exception is `TPM2_KIRA_UNPRIVILEGED=1` for the binary
  against a software TPM.
