# TODO-SEC — security hardening backlog

Findings from a source review on 2026-10-03 (branch `feat/yubikey-v2`, commit
`1d21db5`). Each item says where the problem is, why it matters, how to resolve
it, and what "done" looks like. Line numbers are from that commit; re-locate by
function name if they have moved.

Items are independent unless a **Depends on** line says otherwise. Pick one,
finish it, tick it off here.

## Ground rules for whoever picks these up

- **One static binary.** `CGO_ENABLED=0`, no second build artifact, no cgo
  dependency. A feature that would normally pull in a C library is written in
  pure Go instead.
- **No backwards compatibility.** The project is alpha. Bumping
  `CurrentBlobVersion` is acceptable when a format change is the clean
  solution; record it in `HISTORY.md`. Do not overload existing fields to
  avoid a bump.
- **Exit status stays 0 on failure** (README "Exit status"). Report failures
  with the `tpm2-kira: FAILED:` marker; hooks grep the output.
- **Docs move with the code.** Any behaviour change updates `README.md` and
  `docs/SECURITY-BACKGROUND.md` in the same change (threat model §8, NVRAM §9,
  blob format §10 are the usual places).
- **Tests.** `make test-unit` must pass. Before pushing also run
  `go vet ./...`, `go vet -tags=unit ./...` and `go vet -tags=integration ./...`
  — `cmd/cmd_test.go` is `//go:build unit || !integration`, so helpers defined
  there do not exist under the integration tag. Integration tests need `swtpm`
  (`make test-integration`); the harness only rebuilds `./tpm2-kira` when it is
  missing, so `rm -f tpm2-kira` first.
- Items marked **OWNER DECISION** contain a design choice the maintainer has
  not made yet. Implement the recommended option only if told to; otherwise
  ask.

## Overview

| # | Sev | Area | Summary | Size |
|---|-----|------|---------|------|
| 1 | High | policy | Default PCR selections do not attest the initrd or command line; no warning | S |
| 2 | High | policy | Secret remains unsealable in the running OS (no PCR cap) | L |
| 14 | High | design | Secret leaves the TPM on every use; compute the HMAC in the TPM instead | L |
| 3 | Med | reseal | Blob signature is verified with a key the blob itself names | S |
| 4 | Med | keys | Key files checked for mode only, not owner / symlink / parent | S |
| 5 | Med | seal | TOTP secret passed to `qrencode` on the command line | S |
| 6 | Med | yubikey | PIN read from a world-readable file | M |
| 7 | Med | tpm | Unseal/Create parameters cross the TPM bus in cleartext | M |
| 8 | Med | tpm | Raw `/dev/tpm0` default plus global handle flush | S |
| 9 | Low | info | `info` prints and opens unverified blob strings | S |
| 10 | Low | tests | No fuzz target for the blob parser | S |
| 11 | Low | nvram | `nvram delete` wipes all slots without confirmation | S |
| 12 | Doc | docs | RTC pre-recording attack missing from the threat model | S |
| 13 | Low | initrd | systemd unit runs unsandboxed | S |

Suggested order: 3+4 together, 5, 8, 9, 10, 1, 6, then 14, then 2, then the
rest. Decide on 14 before starting 7 or 2: it replaces the unseal path that 7
encrypts and changes how `reseal` works, so doing 7 or 2 first means doing
parts of them twice.

How the three High items fit together — none is sufficient alone:

| Attack | 1 (selection) | 2 (cap) | 14 (HMAC in TPM) |
|---|---|---|---|
| Boot another OS / shell in the genuine initrd, then use the TPM | **closes** | no effect | limits to precomputed codes |
| Root or `tss` in the running OS uses the TPM | no effect | **closes** | limits to precomputed codes |
| TPM bus probe | no effect | no effect | **closes** for the key |
| Copy the key out, use it forever | — | — | **closes** |

---

## 1. Default PCR selections do not attest the initrd

- [x] done — steps 1–4 (warning, UKI detection, README "Choosing PCRs" and "Hardening the boot path", setup hint via `RecommendedPCRs`). Step 5 (flag default) left for the OWNER DECISION.

**Where**
- `main.go:184` — `seal --pcrs` default `0,2,7`
- `cmd/pcrwarn.go:59` — `WarnAboutPCRSelection` (only warns for PCR 0 alone
  and PCR 7 without Secure Boot)
- `README.md` — Quick Start uses `--pcrs 0,7`; the Debian section calls
  `0e,2e,4e,7e` "a good default"
- `cmd/setup.go` — prints `tpm2-kira seal --pcrs 0,7` as the next step

**Problem.** PCRs 0, 2, 4 and 7 measure firmware, the bootloader binary and
the Secure Boot policy. Outside a unified kernel image the initrd is never
signature-checked, not even with Secure Boot on. An attacker with disk access
replaces the initrd with one that logs the LUKS passphrase and still runs the
genuine `tpm2-kira run`; every sealed PCR is unchanged, so a valid code is
shown. The tool's central promise fails in its recommended configuration.

The same gap lets an attacker take the secret itself, without the passphrase
and without hardware. The TPM releases it to whoever presents matching PCRs,
and the owner hierarchy has no password, so a root shell with the sealed PCRs
intact is enough:

- **Another OS.** Firmware-only selections do not record which OS booted.
  With Secure Boot off any live USB works; with it on, a medium whose
  bootloader is accepted by the same certificates (the same distro's signed
  shim/GRUB) leaves PCR 7 unchanged, and carrying the same bootloader binaries
  leaves PCR 4 unchanged too. The attacker reproduces the `os-separator`
  extends by hand if the policy expects them.
- **A shell in the genuine initrd.** Editing the kernel command line at the
  boot menu (`break=`, `rd.break`, a debug shell), or on Debian the fallback
  shell after failed passphrase attempts, gives root inside the real initrd.
  The command line is not in PCRs 0–7.

Either way the attacker runs a static unseal tool from a USB stick. This was
derived from the code and PCR semantics, not reproduced on hardware.

**Resolution.**
1. Add a warning to `WarnAboutPCRSelection` when no selected PCR covers the
   kernel + initrd + command line: i.e. the selection contains none of PCR 9
   (GRUB files / EFI-stub initrd) with PCR 8 (GRUB commands, which include the
   command line), PCR 11 (UKI, command line embedded). Word it like the
   existing warnings: what is not covered, what an attacker can do, which
   selection fixes it (`7,11u` on a UKI system with own Secure Boot keys;
   `8e,9e` on GRUB with the reseal-after-reboot workflow the README already
   describes). On a non-UKI systemd-boot setup the command line lands in
   PCR 12; say so.
2. Add a "Hardening the boot path" section to the README: a selection is only
   as good as the ways into a shell it measures. List: boot-menu editor off
   (systemd-boot `editor no`, GRUB password), `panic=0` on Debian so a failed
   unlock does not drop to a shell, firmware setup password and locked boot
   order, own Secure Boot keys so foreign media change PCR 7.
3. Detect a UKI boot (the `u` source code in `cmd/ukipredict.go` already knows
   how to find the image) and name the concrete suggestion in the warning.
4. Change README Quick Start, the AUR/Debian post-install snippets and the
   `setup` "next step" hint so the first command a user copies covers the
   initrd. Keep the firmware-only selections documented, but as the weaker
   option with the consequence stated.
5. Leave the flag default alone unless the owner says otherwise — changing it
   silently changes what existing scripts seal. **OWNER DECISION:** whether
   the default becomes platform-detected (`0e,2e,7e,11u` when a UKI is found).

**Done when** `seal --pcrs 0,7` and `--pcrs 0,7,9e` (initrd but no command
line) print the new warning, `seal --pcrs 0,7,11u` and `--pcrs 0,7,8e,9e` do
not, unit tests cover all four, and no doc recommends a selection without
saying what it leaves out.

---

## 2. The secret stays unsealable after boot (no PCR cap)

- [x] done — owner first chose PCR 23, which turned out to be resettable from locality 0 (verified on swtpm), so the cap is an NV read-lock instead: `tpm2-kira cap` read-locks the item-14 generation indices (`READ_STCLEAR`). Wired into `tpm2-kira-cap.service` (stop action at `initrd-switch-root.target`, like systemd-pcrphase's leave-initrd) and the initramfs-tools init-bottom script. Integration test `TestCapLocksCodesUntilReboot`. Not yet verified in a real initrd boot.

**Where**
- `cmd/policy_or.go:580` — `UnsealWithPCRBranch`: policy is PolicyPCR only
- `initramfs/systemd/tpm2-kira.service`,
  `initramfs/initramfs-tools/scripts/init-bottom/tpm2-kira` — nothing is
  extended when the display stops
- `docs/SECURITY-BACKGROUND.md` §8 lists "root on a running, measured system
  can unseal" as accepted

**Problem.** With a policy of firmware PCRs only, the registers still match
after boot. Any process with TPM access (root, members of `tss`) can run
`tpm2-kira reveal` or unseal the secret itself and copy it out. A stolen TOTP
secret lets a tampered boot chain show correct codes forever; the user cannot
detect it and the only fix is a fresh `seal`. This is the "misuse in the
started OS" case.

**What already works.** On a UKI + systemd-initrd system, sealing with `11u`
closes this: `systemd-pcrphase-initrd.service` extends `leave-initrd` into
PCR 11 at switch-root, so the policy is unsatisfiable afterwards. Item 1
steers users there. This item is for everything else (Debian/initramfs-tools,
non-UKI Arch).

**Resolution (recommended design).**
1. New command `tpm2-kira cap`: extends a fixed digest
   `H("tpm2-kira:leave-initrd")` into the cap PCR, in every active bank. No
   flags needed beyond `--tpm`.
2. The cap PCR must be part of the sealed policy. **OWNER DECISION** between
   two options:

   **Option A — cap PCR 0** (raised by the owner; the simpler one).
   Every common selection already contains PCR 0, and extending firmware PCRs
   from userspace has precedent: `systemd-pcrosseparator.service` extends
   `os-separator` into PCRs 0–7. No new source type is needed.
   - PCR 0 must then be sealed with the eventlog source (`0e`). The register
     source reads the capped value in the running OS, which the next boot
     never shows at the measure point: `seal`/`reseal` must refuse `0`/`0r`
     once capping is active and say to use `0e`. On firmware whose event log
     has no digests in the selected bank (README "TPMs whose event log has no
     SHA-256 digests") option A is unavailable; say so in the error.
   - `--measure-point=auto` (`cmd/measurepoint.go`) probes stable PCRs with
     "register == replay" / "register == replay + words". Add the capped
     candidates (`… + capDigest`) or the probe will refuse with "ambiguous".
   - Side effects outside tpm2-kira, to document: anything that reads the
     live PCR 0 in the running OS sees the capped value — e.g.
     `systemd-cryptenroll --tpm2-pcrs=0` would enrol a value the next boot
     does not produce in the initrd, and firmware checks that compare PCR 0
     with the event log may report a mismatch.
   - If the selection does not contain PCR 0, cap the lowest-numbered sealed
     PCR that uses the `e` source.

   **Option B — a dedicated OS PCR** (proposed PCR 13). No side effects on
   tools bound to firmware PCRs, but needs step 3 and an extra PCR in every
   policy.
3. Option B only: new PCR source for the cap PCR (suggested suffix `c`, a new
   `PCRSource` value — source byte 2 is retired, do not reuse it). Its
   measure-point value is computed, not read: reset value (zeros) plus the
   measure-point extends from `cmd/measurepoint.go` (`os-separator` on systemd
   initrds, nothing on Debian). At seal time in the running OS the register is
   already capped, so verify the prediction:
   `register == Extend(predicted, capDigest)`; refuse to seal otherwise
   (something else extends that PCR on this machine).

   Under either option the cap only protects the *running OS*. An attacker
   who boots another OS or gets a shell in the initrd does not run it; that
   is item 1.
4. Run the cap:
   - systemd initrd: a separate oneshot unit `tpm2-kira-cap.service`,
     `DefaultDependencies=no`, `Before=initrd-switch-root.target`,
     `After=tpm2-kira.service`, `Conflicts=tpm2-kira.service` so the display
     stops first; wire it in `initramfs/mkinitcpio/install/sd-tpm2-kira` the
     same way `tpm2-kira.service` is enabled. A separate unit is more reliable
     than `ExecStopPost=` if the display process is killed.
   - initramfs-tools: call `tpm2-kira cap` in `scripts/init-bottom/tpm2-kira`
     after the `kill`.
   - The cap must fail closed in the sense that a failed extend is printed
     loudly on the console; it must not block boot.
5. `seal`/`reseal`: warn (item 1 style) when the policy contains no PCR that
   is extended after the measure point — i.e. neither PCR 11 with pcrphase
   present nor the cap PCR.
6. `reseal` in the running OS then always takes the PolicySigned branch. That
   path exists and the key is required anyway for the NV write. `reveal` in
   the running OS reports a PCR mismatch on the cap PCR — document this as the
   intended result, and make the message say so instead of suggesting reseal.
   (If item 14 has landed, `reseal` no longer unseals at all and only the
   `reveal` part of this step applies.)

**Done when** an integration test (swtpm) seals with the cap PCR, shows
`reveal` succeeding, runs `cap`, shows `reveal` failing and `reseal`
succeeding via the signing key; and SECURITY-BACKGROUND §8 moves the "root on
a running system" row to the mitigated table with the remaining limits
(root can still steal a local signing key; see item 6 for the YubiKey case).

---

## 3. `reseal` verifies the blob with a key the blob names

- [x] done — `resolveResealKeys` in `cmd/reseal.go`; reseal also unseals the verified blob instead of re-reading NVRAM, and refuses a `--pubkey` that does not match. Step 5 (key path for the post hook) left for the OWNER DECISION.

**Where** `cmd/reseal.go`, function `Reseal`:
- lines 199–213: `effectivePrivKeyPath` / `effectivePubKeyPath` fall back to
  `sealedBlob.Payload.PrivateKeyPath` / `PublicKeyPath` — fields of the
  **unverified** blob
- lines 266–271: the verification key is loaded from that path and
  `VerifyBlobSignature` is checked against it

**Problem.** The comment says a tampered blob "cannot steer reseal via its
stored PCR specs or key paths", but the trust anchor comes from the blob.
The NV index can be deleted and redefined by anyone with TPM access (owner
auth is empty, SECURITY-BACKGROUND §9.4). Such a user plants a blob signed
with their own key, with `PrivateKeyPath` pointing at their own 0400 PEM file
in any directory they can write. The next root `reseal` (the mkinitcpio post
hook runs it automatically) verifies the planted blob successfully, reseals
the attacker's secret under the attacker's key and prints
"Successfully resealed" instead of the tamper error. Root also parses
attacker-chosen files (key file, then the UKI path from `spec.Command`).

**Resolution.**
1. Resolve the verification key without consulting the blob:
   `--privkey` if given, else `DefaultPrivateKeyPath`. If neither exists,
   fail with the existing "private key is required" message.
2. Verify the signature with that key.
3. Only after verification may blob paths be used, and then only as a
   consistency check: if the blob's `PrivateKeyPath`/`PublicKeyPath` differ
   from the resolved ones, say so. When the blob was sealed with a
   non-default key and no flag is given, the error must tell the user to pass
   `--privkey <path from blob>` explicitly — print the path quoted (`%q`), do
   not open it.
4. Same rule for the public key used for the *new* blob: `--pubkey`, else
   derived from the verified private key. Do not load
   `sealedBlob.Payload.PublicKeyPath` unless it was verified.
5. The mkinitcpio post hook (`initramfs/mkinitcpio/post/sd-tpm2-kira`) calls
   plain `tpm2-kira reseal`; users with a non-default key need a place to
   configure the path. **OWNER DECISION:** a `TPM2_KIRA_PRIVKEY=` line read
   the same way as the PIN (see item 6), or a small `/etc/tpm2-kira/` config.

**Done when** a unit test plants a blob signed by key B with paths pointing
at key B while the default key is A, and `Reseal` fails with the integrity
error without opening B's files; README "Custom signing keys" and
SECURITY-BACKGROUND §5.5 describe the new resolution order.

**Depends on / pairs with** item 4.

---

## 4. Key files are checked for mode only

- [x] done — `ReadSigningKeyFile` / `LoadChecked*` in `cmd/keyfile.go`, `cmd/signingkey.go` (was `policy_or.go`); `info` reports the same checks.

**Where** `cmd/keyfile.go:43` — `CheckSigningKeyFileMode` uses `os.Stat` and
compares `Perm()` with `0400`. Callers: `cmd/seal.go` (`Seal`),
`cmd/reseal.go` (`Reseal`).

**Problem.** A file owned by any user, reached through a symlink, in a
world-writable directory passes. That is what makes item 3 practical, and it
means an explicitly passed `--privkey` can be swapped by its owner between
check and use.

**Resolution.** In `CheckSigningKeyFileMode`:
1. `os.Lstat` first; refuse symlinks.
2. Require owner uid `0` or the effective uid (`syscall.Stat_t.Uid`), so
   tests running as a normal user keep working.
3. Require the parent directory to be not group- or world-writable and owned
   by the same uid set.
4. Keep the exact-0400 rule.
5. Close the check/use gap: open the file once, `fstat` the descriptor for
   the checks, and read the key from that same descriptor. That means
   `LoadSigningPrivateKey` / `LoadSigningPublicKeyFromPEM` get variants that
   take the checked content; do not stat by path and re-open by path.

**Done when** `cmd/keyfile_test.go` covers symlink, foreign owner (skip when
not root), writable parent and the happy path, and `info`'s
`printKeyFileModes` (`cmd/info.go:304`) reports the same conditions.

---

## 5. TOTP secret on the `qrencode` command line

- [x] done — built-in encoder (`rsc.io/qr`, BSD-3, pure Go); no external program is run any more.

**Where** `cmd/totp_utils.go:144` — `generateQRCode`:
`exec.LookPath("qrencode")` then `exec.Command(path, "-t", "ANSIUTF8", data)`
where `data` is the `otpauth://` URI containing the secret.

**Problem.** Command-line arguments are readable by every local user through
`/proc/<pid>/cmdline` while the process runs. Any unprivileged user polling
the process list during `seal` gets the TOTP secret. The binary is also
resolved through `PATH`.

**Resolution (preferred).** Drop the subprocess: render the QR code in the
binary with a pure-Go encoder (for example `rsc.io/qr` or
`github.com/skip2/go-qrcode`, both cgo-free) and print it with UTF-8 half
blocks. This removes the optional `qrencode` dependency from
`packaging/aur/PKGBUILD` and the "install qrencode" hints in
`displayTOTPQRCode`. Check the licence is compatible with BSD-3 and add the
module through `go.mod` normally.

**Fallback** if a new dependency is rejected: keep `qrencode` but pass the URI
on stdin (`qrencode -t ANSIUTF8` reads stdin when no string is given), and
look the binary up only in `/usr/bin` and `/bin`.

**Done when** no code path places the secret in an argv, and a unit test
asserts the QR output for a fixed URI is non-empty.

---

## 6. YubiKey PIN in a world-readable file

- [x] done — the PIN lives in `/etc/tpm2-kira/control.conf`
  (`TPM2_KIRA_PIN`), the one file `control` writes: the Signing key step
  checks the PIN on the token, writes the line and makes the file 0600.
  `readPIN` (`cmd/yubikey.go`) reads the environment, then the file, then
  the terminal; a file that is not root's or is group/world-readable is
  refused on the opened descriptor, not warned about (`configPIN`,
  `cmd/control_config.go`). The initramfs hooks copy the file without the
  PIN line. The old place, a line in `/etc/mkinitcpio.conf`, is gone with
  its parser.

**Trade-off** (`docs/PLAN-YUBIKEY.md` §4.4 and §6): an unattended PIN
makes the token a presence check only; the touch policy decides whether a
reseal needs a hand on the key.

**Done when** `readPIN` never returns a PIN from a group/world-readable or
non-root-owned file, with tests for each refusal (`cmd/yubikey_test.go`
`TestPINFromControlConf`).

---

## 7. TPM parameters in cleartext on the bus

- [x] done — after item 14 only step 3 remained: `CreateTOTPKey` sends the key in a session salted with the primary key, with parameter encryption. Steps 2 and 4 are obsolete (no unseal); step 5 is documented in SECURITY-BACKGROUND §8.

**Check item 14 first.** If the HMAC moves into the TPM, only step 3 below
(encrypting the key on its way in at `seal`) is still needed.

**Where**
- `cmd/policy_or.go:580` `UnsealWithPCRBranch`, `:663`
  `UnsealWithSignedBranch` — `tpm2.Policy(tpm2.TPMAlgSHA256, 16, callback)`
  with no encryption option; `Unseal` returns the secret in the clear
- `cmd/policy_or.go:999` `CreateSealedObjectPolicyOR` — the secret goes in as
  `InSensitive` in the clear (`tpm2.PasswordAuth(nil)` on the parent)
- `cmd/scan.go:451` `RunCommand` — unseals every 30 s for as long as the
  passphrase prompt is up

**Problem.** On a discrete TPM a passive probe on the LPC/SPI bus reads the
TOTP secret from the first unseal. SECURITY-BACKGROUND §8 lists this as
unmitigated; passive sniffing is cheap to stop.

**Resolution.**
1. Have `CreatePrimaryKey` (`cmd/tpm_utils.go:187`) also return
   `OutPublic`. The primary is a restricted decrypt ECC key, so it can salt a
   session.
2. Unseal: add `tpm2.Salted(primary.ObjectHandle, primaryPublic)` and
   `tpm2.AESEncryption(128, tpm2.EncryptOut)` to both `tpm2.Policy(...)`
   calls. Check against the pinned go-tpm version in `go.mod` that policy
   sessions accept these options together with the callback form.
3. Create: authorise the parent with a salted HMAC session with
   `tpm2.EncryptIn` instead of `PasswordAuth(nil)` so the sensitive data is
   encrypted on the way in.
4. Reduce exposure in `RunCommand`: unseal once, keep the secret in the
   process, and re-check the policy each window without releasing the secret
   again (a PCR read compared against the blob is enough for the display to
   notice a change). Once item 2 lands the process ends at the cap anyway.
5. State the limit in SECURITY-BACKGROUND: the salt key's public area is not
   authenticated, so an *active* interposer can still substitute it. Pinning
   the primary's name in the blob (signed region) and comparing after
   `CreatePrimary` narrows that; do it if a blob bump is happening anyway.

**Done when** the swtpm integration suite passes with encrypted sessions and
a test asserts the option set on the unseal session (or inspects the swtpm
command log for the encrypt attribute).

---

## 8. Raw `/dev/tpm0` default and global flush

- [x] done — `OpenTPM` in `cmd/tpm_utils.go`. Deviation: `CleanupTPM` is kept for unmanaged paths (raw device, swtpm socket) where the raw device admits one opener, so it cannot hit another program's handles.

**Where**
- `main.go:34` — `--tpm` default `/dev/tpm0`
- `cmd/tpm_utils.go:14` `CleanupTPM`, called from `cmd/scan.go` (`RevealCommand`,
  `RunCommand`, `ScanNVRAMSlotsRange` before every slot), `cmd/seal.go`,
  `cmd/reseal.go`
- `initramfs/systemd/tpm2-kira.service` — `Requires=/After=dev-tpm0.device`
- `initramfs/initramfs-tools/scripts/init-premount/tpm2-kira` — waits for
  `/dev/tpmrm0`, then runs a binary that opens `/dev/tpm0`

**Problem.** The raw device bypasses the kernel resource manager, and
`CleanupTPM` flushes *every* loaded session and transient object, including
ones that belong to other software. During boot that races with anything
else using the TPM before unlock (systemd-cryptsetup with TPM2 tokens,
systemd-pcrextend). The Debian script and the binary also disagree on the
device.

**Resolution.**
1. Default `--tpm` to `/dev/tpmrm0`; fall back to `/dev/tpm0` only when
   `tpmrm0` does not exist, and say so in `--debug`.
2. Stop flushing handles tpm2-kira did not create. Every object and session
   the code creates already has a matching `FlushHandle`/session cleanup;
   audit for leaks (`grep -n "CreatePrimaryKey\|PolicySession\|LoadExternal"`)
   and then delete `CleanupTPM`, `flushAllTransientHandles` and
   `flushAllSessions`. If the raw-device fallback needs it, keep it for that
   path only.
3. Change the unit to `dev-tpmrm0.device` and update README "Global Options",
   the usage text in `main.go`, and the `/dev/tpm0` mentions in
   SECURITY-BACKGROUND §8.

**Done when** integration tests pass (the swtpm harness passes `--tpm`
explicitly; confirm) and no code path issues `FlushContext` for a handle it
did not obtain itself.

---

## 9. `info` trusts unverified blob contents

- [x] done — `info --privkey`; `quoteUntrusted` in `cmd/untrusted.go`, also used for blob strings in reseal, scan, nvram and `PCRSpecsToString`.

**Where** `cmd/info.go`:
- `:200` prints `AppVersion`; `:265`, `:276`, `:325` print key paths; `:336`,
  `:338` print measure-point strings; the eventlog path and timestamp nearby —
  all straight from the blob with `%s`
- `:260` `printSigningKeyInfo`, `:288` `printSigningKeyLocation` open and
  parse whatever files the blob's paths name
- `initramfs/initramfs-tools/post-update.d/tpm2-kira` runs `info --json` as
  root after every initramfs rebuild

**Problem.** The blob is attacker-writable (SECURITY-BACKGROUND §9.4) and
`info` never checks its signature. Blob strings can carry terminal escape
sequences, and root opens attacker-named paths.

**Resolution.**
1. Verify first, with the same key resolution as item 3 (default key or
   `--privkey`). Print a clear first line: `Signature: valid (key …)` or
   `Signature: NOT VERIFIED — fields below are untrusted`. In JSON add
   `"signature_verified": true|false`.
2. When unverified: do not open any path from the blob.
3. Always print blob-derived strings through one helper that replaces
   non-printable bytes (`strconv.Quote`-style). JSON output is already
   escaped by `encoding/json`.
4. Also route the UKI path printed by `reseal` (`cmd/reseal.go:438`,
   `spec.Command`) through the helper.

**Done when** a test feeds a blob whose `AppVersion` and paths contain
`\x1b[2J` and a path to a nonexistent file, and asserts no escape byte in the
output and no file open on the unverified path.

---

## 10. Fuzz target for the blob parser

- [x] done — `cmd/fuzz_test.go`, `internal/pcsc/fuzz_test.go`, `make fuzz`, CI step. The pcsc decoders need their fixed wire size, which every caller guarantees with `io.ReadFull`; the target pads accordingly.

**Where** `cmd/blob.go` — `UnmarshalSealedBlob`, `UnmarshalPayload`,
`PeekBlobVersion`. No `func Fuzz…` exists in the repo.

**Problem.** This parser runs as root in the initrd on data anyone with TPM
access can replace. A 40 s ad-hoc fuzz run (about 1M executions) found no
panic, but nothing keeps it that way.

**Resolution.** Add `cmd/blob_fuzz_test.go` with the `unit || !integration`
build constraint used by `cmd/cmd_test.go`:

```go
func FuzzUnmarshalSealedBlob(f *testing.F) {
	sb := &SealedBlob{Version: CurrentBlobVersion, Payload: SealedBlobPayload{
		AppVersion: "x", Public: []byte{1, 2}, Private: []byte{3},
		PCRDigests:         []PCRDigestPair{{Index: 7, Source: PCRSourceUKI, Command: "/boot/x.efi"}},
		SignedBranchDigest: make([]byte, 32), PublicKeyPath: "/a", PrivateKeyPath: "/b",
		EventlogInfo: &EventlogInfo{EventlogPath: "/p"}}}
	if b, err := sb.Marshal(); err == nil {
		f.Add(append(b, 2, 0, 1, 2))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := UnmarshalSealedBlob(data)
		if err != nil {
			return
		}
		b.GetHashAlgo()
		PcrsToBitmapBytes(b.GetPCRIndices())
		b.GetPCRSpecs()
		_, _ = b.MarshalJSON()
		PeekBlobVersion(data)
	})
}
```

Add equivalent targets for `ParseYubiKeyStub` (`cmd/yubikey.go:59`), the
event-log parser (`cmd/eventlog_utils.go`) and the pcsc wire decoder
(`internal/pcsc/wire.go`). Add a `make fuzz` target (30 s each) and a short
fuzz step to `.github/workflows/unit-tests.yml`.

**Done when** `go test ./cmd -run '^$' -fuzz FuzzUnmarshalSealedBlob -fuzztime 30s`
passes locally and in CI.

---

## 11. `nvram delete` wipes every slot without asking

- [x] done — `--yes`, or typing 'yes' on a terminal. The owner-auth follow-up remains an OWNER DECISION.

**Where** `cmd/nvram.go:540` `NVRAMDeleteCommand`; `main.go` `runNVRAM`.

**Problem.** `tpm2-kira nvram delete` with no `--nvram` deletes all populated
slots immediately. Deletion is irreversible and forces re-enrolment. (That
anyone with TPM access can undefine the index through the owner hierarchy is
a TPM property and already documented in SECURITY-BACKGROUND §9.3; it cannot
be fixed here without owner-auth support.)

**Resolution.** Require `--yes` for the all-slots form; without it, list what
would be deleted and report FAILED with the hint. On a terminal, ask instead.
Single-slot delete with an explicit `--nvram` stays as it is. Update README
"Deleting Sealed Data" and "Uninstall".

**Optional follow-up, OWNER DECISION:** support an owner-hierarchy password
(`TPM2_KIRA_OWNER_AUTH` or a prompt) for `CreatePrimary`, `NV_DefineSpace`
and `NV_UndefineSpace`, so users who set one can keep using the tool and
close the delete/plant path.

---

## 12. Document the clock pre-recording attack

- [x] done — SECURITY-BACKGROUND §8 and README "How it works at boot".

**Where** `docs/SECURITY-BACKGROUND.md` §8 "What the TPM does NOT protect
against"; `README.md` near "How it works at boot".

**Problem.** The code is `HOTP(secret, time/30)` and the time comes from the
RTC, which is neither measured nor protected. An attacker boots the
untouched machine with the clock set to the moment the owner is expected to
boot next, records the codes shown, then tampers with the boot chain and
replays the recorded codes at the right time. The codes match the owner's
authenticator. Nothing in the docs mentions it.

**Resolution.** Add the row to the threat table with what narrows it: a
firmware setup password, a locked boot order, Secure Boot (so another OS
cannot be booted to set the clock), and noticing unexpected RTC drift. State
that it is inherent to time-based codes and that only a counter- or
challenge-based scheme removes it. No code change. If the owner wants a
detection aid later: store a monotonic "highest time seen" in a
PolicySigned-written NV index from the running OS and have `run` flag a clock
that is behind it — that catches a rollback after a harvest, not the harvest.

---

## 13. Sandbox the initrd unit

- [ ] done — not started: needs verifying in a real systemd initrd, which the review machine (TPM 1.2) cannot do

**Where** `initramfs/systemd/tpm2-kira.service`.

**Problem.** The service runs as full root before unlock and parses
untrusted NV data. The parser is memory-safe Go and held up under fuzzing, so
this is defence in depth only.

**Resolution.** Add, and verify each in a real mkinitcpio systemd initrd
(some directives need mounts that may not exist there — drop any that break
startup rather than shipping a unit that fails):

```ini
ExecStart=/usr/bin/tpm2-kira run
NoNewPrivileges=yes
CapabilityBoundingSet=
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
DeviceAllow=/dev/console rw
RestrictAddressFamilies=none
SystemCallFilter=@system-service
MemoryDenyWriteExecute=yes
```

`DeviceAllow` must match the device chosen in item 8. For the Debian script
there is no equivalent; leave it.

---

## 14. Compute the HMAC inside the TPM; authorise PCR states by signature

- [x] done — blob v9 (`cmd/totpkey.go`); with revocation (owner decision). Without SHA-1 the key falls back to HMAC-SHA256 with a notice and `algorithm=SHA256` in the URI (owner decision). Integration tests: `TestCodeMatchesAuthenticator`, `TestResealRevokesOldBlob`, `TestCompleteWorkflow` (reseal after a PCR change).

**Where**
- `cmd/policy_or.go:999` `CreateSealedObjectPolicyOR` — the TOTP key is
  stored as *sealed data* (`TPMAlgKeyedHash`, no `SignEncrypt`)
- `cmd/policy_or.go:580` / `:663` — `TPM2_Unseal` hands the key to the process
- `cmd/scan.go:152` `ScanNVRAMSlotsRange` — keeps it in `NVRAMSlot.Secret`;
  `cmd/totp_utils.go` `generateTOTPCode` / `generateHOTP` do the HMAC in Go
- `cmd/reseal.go` `Reseal` — unseals the key and creates a new object for the
  new PCR values
- `cmd/seal.go` `generateTOTPSecret` — seals the *base32 text* of 32 random
  bytes, not the raw key

**Problem.** A TOTP code is `Truncate(HMAC-SHA1(key, time/30))`. Because
tpm2-kira does the HMAC itself, the TPM must release the whole key on every
use, and it releases it to anyone who presents matching PCRs. Whoever gets it
once has it forever (see items 1, 2, 7 for the ways). The TPM can do the HMAC
instead, so the key never leaves the chip.

**What it buys, and what it does not.** The key becomes non-extractable: not
by root, not from another OS, not from the bus. An attacker with matching
PCRs can still ask the TPM for the code of *any* time value, so they can
precompute codes for a future window. Theft changes from "the key, forever"
to "a list of codes, needing renewed access". Items 1 and 2 are still needed
to stop the oracle itself. Put exactly this in SECURITY-BACKGROUND §8.

**Resolution.**

*A. HMAC key object*
1. Create the object as an HMAC key: `Type: TPMAlgKeyedHash`, attributes
   `FixedTPM`, `FixedParent`, `SignEncrypt` set; `UserWithAuth` and
   `SensitiveDataOrigin` clear (tpm2-kira supplies the key so it can show the
   QR code once); scheme `TPMAlgHMAC` with `TPMAlgSHA1`. Put the **raw** key
   bytes in `InSensitive.Data`. Use 20 random bytes (the RFC 4226 size; a
   keyedHash key may not exceed the hash block size). The QR code carries the
   base32 of those same bytes.
2. Each code: `TPM2_HMAC(handle, 8-byte big-endian counter, SHA1)` authorised
   by the policy session; truncate the 20-byte result with the existing
   dynamic-truncation code. Remove `NVRAMSlot.Secret` and every path that
   holds the key after `seal`. `RunCommand` calls the TPM once per window,
   which it effectively does already.
3. Before sealing, check `TPM2_GetCapability` for `TPM_CC_HMAC` and a SHA-1
   HMAC. Some TPMs ship without SHA-1. **OWNER DECISION** for that case:
   refuse, or fall back to HMAC-SHA256 with `algorithm=SHA256` in the
   `otpauth://` URI (not every authenticator app honours it).
4. `seal` still handles the key once in process memory and sends it to the
   TPM in `TPM2_Create`; encrypt that parameter (item 7 step 3). Item 7
   step 2 and 4 (unseal encryption, unseal-once) become obsolete — the HMAC
   result on the bus is not secret.

*B. PolicyAuthorize instead of PolicyOR*

With a non-extractable key, `reseal` cannot re-create the object for new PCR
values. Replace the object's fixed policy with one that trusts the signing
key to approve PCR states:

5. Object `AuthPolicy` = digest of `PolicyAuthorize(keyName, policyRef)` for
   the signing public key. It never changes for the life of the object.
6. The blob stores: the signing public key (needed in the initrd, where the
   key files are not available), the PCR selection and digests as today, and
   a signature by the signing key over
   `H(approvedPolicy || policyRef)`, where `approvedPolicy` is the PolicyPCR
   digest for those values. Add proper typed fields; bump
   `CurrentBlobVersion`; drop `SignedBranchDigest`.
7. Use at boot: start a policy session; `PolicyPCR` (live registers);
   `LoadExternal` the public key; `TPM2_VerifySignature` to get a ticket;
   `PolicyAuthorize(approvedPolicy, policyRef, keyName, ticket)`; then
   `TPM2_HMAC`. No private key and no token involved.
   Gotcha: load the public key into the **owner** hierarchy
   (`LoadExternal{Hierarchy: TPMRHOwner}`), not the NULL hierarchy the
   current `LoadExternalPublicKey` uses — a ticket from a NULL-hierarchy key
   may not be accepted by `PolicyAuthorize` (tpm2-tools examples load with
   `-C o` for this reason). Not verified here; confirm on swtpm first.
8. `reseal` becomes: read PCR values for the next boot (unchanged logic),
   compute the PolicyPCR digest, sign it, write the blob. It never touches
   the key object and never unseals anything. `UnsealWithSignedBranch`,
   `UnsealWithSignedBranchFromBlob` and the PolicyOR code go away. The NV
   write stays PolicySigned as it is.
9. The planted-blob analysis changes and must be re-stated in
   SECURITY-BACKGROUND §9: a planted blob can still only carry an object the
   attacker created (their key, their `AuthPolicy`), so its codes do not match
   the owner's authenticator. A blob that re-uses the owner's object with a
   different approved policy needs the owner's signature.

*C. Revocation of old approvals* — **OWNER DECISION**: first version or later

10. Without revocation, every PCR state ever signed stays valid for the
    object: an attacker who kept an old blob can roll the machine back to an
    old kernel/initrd and get codes. To revoke: keep a generation number in a
    second NV index defined exactly like the blob index (PolicySigned write,
    open read) and make the approved policy `PolicyPCR` **then**
    `PolicyNV(genIndex == G)`. `reseal` writes `G+1` and signs the policy for
    `G+1`. Deleting and re-creating the index does not help an attacker:
    `PolicyNV` binds the index *Name*, which includes its attributes and
    write policy, so a look-alike must have the same PolicySigned write
    policy and then cannot be written without the key.

*D. Migration*

11. No migration path (ground rules). Old blobs produce the existing
    "incompatible blob version … seal again" message. Record the format
    change and the reason in `HISTORY.md`; rewrite SECURITY-BACKGROUND §3–6
    and §10, README "How It Works".

**Done when**
- swtpm integration test: `seal` with a known key, `reveal` matches
  `generateHOTP` computed in the test for the same counter; `reseal` after a
  PCR change works with the signing key and without any unseal; a blob whose
  approval signature is from another key yields no code.
- `grep -rn "tpm2.Unseal" cmd/` finds nothing outside tests.
- No struct or variable holds the TOTP key after `Seal` returns.
- If C is in scope: an old blob stops producing codes after one `reseal`.

---

## Checked and found sound — do not redo

- **Blob parser bounds**: every length field is capped (`cmd/blob.go:183`
  constants); fuzzing found no panic.
- **Boot display and planted blobs**: `PrintKIRASlots` (`cmd/scan.go`) prints
  only integers and hex from the blob, so a planted blob cannot inject
  terminal escapes into the pre-unlock console. A planted blob can only show
  codes for a secret the attacker chose, which do not match the owner's
  authenticator.
- **Policy enforcement** is in the TPM: `UserWithAuth` is unset on the sealed
  object, `PolicyPCR` is issued without a caller digest, trial sessions are
  only used to compute digests. The software PCR comparison in
  `UnsealWorkflow` is advisory.
- **NV writes** need a PolicySigned session per chunk; `OwnerWrite` and
  `AuthWrite` are clear. `WriteToNVRAM` exercises the signer before the
  undefine and stashes the blob on failure.
- **No command execution from blob data**: the `p:COMMAND` source is gone
  (HISTORY.md), and since item 5 tpm2-kira runs no external program at all.
- **PIN retry handling** (`cmd/yubikey.go` `ensurePIN`): one VERIFY per need,
  never retries a rejected PIN, refuses to spend the last attempt, resets the
  card on exit.
- **Policy failures do not feed TPM dictionary-attack lockout**, so the
  30-second retry loop on a mismatching machine does not lock the TPM.
