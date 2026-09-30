# History

Design decisions and removed features that used to be recorded as comments in
the source. Kept here so the code states what it *is*, not what it *was*.

Development mode: no backwards compatibility is maintained. Blobs, on-disk
formats and CLI flags may change without migration paths.

---

## Layout

### cmd/ became internal/kira/

The application lived in a package named `cmd`, imported by `main.go` at the
repository root. In Go, `cmd/` conventionally holds *main* packages — one
directory per binary — so a library package with that name reads as a binary
directory that is not one, and it left `internal/` looking like the place a few
things had been moved out to rather than where the code lives.

`main.go` stays at the root and does what a command does: parse flags and
dispatch. Everything else is under `internal/`, which also makes it
non-importable from outside the module.

The boundary inside `internal/` is by subsystem, not by layer. `pcsc`, `piv` and
`virtualpiv` earn their own packages by being self-contained: each has its own
vocabulary, depends on nothing else in the project, and is unit-testable alone.
The rest is one `kira` package because the verbs and the mechanism they drive
share a vocabulary — PCR specs, the blob, TPM handles — and because output is
interleaved with logic throughout. Splitting those by layer would need either a
shared types package or the extraction of printing from nearly every file, for
less benefit than it cost. The README states the rule so new files land in the
right place.

---

## Commands

### The failure marker no longer restates the exit status

Failures printed a second line, `(exit status is 0 by design; this command did
NOT succeed)`, after every `FAILED:` message. It was noise on every error, and it
explained a design decision to the wrong audience: a script cannot act on it, and
a person reading one error does not need the rationale repeated. The reasoning
now lives next to the code that exits, and in the README's "Exit status" section.
`tpm2-kira: FAILED:` remains the marker to grep for, and the exit status is still
always 0.

### Opening the TPM requires root, and the check lives at the device

The first version of this exempted the read-only commands — `reveal`, `info`,
`nvram list` and friends — on the grounds that a udev rule could grant a group
access to `/dev/tpm0`, and the error message offered that as an alternative to
`sudo`.

That was wrong, and it contradicted the project's own threat model: §8 already
places non-root userspace outside the trust boundary precisely because *anything*
that can open the TPM device can ask the TPM to unseal while the PCRs still match.
Reading the sealed secret is the capability the boundary protects, so there is no
read-only tier to exempt, and suggesting a udev rule was advice to move the
boundary rather than to work within it.

The replacement keyed the requirement off the **command name**, which was also
wrong and broke more visibly: the integration suite drives a software TPM over a
unix socket that the test user owns and which needs no privilege whatsoever, so
every test failed for a non-root user. The container the suite normally runs in is
root, which hid it.

The check now lives where the requirement actually comes from — the moment the
device is opened. A character device is refused for a non-root user; a socket, or
a path that is not there, is left to the open attempt. That is simultaneously
stricter about `/dev/tpm0`, which no command can now reach without root, and
permissive about software TPMs, which never needed it. `setup` keeps an up-front
requirement because it writes under `/var/lib/tpm2-kira` whatever its TPM path is.

The container test runner gained an unprivileged pass, since running everything as
root is what allowed a root-only assumption to go unnoticed.

### The signing key is created 0400, and a looser mode is reported

`setup` used to write the private key 0600. It is now 0400: the file is written
once and only ever read, so dropping the write bit costs nothing and takes an
accidental overwrite off the table.

Whenever the key is opened for signing — seal, reseal, nvram restore — the mode
is checked. Group or other access is a warning naming the risk and the fix,
because that mode is the key's only protection on disk and a readable key undoes
the PCR policy for whoever can read it. Owner-writable but otherwise private
(0600) is a one-line note, since it exposes the key to nobody. The recommended
mode says nothing at all.

It warns rather than refuses. A reseal is what someone reaches for when their
machine has stopped showing a code, and declining to use a working key at that
moment would be worse than the exposure it is warning about. It also warns once
per file per run, since a reseal with no --nvram opens the key once per populated
slot.

### seal guides the PCR selection when none is given

`tpm2-kira seal` with no `--pcrs`, run from a terminal, now profiles the machine
and suggests a selection instead of silently applying `0,2,7`. It reports the
Secure Boot state, whether the event log carries SHA-256 digests, whether a
unified kernel image or GRUB is present, and which NVRAM slots are already in use.

The recommendation depends on those facts rather than being fixed advice. With
Secure Boot verifying the boot chain, PCRs 0 and 7 are enough and survive kernel
updates. With Secure Boot off — or in Setup Mode, or unreadable — nothing
verifies which kernel runs, so the suggestion adds whatever this system measures
the boot components with: `11u` for a unified kernel image, `8,9` for GRUB, `4`
otherwise. Each of those needs resealing on updates, and the suggestion says so,
including the rule that a GRUB reseal has to follow the reboot rather than
precede it.

An explicit `--pcrs` skips the whole thing and is used exactly as written, and so
does running without a terminal, which keeps the default for hooks and scripts.
Typing a selection at the prompt is validated before anything is sealed, so a
typo is a question rather than a policy bound to the wrong registers.

### setup no longer seals

`tpm2-kira setup` used to create the signing key **and** seal a TOTP secret
against PCRs 0 and 7. It now stops after the key and prints the `seal` command to
run next.

The two acts are different in kind. Creating a key is cheap, local and
repeatable. Sealing mints a secret that has to be enrolled in an authenticator,
writes to TPM NVRAM, and is where the PCR selection is chosen — so it is the step
someone is most likely to want to redo with different arguments, and the one whose
failure matters. Combining them meant `setup` could not be re-run to reason about
keys alone, and that a key-related question was answered in the same breath as a
policy one.

It also removed a PIN from the flow: setup reads a token's public key, which needs
no PIN, and now performs no signature, so `--pin-file` is gone from it.

Nothing automated ever called `setup` — the initramfs hooks and the Debian
postinst only ever advised a human to run it — so the split broke no callers. The
mkinitcpio post hook did gain a case: signing keys can now exist with nothing
sealed, which used to be impossible, and it reports that as a skip rather than a
failed reseal.

---

## Blob format

### Version 9 — key references instead of key paths

`PublicKeyPath` and `PrivateKeyPath` were plain strings holding filesystem
paths. A signing key can now live in a YubiKey PIV slot, which a path cannot
name, so both became typed `KeyRef` values carrying a kind byte alongside a
canonical string (`yubikey:serial=12345678;slot=9a`). The two encode the same
fact and are cross-checked on read; a blob whose kind byte contradicts its
string is rejected rather than resolved one way or the other.

The string alone would have been enough to distinguish the cases — a filesystem
path cannot begin with `yubikey:` — and reusing the v8 field would have avoided
forcing everyone to re-seal. The bump was taken deliberately instead: the
project maintains no backwards compatibility, and a field documented as a path
that sometimes holds a URI is the kind of thing that is correct for exactly as
long as nobody looks at it.

Added in the same version: `KeyFingerprint` (SHA-256 of the signing key's PKIX
DER) and `TokenSerial`. They identify the signing key without being usable as
one, so `reseal` can say "the key in slot 9a is not the one this slot was sealed
against" instead of failing as an opaque TPM policy error, and `info` can
describe the key with the token unplugged.

The public key itself is still **not** stored, for the same reason it was
dropped in v5: a blob carrying its own verification key is a circular trust
anchor, since a planted blob would carry a matching one.

The **PIN** is deliberately not stored either. NVRAM reads are open, so anything
in the blob is readable by any process that can reach the TPM and by anyone who
takes the disk — publishing the PIN to exactly the attacker the token defends
against.

### Version 8 — dropped the unverified eventlog hash

`EventlogInfo.EventlogHash` stored a SHA-256 of the event log file and was
documented as being "for verification". Nothing ever read it. It could not have
been a useful check either: the event log differs on every boot, so comparing a
seal-time hash against the current one would fail on any legitimate reboot. It
added nothing to blob integrity, since the whole payload is already covered by
the blob signature. Removed along with `MaxEventlogHash`.

`EventlogInfo.EventlogPath` is retained for provenance only. It is **never**
reopened from the blob — reads always go through `DefaultEventlogPath` — and it
must stay that way, since honouring a blob-supplied path would turn a stored
string into a file-access vector.

### Version 7 — UKI source, measure-point metadata

- Added the `u` PCR source (unified kernel image) and the `EventlogInfo` fields
  `measure_point_extends` / `measure_point_detection`.
- **Removed the external predict source (`p:COMMAND`).** The blob used to store
  a command string that `reseal` executed, so a planted blob meant arbitrary
  code execution as root — `docs/pentest2/vulnerabilities/vuln-0001.md`.
  PCR 11 is now computed in-process from the image (`internal/kira/ukipredict.go`).
- Blob `PCRSource` byte **2** is retired and must not be reused; it identified
  the predict source. 0 = register, 1 = eventlog, 3 = uki.
- `ParsePCRSpecs` carried an explicit rejection of the `p:` suffix with a
  migration hint. Removed: the syntax now fails as an invalid PCR value.

### Version 6 — signed payload envelope

- Introduced `SealedBlobPayload` and the detached blob signature. Layout became
  `[version:4][payloadLen:4][appVersionLen:4][appVersion...]`.
- Earlier blobs used `[version:4][appVersionLen:4][appVersion...]`, with no
  payload-length field. `PeekBlobVersion` kept a branch to read that older
  layout for diagnostics; removed, as pre-v6 blobs are no longer supported.

### Version 5 — signed branch digest

- Replaced the `SigningKeyPEM` field from version 4 with the 32-byte
  `SignedBranchDigest`. The public key is no longer stored in the blob: it is
  loaded from the filesystem or derived from the private key when needed.
- Consequences still visible in the code: `reseal` and the PolicySigned unseal
  path require a key source on the filesystem, because the blob cannot supply
  one.

---

## NVRAM index definition

The NV index holding the blob was originally defined with `OwnerWrite: true`
and `AuthWrite: true` and an empty `AuthPolicy`, which let any process with
`/dev/tpm0` access overwrite the sealed blob without credentials.

Current definition, and why each attribute is set that way:

| Attribute | Then | Now | Reason |
|---|---|---|---|
| `OwnerWrite` | true | false | prevents owner-hierarchy bypass of the policy |
| `AuthWrite` | true | false | removes the unauthenticated write path |
| `PolicyWrite` | unset | true | requires a policy session for writes |
| `AuthPolicy` | empty | PolicySigned digest | binds writes to the signing key |

Read attributes are deliberately unchanged: reading the raw blob is harmless,
since the TPM still protects the secret itself via the sealed object's policy.

`reseal` verifies the blob signature **before** acting on any field. The
original reason was to prevent execution of predict commands from a tampered
blob; that specific risk is gone with the predict source, but the ordering
requirement stands, because a tampered blob can still steer reseal through its
stored PCR specs and key paths.

---

## Removed functions

Deleted as unreferenced by production code and tests. Recorded here in case the
behaviour is ever wanted again.

| Function | Was in | Note |
|---|---|---|
| `CreateSealedObject` | `tpm_utils.go` | Superseded by `CreateSealedObjectPolicyOR`. Built the object with `UserWithAuth: true`, which would have permitted password/HMAC auth — contradicting the policy-only model in SECURITY-BACKGROUND.md §4.4. Do not resurrect without dropping that attribute. |
| `UnsealData` | `tpm_utils.go` | Pre-PolicyOR unseal path. Superseded by `UnsealWithPCRBranch` / `UnsealWithSignedBranch`. |
| `CreatePCRPolicySession` | `tpm_utils.go` | Only reachable from `UnsealData`. |
| `ComputePolicyDigest` | `tpm_utils.go` | Superseded by the PolicyOR digest computation in `policy_or.go`. |
| `RunPredictCommand` (whole file `predict_utils.go`) | — | Executed the blob-supplied predict command. Removed with the predict source. |
| `padBigInt` | `policy_or.go` | Never called. |
| `readRawEventLog` | `eventlog_utils.go` | No-argument wrapper; everything uses `readRawEventLogFromPath`. |
| `InfoWithFormat` | `info.go` | Thin wrapper over `InfoCommand`, kept as a "legacy entry point". This is a CLI binary, so there was no external consumer. |
| `ParsePCRs` | `pcr.go` | Convenience wrapper returning indices only. No production caller. |

---

## CLI output

### `info --json` always emits an array

`printJSON` used to special-case a single slot and emit a bare blob object,
switching to an array of `{slot_number, nvram_index, blob}` entries only when
more than one slot was populated. Consumers therefore had to branch on the
shape, and a script written against a one-slot machine broke as soon as a
second slot was sealed.

It now always emits the array form.

---

## Superseded tooling
| Removed | Replaced by |
|---|---|
| `calculate.py` | `tools/pcrtool.py replay` |
| `verify_os_separator.py` | `tools/pcrtool.py verify` |

`calculate.py` had two independent implementations of the same replay (all-PCR
and single-PCR), each with its own copy of the StartupLocality handling. It was
also SHA-256 only. Both scripts were verified to produce identical results to
the merged tool on a real event log before removal.

`tools/tpm2-pcr11predict` is intentionally retained — not as a fallback, but as
an *independent* cross-check of the built-in PCR 11 computation, using
`systemd-measure` instead of tpm2-kira's own implementation. That independence
is the point: see `docs/UKI-PCR11-PADDING.issue` for the bug it would have
caught.

---

## Related records

- `docs/SYSTEMD-PCROSSEPARATOR.issue` — systemd's userspace measure-point
  extends and the measure-point model.
- `docs/UKI-PCR11-PADDING.issue` — PCR 11 computed over padded PE sections.
- `docs/pentest1/`, `docs/pentest2/` — penetration test findings.
