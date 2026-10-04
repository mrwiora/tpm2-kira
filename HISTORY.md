# History

Design decisions and removed features that used to be recorded as comments in
the source. Kept here so the code states what it *is*, not what it *was*.

Development mode: no backwards compatibility is maintained. Blobs, on-disk
formats and CLI flags may change without migration paths.

---

## Blob format

### Version 9 — the TOTP key stays in the TPM; PolicyAuthorize replaces PolicyOR

Up to version 8 the blob held a *sealed* TOTP secret behind a PolicyOR: a PCR
branch for boot, and a PolicySigned branch for recovery. Every code meant a
`TPM2_Unseal`, so the secret crossed the TPM bus every 30 seconds, and anyone
who satisfied the PCR branch — root in the running system, or a shell in an
initrd booted with the sealed PCRs intact — could copy it out and produce
codes forever. `reseal` had to unseal it too, through the PolicySigned branch
when the PCRs had changed.

Version 9 creates the key as an HMAC key object; the TPM computes each code
with `TPM2_HMAC`, and the key is never returned. The object's policy is
PolicyAuthorize by the signing key, so `reseal` approves new PCR values by
signing instead of unsealing. Added with it:

- a per-slot **generation index** (`GenerationIndex`): the approved policy
  includes PolicyNV on it, and each reseal raises it, revoking every older
  approval;
- **`tpm2-kira cap`**, which read-locks the generation indices
  (`READ_STCLEAR`) when the initrd is left, so nothing can compute codes
  until the next reboot. A PCR cap was considered and rejected: PCR 23, the
  one free choice, can be reset from locality 0 by any process with TPM
  access;
- a random **policyRef** per key object, so approvals made for one object
  never fit another made with the same signing key.

Removed: `SignedBranchDigest`, the PolicyOR and unseal code, and
`generateTOTPSecret` (the secret used to be the base32 *text* of 32 random
bytes; the key is now the raw 20 bytes RFC 4226 recommends, or 32 bytes for
HMAC-SHA256 on a TPM without SHA-1). Blob indices are now limited to
`0x01803000–0x018037FF`; the range above holds the generation indices.

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
  PCR 11 is now computed in-process from the image (`cmd/ukipredict.go`).
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

## Signing key handling

### `reseal` no longer finds its key through the blob

`reseal` used to fall back to the `PrivateKeyPath` / `PublicKeyPath` stored in
the blob when no `--privkey` / `--pubkey` was given, and then verified the
blob's signature with the key it found there. Since anyone with TPM access can
delete and redefine the NV index, a planted blob could name its author's key
and pass its own check; the automatic reseal after an initramfs rebuild would
then report success instead of tampering. The key now comes from `--privkey`
or the default location only, and the stored paths are just compared after
verification (SECURITY-BACKGROUND §5.5). A slot sealed with a custom key needs
`--privkey` on every reseal.

`--pubkey` on reseal used to be described as the way to change the signing
key. It never worked: the policy was built from the new public key while the
NV write was signed with the old private key, so the TPM refused the write
after the old index had been undefined. A mismatched `--pubkey` is now refused
before anything is touched; changing the key means sealing again.

### Key files are checked on the descriptor they are read from

`CheckSigningKeyFileMode(path)` checked the mode with `stat` and the key was
then read by path. It is replaced by `ReadSigningKeyFile`, which also refuses
symlinks, foreign owners and writable directories, and returns the content of
the file it checked.

## Removed external tools

### `qrencode`

`seal` rendered the enrolment QR code by running `qrencode` with the
`otpauth://` URI, TOTP secret included, as a command-line argument — readable
by every local user through `/proc/<pid>/cmdline`. The code is now rendered
in-process with `rsc.io/qr`. tpm2-kira runs no external program any more.

## TPM device

The default device was `/dev/tpm0`, and every command flushed all loaded
sessions and transient objects first, including other programs' handles. The
default is now `/dev/tpmrm0`; the global flush runs only on the raw device or a
simulator socket, where no other program can hold handles at the same time.

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
