# PLAN-YUBIKEY.md — moving the signing key onto a YubiKey

Status: **proposal**. Nothing in here is implemented yet.
Branch: `feat/yubikey-support`.

Decisions already taken (§15 records the rest):

- **One binary.** No build-tag split, no second artifact. The PC/SC client is
  written in pure Go so `CGO_ENABLED=0` keeps working and the initramfs stays
  library-free.
- **Blob format bumps to v9.** Done. Typed key references, plus the key
  fingerprint and token serial, so everything needed to find and identify the
  signing key lives in the blob.
- **No separate configuration file.** There is no `reseal.conf`. The key
  reference is in the blob; the PIN is deliberately *not*, because NVRAM reads
  are open (see §9.1).
- **`TPM2_KIRA_PIN`** is the environment variable, matching the existing
  `TPM2_KIRA_INITRAMFS_MODE` convention.
- **A key file on disk stays the default.** The YubiKey is opt-in. `setup`
  with no flags generates a PEM pair exactly as it does today, `--privkey`
  without a scheme is still a path, and nothing about an existing installation
  changes.
- **The slot must already hold a key.** tpm2-kira never writes to the token —
  no key generation, no certificate writing, no management-key handling. This
  is what makes sharing a slot with sbctl work, and it roughly halves the PIV
  code.

---

## 1. Goal

Today the PolicySigned recovery key lives at `/var/lib/tpm2-kira/keys/seal.key`
as a PEM file on the encrypted root filesystem. The goal is to move it into a
YubiKey PIV slot, so that:

- the private key is **generated on the token and never exists off it**;
- using it requires the physical token **and** a PIN, supplied via
  `TPM2_KIRA_PIN`;
- the token is needed **only for `reseal`** (and `seal`/`setup`), never for
  `reveal`, `run`, `info` or anything that happens in the initramfs;
- when the token is absent, `reseal` **warns instead of failing hard**, and the
  user is told plainly that the next boot will show a PCR **MISMATCH** and no
  TOTP code.

---

## 2. What the private key is actually used for

Everything follows from this, so it is worth being exact. There are exactly
three places where private key material is touched, and all three are "sign one
32-byte SHA-256 digest":

| # | Call site | Purpose | Signature format |
|---|-----------|---------|------------------|
| 1 | `cmd/policy_or.go` → `signForTPM()` | `TPM2_PolicySigned` aHash, for recovery unseal | TPM-native: RSASSA blob, or ECDSA **raw r‖s** |
| 2 | `cmd/blob.go` → `SignBlobPayload()` | detached signature over the blob metadata | RSA PKCS#1 v1.5, or ECDSA **ASN.1 DER** |
| 3 | `cmd/nvram.go` → `WriteToNVRAM()` (per 1024-byte chunk) | `TPM2_PolicySigned` for the NV write policy | same as #1 (reuses `signForTPM`) |

A fourth use is **not** signing: `reseal` loads the private key merely to derive
the *public* key (`cmd/reseal.go:165`, `:257`) for blob signature verification
and for the new blob's PolicyOR digest. That needs no PIN and no token — it must
be served from a cached public key on disk.

Two consequences that shape the whole design:

- **`reseal` always needs the key, even when the PCRs still match.** Unsealing
  may succeed through the PCR branch, but writing the new blob back is gated by
  the NV index's PolicySigned write policy (SECURITY-BACKGROUND §9). There is no
  "PCRs matched, so no key needed" shortcut for reseal.
- **A reseal costs ~3 signatures per slot** (recovery unseal + blob signature +
  one NV write chunk). `reseal` with no `--nvram` walks every populated slot, so
  a 4-slot machine is ~12 signature operations in one run. PIN policy and touch
  policy must be chosen accordingly (§6).

---

## 3. Core abstraction: a signer, not a path

Right now a private key is a `string` path threaded through `Seal`, `Reseal`,
`sealDataWithSpecs`, `WriteToNVRAM` and `UnsealWithSignedBranch*`. The plan
replaces the *path* with a *resolved signer*, resolved once at the top of each
command.

```go
// cmd/signer.go  (new)

// KeyRef is a parsed reference to a signing key: a filesystem path, or a
// token slot. It is what the blob stores and what the CLI flags produce.
type KeyRef struct {
    Kind   KeyRefKind // KeyRefFile | KeyRefYubiKey
    Path   string     // KeyRefFile
    Serial uint32     // KeyRefYubiKey, 0 = any
    Slot   byte       // KeyRefYubiKey, e.g. 0x9A
}

// SigningKey is everything the rest of the code needs.
type SigningKey interface {
    crypto.Signer            // Public(), Sign(rand, digest, opts)
    Ref() KeyRef
    Close() error            // releases the card handle
}

// OpenSigningKey resolves a KeyRef into a usable key, or returns a typed
// ErrKeyUnavailable that callers can degrade on instead of failing.
func OpenSigningKey(ref KeyRef, pin PINSource, debug bool) (SigningKey, error)
```

Refactor surface (mechanical; no behaviour change on the file-backed path):

- `signForTPM(privKey crypto.Signer, digest []byte)` type-switches on
  `*rsa.PrivateKey` / `*ecdsa.PrivateKey` and reads `r`, `s` as big.Ints. A
  token-backed signer is neither. **It must switch on the *public* key type and
  call `Sign()`, then parse the ECDSA ASN.1 DER back into r/s** and left-pad to
  the curve length. This is the most error-prone change in the plan; it gets a
  known-answer test (§11).
- `SignBlobPayload` likewise: switch on `privKey.Public()`, call `Sign()`. For
  ECDSA the output is already ASN.1 DER, which is what the current code
  produces, so `VerifyBlobSignature` is unchanged.
- `verifyKeyPairMatch` compares concrete private keys; it becomes a comparison
  of `signer.Public()` against the loaded public key.
- `Seal`, `Reseal`, `sealDataWithSpecs`, `WriteToNVRAM`,
  `UnsealWithSignedBranch`, `UnsealWithSignedBranchFromBlob` take a
  `SigningKey` (or `nil`) instead of a `privKeyPath string`.

The file backend is then just `LoadSigningPrivateKeyFromPEM` behind the same
interface, and the existing test suite covers it unchanged.

---

## 4. Talking to the card without cgo

This is the part with real engineering risk, so it is specified in more detail
than the rest.

### 4.1 Why not the obvious library

`github.com/go-piv/piv-go/v2/piv` is the standard answer and it is ruled out:
it binds `libpcsclite` through cgo. `debian/rules` sets `CGO_ENABLED=0`, and
the initramfs is promised to need no libraries. One binary means no cgo.

### 4.2 Transport: a pure-Go pcscd client

New package `internal/pcsc`. It speaks pcsc-lite's Unix-socket protocol
directly, the same protocol `libpcsclite` implements:

| Step | Message |
|---|---|
| connect | `/run/pcscd/pcscd.comm` (fall back to `/var/run/pcscd/pcscd.comm`) |
| negotiate | `CMD_VERSION` — send our major/minor, read the daemon's back |
| enumerate | `CMD_GET_READERS_STATE` — reader names and card presence |
| session | `SCARD_ESTABLISH_CONTEXT` → `SCARD_CONNECT` (T=1, shared mode) |
| exchange | `SCARD_TRANSMIT` — one APDU in, one response out |
| teardown | `SCARD_DISCONNECT` → `SCARD_RELEASE_CONTEXT` |

Choosing pcscd over driving USB ourselves is deliberate: pcscd exists precisely
so several processes can share a reader, and on a desktop something else
(gpg-agent, a browser, `ykman`) usually holds it already. Bypassing it would
mean fighting for an exclusive USB claim.

**The risk is struct layout.** These messages are C structs with native
alignment, and the layout differs between pcsc-lite protocol versions and
between 32- and 64-bit builds. Mitigations, all of which belong in the code
rather than the docs:

- Negotiate the version first and **refuse loudly on an unknown protocol
  version** rather than guessing. A wrong guess here is silent corruption in
  the recovery path, which is the worst possible place for it.
- Keep every wire struct in one file, with explicit sizes and a comment citing
  the pcsc-lite header it mirrors, so a future version bump is one file to
  review.
- Encode a compile-time-checked size for each struct, and unit-test the
  encoders against golden byte vectors captured from a real daemon.
- Record tested pcsc-lite versions in the docs, and make the error message name
  the version we saw.

If pcscd is not running, the error is explicit ("no PC/SC daemon at
/run/pcscd/pcscd.comm — start pcscd, or use a file-backed key"), never a
silent fallback.

**Escape hatch, not in scope now:** a direct `usbfs` + CCID transport
(`/dev/bus/usb/*` with `USBDEVFS_*` ioctls) is also pure Go and needs no
daemon, but it must claim the USB interface exclusively and so conflicts with a
running pcscd. Worth keeping as a documented fallback for minimal systems;
not worth building until someone needs it.

### 4.3 Applet layer: PIV, strictly read-and-sign

New package `internal/piv` on top of the transport. **tpm2-kira never writes to
the token.** The slot must already hold a key; if it does not, the command says
so and stops. Four APDUs are all that is needed:

| APDU | Purpose |
|---|---|
| `SELECT` (AID `A0 00 00 03 08 00 00 10 00`) | select the PIV applet |
| `VERIFY` (INS `20`, P2 `80`) | verify the PIN; with empty data, read the retry counter |
| `GENERAL AUTHENTICATE` (INS `87`) | sign a digest with the slot key |
| `GET DATA` (INS `CB`) | read the slot certificate → public key; read the serial |

Requiring a pre-populated slot is the single biggest simplification available
here, and it is worth spelling out what it removes:

- `GENERATE ASYMMETRIC KEY PAIR` (INS `47`) and the slot-metadata handling
  around it;
- writing a self-signed certificate back with `PUT DATA`;
- **management-key authentication**, which is the expensive one: 3DES on older
  firmware, AES-192 on YubiKey 5.7 and later, plus the PIN-protected
  management-key object as a third variant, plus the mutual-authentication
  challenge/response for each;
- PIN, PUK and management-key change flows, and the failure modes that come
  with getting any of them wrong.

That is a large amount of security-critical code whose only purpose would be to
reimplement `ykman` less well, in a program whose signing path has to work when
everything else has already gone wrong.

It also buys a property worth having in its own right: **tpm2-kira cannot alter
or brick the token.** A bug in this code cannot destroy a Secure Boot signing
key that happens to live in the same slot. Given that sharing a slot with sbctl
is an explicit goal, read-only is the right posture.

Enrolment is therefore a documented `ykman` procedure, not a tpm2-kira feature:

```bash
# only if the slot is empty — skip entirely when reusing an sbctl key
ykman piv keys generate --algorithm ECCP256 \
    --pin-policy ONCE --touch-policy NEVER 9a /tmp/seal.pub
ykman piv certificates generate --subject "CN=tpm2-kira" 9a /tmp/seal.pub

sudo tpm2-kira yubikey adopt --slot 9a
```

`adopt` is read-only: it reads the slot, reports the key type and the PIN and
touch policies, checks the key against the TPM with the existing
`ValidateKeyForTPM`, caches the public key to
`/var/lib/tpm2-kira/keys/seal.pub`, and prints the `KeyRef` to use.

### 4.4 Slots, algorithms and policies — detect, do not dictate

Because the slot is pre-populated, tpm2-kira takes what it finds. It supports
any PIV slot (`9a`, `9c`, `9d`, `9e` and the retired slots `82`–`95`) and any
key the TPM can load: RSA-2048, ECC P-256 and ECC P-384 (SECURITY-BACKGROUND
§7). `adopt` reports what is there and warns about what will hurt, rather than
insisting on one configuration.

**For a slot created specifically for tpm2-kira**, `9a` with ECCP256, PIN
policy `ONCE` and touch policy `NEVER` remains the recommendation, and the
`ykman` line above produces exactly that.

**For a slot shared with sbctl**, the natural home is `9c` (Digital Signature)
and the key is likely RSA-2048. Both work, with consequences that have to be
handled rather than warned about:

| What the slot has | Consequence | How it is handled |
|---|---|---|
| PIN policy `ALWAYS` (mandatory on `9c`) | a PIN verification before **every** signature | §6.2 — the PIN is held for the process and re-verified per signature |
| Touch policy `ALWAYS` | one physical touch per signature | `adopt` and `reseal` print the exact number of touches to expect before starting |
| Touch policy `CACHED` | one touch per 15-second window | usually one touch for a whole reseal |
| RSA-2048 | ~100 ms per signature instead of ~10 ms | irrelevant at ~3 signatures per slot |
| RSA-4096 | `TPM2_LoadExternal` may reject it | caught by `adopt`, and again by the NV write pre-flight before anything is destroyed |

`reseal` computes its signature count up front — 3 per slot, times the number
of populated slots — so "this will need 12 touches" is said once, at the start,
rather than discovered one touch at a time.

### 4.5 The public key stays on disk

The slot's public key is cached at `/var/lib/tpm2-kira/keys/seal.pub` and its
path stored in the blob. Blob-signature verification, the PolicyOR digest and
`info` then all work with the token in a drawer. The token is only ever needed
to *sign*.

---

## 5. Blob format v9

Since compatibility is not maintained, the key reference goes in as a typed
field rather than a string that has to be sniffed.

Replacing the `HasKeyPaths` block:

```
?  HasKeyRefs              uint8     0 or 1
   If HasKeyRefs=1, twice (public then private):
     Kind                  uint8     0=file, 1=yubikey
     Ref length            uint16    <= 4096
     Ref                   string    path, or "yubikey:serial=N;slot=9a"
?  HasKeyPin               uint8     0 or 1
   If HasKeyPin=1:
     TokenSerial           uint32    0 if unknown
     KeyFingerprint len    uint8     <= 64
     KeyFingerprint        []byte    SHA-256 over the marshalled public key
```

Everything sits inside `SealedBlobPayload`, so it is covered by the existing
blob signature automatically — a planted blob cannot redirect `reseal` at an
attacker-controlled token without breaking that signature.

`CurrentBlobVersion` → 9; the unmarshal path rejects v8 with the existing
"seal again" error. Users re-seal once and re-enrol their authenticator.

**Worth doing in the same bump:** if any other format change is pending, fold
it into v9 so people re-enrol once rather than twice.

---

## 6. PIN handling

### Sources, in priority order

1. `TPM2_KIRA_PIN` environment variable.
2. `--pin-file <path>` — mode-checked, refused if group- or world-readable.
   This is what makes the unattended hook path workable.
3. Interactive prompt with echo off — **only when stdin is a TTY**. Never in a
   hook.
4. Nothing available → the degradation path of §7.

### Lockout safety — the part that must not be got wrong

A PIV PIN has **3 attempts**; exhausting them requires the PUK, and exhausting
the PUK bricks the slot. Multi-slot `reseal` loops over slots, so a naive
implementation retries a wrong PIN once per slot and destroys the token on a
4-slot machine in one command.

Rules:

- **Open the card once per process**, verify the PIN once, reuse the session for
  every slot. Never re-open per slot.
- **On a wrong PIN, abort the entire run immediately.** Do not continue to the
  next NVRAM slot, do not retry.
- **Read the retry counter before verifying** and refuse to try at all when it
  is 1, printing the PUK recovery instructions instead. Losing the ability to
  reseal is recoverable; bricking the slot is not.
- **Never print the PIN**, and scrub it from `--debug` output, which is
  otherwise very talkative.
- Print "PIN retries remaining: N" whenever N < 3. People do not check
  otherwise.

### 6.2 PIN policy `ALWAYS`

A slot shared with sbctl is probably `9c`, where PIV mandates PIN policy
`ALWAYS`: the card discards the verified state after each cryptographic
operation, so every signature needs its own `VERIFY`. tpm2-kira holds the PIN
for the lifetime of the process and re-verifies transparently before each
signature.

This is safe with respect to the retry counter, which is the thing worth being
careful about: **a successful `VERIFY` resets the counter to full**, so N
correct verifications cost nothing. Only a *wrong* PIN decrements, and the rule
above — abort the whole run on the first wrong PIN — still bounds the damage at
one failed attempt per invocation.

The cost is latency and, if the touch policy is also `ALWAYS`, one touch per
signature. Both are reported before the run starts rather than discovered
during it.

### What the environment variable costs

`TPM2_KIRA_PIN` is convenient and conventional, but it is worth writing down
plainly: it is visible in `/proc/<pid>/environ` (root only — `reseal` is already
root, so no privilege boundary is crossed), it lands in shell history if typed
inline, and it is inherited by child processes. The mitigating fact is that the
PIN alone authorises nothing without physical possession of the token. That is
precisely the property being bought here, and the docs should say so rather than
leave it implied.

---

## 7. Degradation: key unavailable

"Unavailable" covers: no token plugged in, no pcscd, wrong serial, empty slot,
no PIN supplied, PIN refused.

`reseal` then:

1. **Does not attempt a reseal at all.** It cannot: the NV write policy needs a
   signature (§2). Attempting and failing halfway is actively dangerous —
   `WriteToNVRAM` undefines the NV index before writing, so a failure in between
   **destroys the sealed secret**. The check must happen *before* the TPM is
   touched (see §13.1).
2. Prints a clearly-marked warning block, distinct from both the success line
   and the existing `FAILED:` marker:

```
tpm2-kira: SKIPPED: resealing did not happen — the signing key was not available.
  Key reference: yubikey:serial=12345678;slot=9a
  Reason:        no YubiKey with serial 12345678 is present
  Consequence:   the PCR values on this system have changed, but the sealed
                 policy still binds the OLD values. At the next boot tpm2-kira
                 will report a PCR MISMATCH and show no TOTP code.
                 That is expected here — it is not evidence of tampering.
  To fix:        plug in the YubiKey, set TPM2_KIRA_PIN, and run:
                     sudo tpm2-kira reseal
  Affected PCRs: 0 (register), 7 (register)
```

The "Affected PCRs" line comes straight from the blob's `PCRDigests` and tells
the user exactly which registers will mismatch.

3. Exits 0, as everything in this project does by design.

`seal` and `setup` **fail** instead when the key is unavailable — there is
nothing to preserve, and a half-sealed slot is worse than no slot.

### Making the warning impossible to miss

A warning that only lands in `mkinitcpio` scrollback will be missed. So:

- `initramfs/mkinitcpio/post/sd-tpm2-kira` already greps for
  `Successfully resealed`; it gains an explicit `SKIPPED:` branch that prints a
  framed message and drops a stamp file at `/run/tpm2-kira/reseal-skipped`.
- Same for `initramfs/initramfs-tools/post-update.d/tpm2-kira`.
- **New: `tpm2-kira info` reports staleness.** When the blob's PCR digests no
  longer match the live registers, `info` says so in one line. It is the natural
  place to notice "I forgot to reseal" *before* rebooting, and it costs almost
  nothing — the comparison already exists in the reveal path.

---

## 8. CLI surface

```
tpm2-kira yubikey list                    # readers, serial, firmware, slots, retry counter
tpm2-kira yubikey adopt [--slot 9a] [--serial N]
                                          # read-only: inspect an existing key,
                                          # report its policies, check it against
                                          # the TPM, cache the public key,
                                          # print the ref
tpm2-kira yubikey status                  # is the enrolled token present? retries left?
tpm2-kira yubikey export-pubkey [--out PATH]
```

Extended flags on existing commands:

```
--privkey yubikey:serial=12345678;slot=9a   # the existing flag, now taking a ref
--pin-file PATH                             # alternative to TPM2_KIRA_PIN
--require-key                               # turn the §7 warning back into a hard
                                            # failure, for scripts that must not
                                            # silently skip
```

`setup` gains `--yubikey[=serial]`: adopt the token's key instead of generating
a PEM, then seal as usual.

There is no `generate`, no `import` and no `reset`. tpm2-kira only ever reads
from and signs with the token; populating a slot is `ykman`'s job. Users moving
from a PEM key generate a fresh key on the token and `reseal` with it, which
works because reseal re-derives the PolicyOR digest from whatever key it is
given.

---

## 9. Packaging and hooks

Much smaller than it would have been with a split binary:

| File | Change |
|---|---|
| `Makefile` | unchanged — no cgo, no tags, no second artifact |
| `debian/rules` | unchanged (`CGO_ENABLED=0` still works) |
| `debian/control` | `Recommends: pcscd` — a *runtime* suggestion, not a link-time dependency |
| `packaging/aur/PKGBUILD` | `optdepends=('pcsclite: YubiKey signing key support')` |
| `initramfs/*/hooks/*` | unchanged |
| `initramfs/mkinitcpio/post/sd-tpm2-kira` | handle `SKIPPED:` |
| `initramfs/initramfs-tools/post-update.d/tpm2-kira` | same |
| no new configuration file | the key reference is in the blob; the PIN is not — see §9.1 |

### 9.1 Configuration lives in the blob, and the PIN lives nowhere

The blob already carries everything needed to find the signing key: v9 stores a
typed key reference, so `reseal` with no flags finds a token slot exactly as it
used to find a key file. No configuration file is needed for that, and none is
shipped.

**The PIN cannot join it.** The NVRAM index is defined with `OwnerRead` and
`AuthRead` set — reads are open by design, because the secret is protected by
the sealed object's policy rather than by read control (SECURITY-BACKGROUND §9).
Anything in the blob is therefore readable by any process that can reach the
TPM, and by anyone who takes the disk. A PIN stored there would be published to
exactly the attacker the token exists to defend against, turning two factors
into one.

So the PIN comes from `TPM2_KIRA_PIN`, from `--pin-file`, or from a terminal
prompt, and nowhere else.

That leaves the unattended reseal after an initramfs rebuild, which has no
terminal. Three honest options, in order of preference:

1. **Use a slot whose PIN policy is `never`.** The token being physically
   plugged in is then the authorisation. This is a coherent security model —
   possession of the token is the factor — and it needs no secret on disk at
   all. `ykman piv keys generate --pin-policy NEVER` sets it.
2. **Let the reseal be skipped.** This is already the designed behaviour (§7):
   the hook prints the `SKIPPED:` block, nothing is changed, and the user
   reseals by hand. It matches what the project already argues for PCR 8/9 on
   Debian — "Keeping a human in the loop is the point."
3. **Set `TPM2_KIRA_PIN` in the hook's environment**, if a particular deployment
   wants that. It is the deployer's choice and needs no support from us.

**Nothing goes in `initramfs.conf` either**, and that is worth stating because
it is the obvious place to reach for. Debian's hook copies that file *into the
image*, and the image lives on unencrypted `/boot` — the premise of the whole
project is that `/boot` is what an attacker gets to touch. It would also be
pointless: the initramfs never uses the signing key.

What *would* belong there is a display concern. Deferring a reseal produces an
expected PCR mismatch at the next boot (§7), and a blank screen is a poor way to
say "this is the mismatch you chose". A variable such as
`TPM2_KIRA_EXPLAIN_MISMATCH=yes|no` would let the boot display distinguish "no
code because you skipped a reseal" from "no code, and you did not expect that".
That carries no secret. Note `initramfs.conf` is Debian-only today; if it grows
this, Arch should read it too.

## 10. Testing

The integration suite runs against `swtpm` with no card reader, so:

- **`SigningKey` gets an in-process fake** backed by a software ECDSA key whose
  `Sign()` returns ASN.1 DER — i.e. it behaves like a token, not like
  `*ecdsa.PrivateKey`. Running the whole existing integration suite through that
  fake is what actually proves the §3 refactor, with no hardware.
- **Known-answer test for `signForTPM`**: sign a fixed digest with a fixed key
  through both the file path and the fake-token path, and assert the resulting
  `TPMTSignature` bytes are identical. This is the regression test for the one
  change that could silently break recovery.
- **Wire-format tests for `internal/pcsc`**: golden byte vectors for every
  message, plus compile-time size assertions. These are what keep a pcsc-lite
  version bump from becoming a silent failure.
- **`internal/piv` against a scripted APDU mock**: canned responses for SELECT,
  VERIFY (including the retry-counter and wrong-PIN paths), GENERAL
  AUTHENTICATE and GET DATA.
- **Optional end-to-end against a virtual card**: pcscd plus `vsmartcard`'s
  `vpcd` and a PIV emulator exercises the real socket protocol in CI without
  hardware. Worth doing precisely because we own the transport now.
- **PIN state machine tests**: retry counter at 1 refuses; a wrong PIN aborts the
  multi-slot loop after the first slot; the PIN never appears in `--debug`.
- **Degradation tests**: `reseal` with an unresolvable ref prints `SKIPPED:`,
  exits 0, and — asserted explicitly — leaves the NVRAM index byte-identical.
- **Hardware tests** behind `-tags yubikey_hw`, skipped by default, run manually
  before a release.

---

## 11. Documentation

- `README.md`: a YubiKey section (the `ykman` enrolment command, `adopt`,
  reseal, what happens without the token), and the blob v9 re-seal note.
- `docs/SECURITY-BACKGROUND.md`:
  - §3.1 — the v9 blob layout and the key-reference fields.
  - §3.3 — the key pair may live on a token; only the public key is on disk.
  - §4.6 — the interesting change (§12 below).
  - §7 — token key types and why ECCP256.
  - §8 — threat-model rows for token theft, token-present-at-boot, PIN capture.
  - §9 — unchanged, but note that NV writes now need the token.
  - §10 — blob v9.
  - §12 — backup strategy for a lost token.
  - new §13 "Signing key on a hardware token", including the pcsc-lite
    versions the transport was tested against.
- `HISTORY.md`: v8 → v9, and why `PrivateKeyPath` became a typed reference.

---

## 12. What this actually changes for security

**Genuinely better.** SECURITY-BACKGROUND §4.6 currently argues the key is safe
at the measure point because it sits on an encrypted filesystem that is not yet
unlocked — and explicitly calls this "a filesystem-layout property that a
different deployment could undo, not a guarantee the TPM makes". A token
replaces that argument with a stronger one: the key is on no filesystem, cannot
be read out at all, and its use is gated by a PIN with a hard retry limit. The
§8 row "Compromise of the signing private key" goes from "root can copy a file"
to "an attacker needs the physical token and the PIN". That is a real
improvement to the worst failure mode in the current design.

**Unchanged.** Root on a running, measured system can still unseal through the
PCR branch — no key involved. The TPM bus interposer is untouched. NV index
deletion is still owner-authorised and still a denial of service (§9).

**Honest about the single binary.** With one artifact, the initramfs image does
contain the PC/SC and PIV code. That is not a hole worth worrying about —
`reveal` and `run` never call it, there is no pcscd and no `/run/pcscd` socket
inside an initramfs, and the key is on a removable token rather than in a file
the initrd could read. But the docs should not claim the stronger "the
early-boot binary physically cannot reach the key" property, because with one
binary it is not true. The guarantee comes from the token, not from the build.

**Sharing the slot with sbctl.** This is already the project's own suggestion
for file-based keys — SECURITY-BACKGROUND §11 argues that pointing `--privkey`
at the sbctl DB key means "the same key that signs boot components also
authorises TOTP re-sealing, with no additional secret to manage". Moving that
shared key onto a token strengthens it in the same way it strengthens the
dedicated key, and the read-only posture of §4.3 means tpm2-kira cannot damage
the Secure Boot key it is borrowing.

Two consequences, one of them a genuine operational trap:

- *One token now gates two things.* Losing it costs both Secure Boot signing
  and TOTP recovery. That raises the stakes on the backup question (§13.4)
  rather than changing its answer.
- **Secure Boot key rotation has a mandatory order**, because a slot holds one
  key at a time. Rotating closes both PolicyOR doors at once: enrolling new
  Secure Boot keys moves PCR 7, and replacing the slot key invalidates the
  PolicySigned branch, which is bound to the old key's Name. If both happen
  before a reseal, nothing can unseal the blob and the secret is gone.

  The fix is ordering, and it works because a reseal needs the *old* key only
  to unseal and the *new* key only to write:

  ```
  1. replace the slot key K_old -> K_new       (PCR 7 has not moved yet)
  2. tpm2-kira reseal --pubkey <K_new.pub>     unseals via the PCR branch,
                                               re-binds the signed branch to K_new
  3. sbctl enroll-keys with K_new              PCR 7 moves now
  4. reboot -> PCR mismatch -> tpm2-kira reseal  unseals via PolicySigned
                                                 with K_new, re-binds PCR 7
  ```

  Step 2 is the one that must not be skipped: it is the only moment when the
  blob can be re-pointed at K_new without needing K_old, because the PCR branch
  still opens on its own. Do steps 1 and 3 in the other order and the blob needs
  a key that no longer exists.

  Two things follow for the implementation. The docs need this sequence
  prominently, and `adopt` should record the key fingerprint (§5) so `reseal`
  can say "the key in slot 9c is not the one this blob was sealed against"
  instead of failing as an obscure TPM policy error.

  The simplest way to avoid the whole problem is to **not share the slot**: put
  the sbctl key in `9c` and a dedicated tpm2-kira key in `9a` on the same token.
  One device, two independent keys, no rotation coupling. Worth recommending as
  the default and documenting slot sharing as the deliberate choice it is.

**New exposure.**

- *Token plugged in during reseal.* With PIN policy `ONCE`, any root process can
  ask the card to sign for the lifetime of the card session. Closing the session
  explicitly when the command finishes is cheap and should be done.
  `CACHED` or `ALWAYS` shrink the window further at a usability cost.
- *Token plugged in at boot.* tpm2-kira never touches the key in `reveal`, but
  an attacker with physical access to a machine that has the token permanently
  inserted is in a different position than one facing a bare machine. Docs
  should say: remove the token when you are not resealing. That is the entire
  point of it being removable.
- *PIN capture.* A root-level attacker on a machine where the PIN is placed in
  a systemd environment file or a hook's environment has the PIN. They still
  need the token. This is a deliberate trade wherever a deployment makes it —
  which is why tpm2-kira does not make it for them by shipping a PIN file.
- *Loss of the token is loss of recovery.* A lost key file is restorable from a
  backup; a lost token is not, and the blob's own docs call the signing key "the
  recovery master key". SECURITY-BACKGROUND §12 must gain a paragraph: keep an
  offline PEM backup key and a documented switch procedure, accepting that the
  backup partially gives back what the token removed — or accept that a lost
  token means `seal` again plus re-enrolling the authenticator app.

---

## 13. What I would introduce beyond the ask

Ranked by how much I think they matter.

1. ~~**Reseal must be atomic, or must not start.**~~ **Done** — `cmd/nvram.go`.
   `WriteToNVRAM` undefined the NV index *before* loading the key, computing the
   write policy and producing the first signature, so any of those failing
   destroyed the sealed secret. All three now run first, plus a test signature
   on a dummy digest, so an unusable key, an absent token or a refused PIN is
   found while the old blob is still intact. Also added: a size guard (the NV
   public area stores the size as a uint16, so a blob over 65535 bytes was
   silently truncated by the conversion), a read-back comparison after the last
   chunk, and `stashUnwrittenBlob`, which writes the blob to
   `/var/lib/tpm2-kira/recovery/` if a step after the undefine fails — the
   sealed object's private area is wrapped by the TPM's deterministic primary
   key, so the secret survives in those bytes even though the index is gone.

   Follow-up: ~~a `tpm2-kira nvram restore` command to write a stashed blob
   back.~~ **Done.** Blob v9 made it small, since the file now names its own
   signing key. It verifies the blob signature, checks the key fingerprint, and
   loads the sealed object to prove the blob belongs to this TPM before touching
   the index, and refuses to overwrite a different blob without `--force`.
2. **`tpm2-kira info` should say whether the blob is stale.** The direct
   consequence of "reseal may legitimately be skipped" is that users need a way
   to ask "am I about to reboot into a mismatch?" that is not "reboot and see".
3. **Key fingerprint and serial pinning in the blob** (already in the v9 layout,
   §5). Checked whenever the token is opened, it turns "wrong YubiKey" from a
   confusing TPM policy failure into a one-line diagnosis.
4. **A documented backup-key procedure.** PolicyOR has exactly two branches, so
   a second independent signing key cannot simply be added, and the same key
   cannot exist on two tokens when it is generated on-device. The options are
   (a) an offline PEM backup with a re-seal-to-switch procedure, or (b) widening
   the policy to three branches (PCR, token A, token B), which is a real change
   to `policy_or.go` and the blob format. Since v9 is being cut anyway, (b) is
   cheaper now than it will ever be again — worth a deliberate decision rather
   than discovering it after someone loses a token. I would still start with (a).
5. **`--require-key`.** The graceful skip is right for the hook path; a
   controlled procedure wants the opposite. One flag, no ambiguity.
6. **PIV attestation at adopt time.** YubiKey can attest that a key was
   generated on-device and never imported (slot `f9`). It needs one extra APDU
   and it makes the central claim of this feature — "the key was born on the
   token" — verifiable rather than assumed.

---

## 14. Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | Split binary vs. pure-Go PC/SC | **decided: pure Go, one binary** |
| 2 | Blob key reference | **done: v9, typed field, plus fingerprint and serial** — but see §16: the reference and serial should now come back out |
| 3 | Environment variable name | **decided: `TPM2_KIRA_PIN`** |
| 4 | Token must be pre-populated | **decided: yes — tpm2-kira never writes to the token** |
| 4a | Touch policy | detected, not dictated; `NEVER` recommended for a dedicated slot |
| 5 | Backup for a lost token | proposed: PEM backup + switch procedure; three-branch PolicyOR is cheapest to add during the v9 bump if you want it |
| 6 | A configuration file for unattended key selection and PIN | **decided: no. The key reference is in the blob; the PIN cannot be (§9.1)** |
| 8 | File-backed key remains the default | **decided: yes — the token is opt-in** |
| 9 | `TPM2_KIRA_EXPLAIN_MISMATCH` in `initramfs.conf` | proposed; carries no secret, unlike the PIN |
| 7 | Anything else to fold into the v9 bump | open — worth checking before cutting it |

---

## 15. Implementation order

0. ~~Pre-flight/atomicity fix in `WriteToNVRAM`~~ — **done**, see §13.1.
1. `SigningKey` abstraction + refactor of the three signing call sites, file
   backend only. **No behaviour change**; the existing suite must pass untouched,
   plus the fake-token suite from §10.
2. ~~`nvram restore`, completing the recovery path opened by step 0.~~ **Done.**
3. ~~Blob v9: typed key refs, fingerprint/serial pinning, `info --json` output.~~ **Done.**
4. Degradation path, `SKIPPED:` marker, hook changes, `--require-key`,
   `info` staleness.
5. `internal/pcsc` — the pure-Go pcscd client, with golden-vector tests.
6. `internal/piv` — SELECT / VERIFY / GENERAL AUTHENTICATE / GET DATA, against
   the APDU mock. No write APDUs, by decision.
7. YubiKey `SigningKey` backend, `yubikey list|adopt|status|export-pubkey`.
8. PIN sources and the lockout state machine.
9. Attestation, documentation.

Steps 1–4 are useful on their own and can merge before any card code exists.
Step 5 is the one with schedule risk; it is deliberately isolated behind the
`SigningKey` interface so nothing else waits on it.

---

## 16. Proposed: blob v10, identical whatever holds the key

Since `setup` and `yubikey adopt` write a reference file at the well-known
private key path, the blob's own copy of "where the key lives" has become a
second, weaker answer to a question already answered locally. The two can
disagree, and the blob is consulted first, so the weaker copy wins. See
[SIGNING-KEYS.md](SIGNING-KEYS.md) for the resulting wart, which is reproducible:
adopt a different token and `reseal` still hunts for the old serial.

The deeper objection is about what a blob is for. It is a portable artifact —
signed, backed up, restored onto rebuilt machines by `nvram restore`. Where a key
happens to live is local, mutable state. Putting the latter inside the former
means a restore drags a stale filesystem path or a retired token serial onto a
machine where neither is true.

### What would change

| Field | Verdict | Why |
| --- | --- | --- |
| `KeyFingerprint` | **keep** | It is the identity gate (§footnote ⁵ in SECURITY-BACKGROUND.md). It must be bound to the sealed object and covered by the blob signature, and it is not duplicated anywhere: `seal.pub` is mutable local state, this is signed. |
| `TokenSerial` | **remove** | Redundant twice over: `private_key_ref` already contains `serial=`, and nothing ever compares it — it is only interpolated into an error string. |
| `PrivateKeyRef` | **remove** | Now answered by `seal.key`, for both variants, at a fixed path. |
| `PublicKeyRef` | **remove** | Always `seal.pub` in practice; the default path finds it. |

The blob then has the same shape whichever way the key is stored, differing only
in the fingerprint — which differs per *key*, not per storage location. Key
resolution collapses to: `--privkey`, else the well-known path. One source of
truth, and it is the local one, which is the copy that can be corrected.

### What it costs

- **Blob v10.** Acceptable in development.
- **A breadcrumb on a bare machine.** Restoring a blob with no `keys/` directory
  would no longer say "this was sealed against YubiKey 12345678". The
  replacement is better: `info` prints the sealed fingerprint, `yubikey list`
  prints the fingerprint of every connected token, and matching those two works
  even after the key moves to another token or slot — which the serial does not.
- **`reseal` with no local key files** would need `--privkey`. But a machine with
  no `keys/` directory has no `seal.pub` either, so it is already supplying
  flags.

### What it does not change

The `SignedBranchDigest` is derived from the public key alone, so it is already
byte-identical for a file-held and a token-held key — verified by sealing one
key both ways and diffing. The TPM cannot tell where the private half lives, and
nothing here changes what it enforces. This is purely about metadata hygiene.

