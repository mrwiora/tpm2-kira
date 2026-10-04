# PLAN-YUBIKEY.md — moving the signing key onto a YubiKey

Status: **in progress** — see §16 for what is implemented.
Branch: `feat/yubikey-v2`.

Decisions already taken (§14 records the rest):

- **One binary.** No build-tag split, no second artifact. The PC/SC client is
  written in pure Go so `CGO_ENABLED=0` keeps working and the initramfs stays
  library-free.
- **The blob format does not change for this.** The token reference goes in
  the key file, the way sbctl does it (§5). The blob keeps storing the key
  *path*, and the path stays a real path. What changes is what that file can
  contain: a PEM private key, or a small JSON stub naming the YubiKey serial
  and slot.
- **`setup` is the only enrolment command** (§8). It looks for a YubiKey and
  says what it found; `setup --yubikey` takes the key from the token. If none
  is found, the user is told so plainly and the local key files are created as
  today. There is no `yubikey adopt`; `yubikey list` shows the candidates.
- **No backwards compatibility.** The project is in developer mode, so there is
  no migration path from a PEM key to a token beyond running setup again and
  sealing again.
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

The code already passed private keys around as `crypto.Signer`, loaded from a
path at the top of each command. Because the token reference lives in the key
file (§5), no new key-reference type is needed: the loader returns a different
`crypto.Signer` for a stub, and nothing that receives it has to know.

```go
// cmd/policy_or.go — was LoadSigningPrivateKeyFromPEM
func LoadSigningPrivateKey(path string) (crypto.Signer, error)
//   PEM   → *rsa.PrivateKey / *ecdsa.PrivateKey, as before
//   stub  → *yubiKeySigner (cmd/yubikey.go): Public() from the stub, token
//           opened lazily on the first Sign(), errors wrap ErrTokenUnavailable
```

The token is therefore never contacted by `info`, by blob verification, or by
the policy computation in `reseal`; only a signature opens it.

What had to change to make that true:

- `signForTPM` type-switched on `*rsa.PrivateKey` / `*ecdsa.PrivateKey`. It now
  switches on the *public* key, calls `Sign()`, and parses the ECDSA ASN.1 DER
  back into r and s, left-padded to the curve size. Software keys take the
  same path, so there is one code path to get right.
- `SignBlobPayload` likewise. The output formats are unchanged, so
  `VerifyBlobSignature` is untouched.
- `verifyKeyPairMatch` compares public keys. It was dead code; `seal` now calls
  it, so a public key that does not belong to the private key file is refused
  before anything is written instead of failing at the first NV write.

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

sudo tpm2-kira setup --yubikey
```

`setup --yubikey` is read-only *towards the token*: it reads the slot and
reports the key type and the PIN and touch policies. On the filesystem it
writes two files: the public key to `/var/lib/tpm2-kira/keys/seal.pub`, and the
token stub (§5) to `/var/lib/tpm2-kira/keys/seal.key`. After that, every
command that already defaults to `seal.key` uses the token without any new
flag. Whether the TPM accepts the key is checked by `seal`, which loads it
before anything is written.

### 4.4 Slots, algorithms and policies — detect, do not dictate

Because the slot is pre-populated, tpm2-kira takes what it finds. It supports
any PIV slot (`9a`, `9c`, `9d`, `9e` and the retired slots `82`–`95`) and any
key the TPM can load: RSA-2048, ECC P-256 and ECC P-384 (SECURITY-BACKGROUND
§7). `setup` and `yubikey list` report what is there and warns about what will hurt, rather than
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
| Touch policy `ALWAYS` | one physical touch per signature | "Touch the YubiKey" is printed before each signature; a touch count up front is still to do |
| Touch policy `CACHED` | one touch per 15-second window | usually one touch for a whole reseal |
| RSA-2048 | ~100 ms per signature instead of ~10 ms | irrelevant at ~3 signatures per slot |
| RSA-4096 | `TPM2_LoadExternal` may reject it | reported as not usable by `setup` and `yubikey list`, and caught again by the NV write pre-flight before anything is destroyed |

`reseal` computes its signature count up front — 3 per slot, times the number
of populated slots — so "this will need 12 touches" is said once, at the start,
rather than discovered one touch at a time.

### 4.5 The public key stays on disk

The slot's public key is cached at `/var/lib/tpm2-kira/keys/seal.pub`, and its
path is stored in the blob exactly as it is today. Blob-signature verification,
the PolicyOR digest and `info` then all work with the token in a drawer. The
token is only ever needed to *sign*.

---

## 5. The key file holds the token reference; the blob does not change

This follows sbctl. When sbctl's db key lives on a YubiKey,
`/var/lib/sbctl/keys/db/db.key` is no longer a PEM private key but a JSON
document describing the token key (`slot`, `algorithm`, `pinPolicy`,
`touchPolicy`, `publicKey`), with the certificate still in `db.pem` beside it.
Everything that reads the key by path keeps working; only the loader learns to
recognise the second format.

tpm2-kira does the same with `seal.key`, and adds the one thing sbctl leaves
out: **the serial number**. sbctl always uses whichever card it finds first in
the signature slot, which is fine for a tool that runs interactively but not
for a reseal hook. With the serial in the file, "wrong YubiKey plugged in" is
diagnosed before any PIN is sent.

### 5.1 Stub format

```json
{
  "backend": "yubikey",
  "version": 1,
  "serial": 12345678,
  "slot": "9a",
  "algorithm": "ECCP256",
  "pinPolicy": "once",
  "touchPolicy": "never",
  "publicKey": "<base64 PKIX DER>"
}
```

- `backend` and `version` make the file self-describing. The loader looks at
  the first non-whitespace byte: `-` is PEM, `{` is a stub. Anything else,
  an unknown `backend`, or an unknown `version` is an error — never a guess.
- `serial` selects the card. It is required; a stub without one is refused.
- `algorithm`, `pinPolicy` and `touchPolicy` are recorded by `setup` for
  display and for the up-front touch count (§4.4). The card is still asked at
  run time; the stub is not trusted over the card.
- `publicKey` is the fingerprint check. On open, the key read from the slot
  must equal it, and it must equal `seal.pub`. A mismatch is reported as "the
  key in slot 9a of YubiKey 12345678 is not the key this installation was set
  up with", not as a TPM policy failure.
- Written with `WriteSigningKeyFile`, so it gets mode 0400 like the PEM does.
  It contains no secret, but it decides which token is trusted to sign, so it
  gets the same protection.

### 5.2 What the blob keeps

The blob's `HasKeyPaths` block is unchanged: `PublicKeyPath` and
`PrivateKeyPath` are still plain filesystem paths, and `CurrentBlobVersion`
stays where it is. `reseal` reads `PrivateKeyPath`, opens the file, and the
contents decide whether it signs with a PEM key or asks the token.

Moving an existing installation from a PEM key to a YubiKey is not a supported
operation, since compatibility is not maintained during development: remove
the keys directory, run `setup --yubikey`, `seal` again and re-enrol the
authenticator.

### 5.3 Why this is safe without the blob signature covering it

A new blob version could have put the serial inside the signed payload. With the stub
outside the blob, the question is whether an attacker who can replace
`seal.key` gains anything. They do not:

- The TPM decides. The PolicySigned branch is bound to the *Name* of the
  original public key. A stub pointing at the attacker's own token produces
  signatures the TPM rejects, both for unseal and for the NV write policy.
- The stub's `publicKey` is cross-checked against `seal.pub` and against the
  key used to verify the blob signature, so a swapped stub fails before any
  PIN is sent.
- Writing to `/var/lib/tpm2-kira/keys/` already requires root. Whoever can do
  that can also replace a PEM `seal.key`, which is the status quo.

The worst a tampered stub can do is make `reseal` fail, which is the §7
degradation path: `SKIPPED:`, and the NV index is left untouched.

---

## 6. PIN handling

### Sources, in priority order

Implemented in `readPIN` (`cmd/yubikey.go`):

1. `TPM2_KIRA_PIN` environment variable — an explicit override.
2. The `TPM2_KIRA_PIN` line in `/etc/mkinitcpio.conf` (§9.1). The same line
   serves the unattended post hook, so the PIN lives in one place and a manual
   seal or reseal does not ask for it again. The file is parsed, never
   executed: `NAME=value`, `export NAME=value` and `export NAME`, with
   `'...'`, `"..."` and backslash quoting, last assignment wins — checked
   against what bash assigns. A value that needs expansion (`$VAR`, `$(...)`,
   backticks) counts as no PIN. When the file can be read by group or others,
   or is not owned by root, the PIN is refused (reported as an unavailable
   token, so the post hook prints SKIPPED) and the error says `chmod 600`.
3. Interactive prompt on `/dev/tty` with echo off. Never in a hook without a
   terminal.
4. Nothing available → the degradation path of §7.

A rejected PIN names its source ("PIN from /etc/mkinitcpio.conf"), because a
stale line in the file is the likely cause and it costs one attempt per run.
A `--pin-file` option is no longer planned: the mkinitcpio line covers it.

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

"Unavailable" covers: no pcscd, no token or the wrong serial, an empty slot,
no PIN supplied, a PIN refused or blocked. It does **not** cover a slot that
holds a different key than the key file names: that is a configuration error
and stays a `FAILED:`. In code, every such reason is a `TokenUnavailableError`
(`errors.Is(err, ErrTokenUnavailable)`).

`reseal` then (**implemented**, `cmd/reseal.go`):

1. **Does not attempt a reseal at all.** It cannot: the NV write policy needs a
   signature (§2). `PrepareSigningKey` runs right after the blob signature is
   verified and before anything is unsealed or written: it finds the token,
   compares the slot key with the key file and verifies the PIN.
2. A failure is a skip only while the NV index is untouched. Every error after
   `WriteToNVRAM` undefines the index goes through `stashUnwrittenBlob`, which
   marks it `ErrNVIndexReplaced`; `asResealSkipped` never turns such an error
   into a skip, whatever caused it. The token being pulled between the
   pre-flight and the write is therefore still reported correctly: a skip if it
   happens before the undefine, a failure with the stashed blob after it.
3. Prints one block for all skipped slots, distinct from the success line and
   the `FAILED:` marker:

```
tpm2-kira: SKIPPED: resealing did not happen — the signing key was not available.
  Key file:      /var/lib/tpm2-kira/keys/seal.key (YubiKey 12345678, slot 9a)
  Reason:        no YubiKey with serial 12345678 is present
  Slots:         #0, #1 (nothing was written; the sealed secrets are intact)
  Sealed PCRs:   0,7
  Consequence:   the sealed policy still binds the PCR values of the last seal.
                 If they have changed — as they do after a kernel or initramfs
                 update — the next boot reports a PCR MISMATCH and shows no
                 TOTP code. That is expected here; it is not evidence of tampering.
  To fix:        plug in the YubiKey and run, with the PIN typed when asked
                 or set in TPM2_KIRA_PIN:
                     sudo tpm2-kira reseal
```

   The PCR line lists the PCRs the blob is sealed to. It does not compare them
   with the live registers: after an initramfs rebuild the registers that will
   change are the ones of the *next* boot, which cannot be read yet.
4. Exits 0 without the `FAILED:` marker. `--require-key` turns the skip back
   into a failure, for procedures that must not silently skip.

`seal` and `setup --yubikey` **fail** instead when the key is unavailable —
there is nothing to preserve, and a half-sealed slot is worse than no slot.

### Making the warning impossible to miss

- **Done:** `initramfs/mkinitcpio/post/sd-tpm2-kira` has a `SKIPPED:` branch
  that prints the block framed, to stderr, and still exits 0.
- Debian's `post-update.d` hook never reseals (every PCR source there is read
  from the running system, so only a reseal after the next boot is correct);
  it needs no change. The manual reseal after boot asks for the PIN.
- Not done: a stamp file for the skip, and **`tpm2-kira info` reporting
  staleness** — the natural place to notice "I forgot to reseal" before
  rebooting.

---

## 8. CLI surface

```
tpm2-kira setup                     # probe; if a usable key is found, ask
                                    # (YubiKey slot or local key files)
tpm2-kira setup --yubikey[=SERIAL] [--slot SLOT]
                                    # use the token without asking
tpm2-kira setup --local             # local key files without probing or asking
tpm2-kira yubikey list              # readers, serials, firmware, populated
                                    # slots, and which are usable; read-only
tpm2-kira reseal --require-key      # fail instead of SKIPPED (§7)
```

With a token, setup writes only `seal.pub` (the token's public key) and
`seal.key` (the reference, §5); no private key exists on disk. Setup needs no
PIN; sealing does.

`--yubikey` alone uses the only suitable token; with several plugged in, the
serial must be given. `--slot` defaults to `9a`. Any other slot — typically
an sbctl key in `9c` — is only used when named or picked in the menu, because a
slot shared with another tool couples key rotation (§12). With `--yubikey`, a
missing or unsuitable token is a hard failure: the user asked for it
explicitly. Sealing stays a separate `seal` step.

Deliberately absent: `adopt` (setup does it), `status` and `export-pubkey`
(`list` and `seal.pub` cover them), and `generate`, `import` and `reset`.
tpm2-kira only ever reads from and signs with the token; populating a slot is
`ykman`'s job.

### 8.1 `setup` looks for a YubiKey and asks

Plain `setup` probes for a token before it creates any files. The probe is
strictly read-only and PIN-free: reader states, then per card `SELECT` PIV,
the serial, and each slot's metadata (`GET METADATA`, firmware 5.3+) or
certificate. No `VERIFY` is ever sent, so the probe cannot cost a PIN retry.
It never fails setup and each exchange with pcscd is bounded to 2 seconds.

A token is **suitable** when the PIV applet answers, it reports a serial
(YubiKey firmware 5+, which the key file needs), and at least one slot holds
RSA-2048, ECC P-256 or ECC P-384. The check is static; `seal` confirms it with
`ValidateKeyForTPM`.

**Suitable key found** — the user decides, even when there is only one
candidate, and can always choose local key files:

```
Looking for a YubiKey... found one suitable for tpm2-kira:
  YubiKey serial 12345678, firmware 5.7.1 (Yubico YubiKey OTP+FIDO+CCID 00)
    slot 9a  ECCP256  PIN once    touch never   <- recommended
    slot 9c  RSA2048  PIN always  touch always
    slot 9d  ECCP256  PIN never   touch never   WARNING: no PIN required (insecure)

Where should the signing key live?
  1) YubiKey 12345678, slot 9a  (ECCP256, PIN once, touch never)  [recommended]
  2) YubiKey 12345678, slot 9c  (RSA2048, PIN always, touch always)
  3) YubiKey 12345678, slot 9d  (ECCP256, PIN never, touch never)  [no PIN required: insecure]
  4) Local key files in /var/lib/tpm2-kira/keys (the private key is stored on disk)
Choice [1]:
```

The default is `9a` when it holds a usable key, local key files otherwise, so
pressing Enter never picks a shared slot. Invalid input is asked again, up to
three times; end of input aborts with nothing written. Without a terminal,
setup uses local key files and names `--yubikey` and `--local` for choosing
non-interactively.

**PIN policy.** A key with PIN policy `never` is flagged in the report and the
menu, and choosing it prints a warning: anyone holding the token could then
authorise a reseal, which is the way around a PCR mismatch. On firmware before
5.3 the policy cannot be read, and setup says so.

**After choosing the token**, setup explains the PIN, which it did not use
itself:

```
Setup did not use the PIN; sealing does. Put it in one place and every step
finds it — seal, reseal, and the mkinitcpio post hook that reseals after every
kernel or initramfs update. Add this line to /etc/mkinitcpio.conf:
    TPM2_KIRA_PIN='<your PIN>'
The file is readable by every user by default and would then hold the PIN, so
make it readable by root only (it is not copied into the initramfs image):
    chmod 600 /etc/mkinitcpio.conf
Without it, seal and reseal ask for the PIN on the terminal, and the automatic
reseal reports SKIPPED: the next boot then shows a PCR mismatch until you run
'tpm2-kira reseal' with the YubiKey plugged in.
```

This is printed where `/etc/mkinitcpio.conf` exists. Without mkinitcpio, setup
explains the terminal prompt and `read -rs TPM2_KIRA_PIN && export
TPM2_KIRA_PIN` instead; when the file already sets the PIN, it says so.

**No suitable key** (PIV disabled, empty slots, or only keys the TPM cannot
load such as RSA-4096 or Ed25519): each token is listed with the reason, the
`ykman` commands to create a key in `9a` are shown, and setup continues with
local key files. **No token at all**:

```
Looking for a YubiKey... none found.
  No YubiKey could be found, so the signing key will be created as local files.
```

---

## 9. Packaging and hooks

Much smaller than it would have been with a split binary:

| File | Change |
|---|---|
| `Makefile` | unchanged — no cgo, no tags, no second artifact |
| `debian/rules` | unchanged (`CGO_ENABLED=0` still works) |
| `debian/control` | `Suggests: pcscd` — a *runtime* suggestion, not a link-time dependency |
| `packaging/aur/PKGBUILD` | `optdepends=('pcsclite: ...')` |
| `initramfs/*/hooks/*` | unchanged |
| `initramfs/mkinitcpio/post/sd-tpm2-kira` | `SKIPPED:` branch (done) |
| `initramfs/mkinitcpio/mkinitcpio.conf.example` | commented `TPM2_KIRA_PIN=` line with the `chmod 600` note (done) |
| `initramfs/initramfs-tools/post-update.d/tpm2-kira` | unchanged: it does not reseal |

### 9.1 Where the PIN lives for unattended resealing

**Decided: `/etc/mkinitcpio.conf`, as a plain `TPM2_KIRA_PIN='...'` line**,
in the style of the file's other settings. This replaces the earlier proposal
of a separate `/etc/tpm2-kira/reseal.conf`.

**No `export` is needed, because tpm2-kira reads the file itself** (§6), in a
manual seal or reseal and in the reseal the post hook runs, which runs as root
on the host. Through mkinitcpio alone it would not work: mkinitcpio sources its
configuration with `.` and runs post hooks as child processes
(`run_post_hooks` in `/usr/bin/mkinitcpio`, 42.x), so only exported variables
reach a hook — checked with a real `mkinitcpio -c ... -g ...` run and a probe
hook. mkinitcpio's own settings need no `export` because mkinitcpio reads them
in the same shell. An exported line still works and is read the same way; it
matters only for a value that needs the shell, such as `$(cat ...)`, which
tpm2-kira does not evaluate but mkinitcpio hands to the hook when exported.

tpm2-kira always reads `/etc/mkinitcpio.conf`. A system that builds its
images from a different file (`mkinitcpio -c`, or a preset with `ALL_config`
pointing elsewhere) needs the line in `/etc/mkinitcpio.conf` all the same.

The PIN does not reach the image: mkinitcpio does not copy its configuration
into the initramfs (the `systemd` install hook reads `MODULES` from it and
writes only `modules-load.d/MODULES.conf`).

**Warning when the automatic reseal will lack the PIN (implemented).** Right
after a manual `seal` or `reseal` has had the PIN accepted, tpm2-kira reads
`/etc/mkinitcpio.conf` and warns, once per run, **only** when the PIN is not
available there: no `TPM2_KIRA_PIN` line, or one whose value needs the shell
and is not exported. When the line is there, the PIN was usually taken from
it in the first place, and nothing is printed. Systems without mkinitcpio get
no warning. `setup` says "already sets TPM2_KIRA_PIN" instead of the
instructions when the line exists.

What it costs, and what setup therefore says:

- `/etc/mkinitcpio.conf` is `0644` by default. With the PIN in it, it must be
  `chmod 600`; setup prints that. An upgrade of mkinitcpio does not reset the
  mode, since pacman writes a `.pacnew` for a modified backup file.
- A plain line stays in mkinitcpio's shell and is not passed to other post
  hooks; an exported one would be inherited by every hook and its children.
- A drop-in `/etc/mkinitcpio.conf.d/tpm2-kira.conf` was tried and **rejected**.
  mkinitcpio 42 ignores drop-ins when a preset passes its configuration with
  `-c` (`ALL_config=...`), which is how `mkinitcpio -P` runs on many systems,
  so the post hook would have had to source the file itself. The main file
  is sourced in every case, including through `ALL_config`, and needs no
  such workaround.

**It must not go in `initramfs.conf`.** Debian's hook copies that file *into
the image*:

```
copy_file config /etc/tpm2-kira/initramfs.conf /etc/tpm2-kira/initramfs.conf
```

The image lives on unencrypted `/boot`, so a PIN there would be readable by
anyone with physical access — the attacker the tool exists to detect — and
the initramfs has no use for it. tpm2-kira should ignore `TPM2_KIRA_PIN` if it
finds it in `initramfs.conf`, and say why (not done).

**What *would* belong in `initramfs.conf`** is a display concern: a variable
such as `TPM2_KIRA_EXPLAIN_MISMATCH=yes|no` letting the boot-time display
distinguish "no code because you skipped a reseal" from "no code, and you did
not expect that". It carries no secret.

The PC/SC and PIV code adds on the order of 50–100 KB to the static binary,
which also lands in the initramfs. That is negligible against the image size and
is the price of keeping one artifact.

---

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
- **Key file loader tests**: PEM and stub are told apart by content; unknown
  `backend`, unknown `version`, missing `serial` and a `publicKey` that
  disagrees with `seal.pub` are each refused with their own message. A
  round-trip test asserts the blob bytes are identical whether `seal.key` is a
  PEM or a stub, which is the regression test for "the blob does not change".
- **Setup probe tests** against the APDU mock: suitable token, token with only
  empty slots, token with only an RSA-4096 key, no pcscd, and a daemon that
  never answers (the timeout). Each asserts the message, that no `VERIFY` was
  sent, and that the local key files were still created.
- **Hardware tests** behind `-tags yubikey_hw`, skipped by default, run manually
  before a release.

---

## 11. Documentation

- `README.md`: a YubiKey section (the `ykman` enrolment command, `setup --yubikey`,
  reseal, what happens without the token), what `setup` prints when it finds
  a token, and the `seal.key` stub format.
- `docs/SECURITY-BACKGROUND.md`:
  - §3.1 — unchanged; note that `PrivateKeyPath` may name a stub.
  - §3.3 — the key pair may live on a token; only the public key and the stub
    are on disk. Why the stub needs no blob signature (§5.3).
  - §4.6 — the interesting change (§12 below).
  - §7 — token key types and why ECCP256.
  - §8 — threat-model rows for token theft, token-present-at-boot, PIN capture.
  - §9 — unchanged, but note that NV writes now need the token.
  - §12 — backup strategy for a lost token.
  - new §13 "Signing key on a hardware token", including the pcsc-lite
    versions the transport was tested against.
- `HISTORY.md`: why the token reference went into the key file, following
  sbctl, rather than into a new blob version.

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
  prominently, and the stub's `publicKey` (§5.1) lets `reseal`
  say "the key in slot 9c is not the one this blob was sealed against"
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
- *PIN capture.* A root-level attacker on a machine where the PIN sits in
  `/etc/mkinitcpio.conf` or a systemd environment file has the PIN. They
  still need the token. This is a deliberate trade and should read as one.
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

   Follow-up: a `tpm2-kira nvram restore --from <file>` command to write a
   stashed blob back. Deferred deliberately — it needs the key resolution that
   step 1 of §15 is about to rewrite.
2. **`tpm2-kira info` should say whether the blob is stale.** The direct
   consequence of "reseal may legitimately be skipped" is that users need a way
   to ask "am I about to reboot into a mismatch?" that is not "reboot and see".
3. **Key fingerprint and serial pinning in the key file** (the stub's `serial`
   and `publicKey`, §5.1). Checked whenever the token is opened, it turns "wrong YubiKey" from a
   confusing TPM policy failure into a one-line diagnosis.
4. **A documented backup-key procedure.** PolicyOR has exactly two branches, so
   a second independent signing key cannot simply be added, and the same key
   cannot exist on two tokens when it is generated on-device. The options are
   (a) an offline PEM backup with a re-seal-to-switch procedure, or (b) widening
   the policy to three branches (PCR, token A, token B), which is a real change
   to `policy_or.go` and needs a blob version bump of its own. The YubiKey
   work no longer bumps the blob, so (b) would be a separate decision. I would
   start with (a).
5. **`--require-key`.** The graceful skip is right for the hook path; a
   controlled procedure wants the opposite. One flag, no ambiguity.
6. **PIV attestation at setup time.** YubiKey can attest that a key was
   generated on-device and never imported (slot `f9`). It needs one extra APDU
   and it makes the central claim of this feature — "the key was born on the
   token" — verifiable rather than assumed.

---

## 14. Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | Split binary vs. pure-Go PC/SC | **decided: pure Go, one binary** |
| 2 | Where the token reference lives | **decided: in the key file, sbctl-style JSON stub with serial; blob format unchanged** (§5) |
| 3 | Environment variable name | **decided: `TPM2_KIRA_PIN`** |
| 4 | Token must be pre-populated | **decided: yes — tpm2-kira never writes to the token** |
| 4a | Touch policy | detected, not dictated; `NEVER` recommended for a dedicated slot |
| 5 | Backup for a lost token | proposed: PEM backup + switch procedure; three-branch PolicyOR would need its own blob bump |
| 6 | Where the PIN for unattended resealing lives | **decided: a plain `TPM2_KIRA_PIN=` line in `/etc/mkinitcpio.conf`, `chmod 600`; tpm2-kira reads it itself** (§9.1) |
| 8 | File-backed key remains the default | **decided: yes — the token is opt-in** |
| 9 | `TPM2_KIRA_EXPLAIN_MISMATCH` in `initramfs.conf` | proposed; carries no secret, unlike the PIN |
| 7 | Token detection in `setup` | **decided: always probe, read-only and PIN-free; with a usable key, ask on the terminal (token slot or local files), even for one candidate; report "none found" and create local files otherwise** (§8.1) |
| 10 | Keys without a PIN | **decided: allowed, with a warning in report, menu and after choosing** |

---

## 15. Implementation order

0. ~~Pre-flight/atomicity fix in `WriteToNVRAM`~~ — **done**, see §13.1.
1. `SigningKey` abstraction + refactor of the three signing call sites, file
   backend only. **No behaviour change**; the existing suite must pass untouched,
   plus the fake-token suite from §10.
2. `nvram restore --from <file>`, completing the recovery path opened by step 0.
3. Key file loader: PEM vs. stub detection, stub parsing and the `publicKey`
   cross-check against `seal.pub` (§5), with the token backend still a stub
   that reports "unavailable". Plus `info --json` output. No blob change.
4. Degradation path, `SKIPPED:` marker, hook changes, `--require-key`,
   `info` staleness.
5. `internal/pcsc` — the pure-Go pcscd client, with golden-vector tests.
6. `internal/piv` — SELECT / VERIFY / GENERAL AUTHENTICATE / GET DATA, against
   the APDU mock. No write APDUs, by decision.
7. YubiKey `SigningKey` backend, `yubikey list`, the `setup` probe and
   `setup --yubikey` (§8).
8. PIN sources and the lockout state machine.
9. Attestation, documentation.

Steps 1–4 are useful on their own and can merge before any card code exists.
Step 5 is the one with schedule risk; it is deliberately isolated behind the
`SigningKey` interface so nothing else waits on it.

---

## 16. Implementation status

Branch `feat/yubikey-v2`, 2026-09-30.

**Done**

| Piece | Where | Tested by |
|---|---|---|
| pcscd client (pure Go): version handshake with 4:6 → 4:4 fallback, context, reader states, connect, transactions, transmit, reset on disconnect | `internal/pcsc` | golden byte vectors and struct sizes; a scripted fake daemon (4:6, 4:4, refused 4:3, silent daemon timeout); **live against pcscd 2.5.2** (`TestLiveDaemon`, handshake, reader list and a connect error round trip) |
| PIV read-and-sign: SELECT, GET VERSION, GET SERIAL, GET METADATA, GET DATA (certificate), VERIFY, GENERAL AUTHENTICATE; command and response chaining; PKCS #1 v1.5 padding for RSA | `internal/piv` | against `internal/piv/pivtest`, a software YubiKey that answers APDUs |
| Key file stub, `LoadSigningPrivateKey`, lazy token signer | `cmd/yubikey.go`, `cmd/policy_or.go` | `cmd/yubikey_test.go` |
| PIN: `TPM2_KIRA_PIN` or a no-echo prompt on `/dev/tty`; one session per process; wrong PIN poisons the session; nothing tried with one attempt left; retries shown when below 3; PIN policy `always` re-verified transparently; card reset on exit | `cmd/yubikey.go`, `main.go` | wrong PIN over four "slots" costs one attempt; last attempt never sent; no PIN costs none; policy `always` keeps the counter at 3 |
| Key check before the PIN: slot key compared with the stub; every token signature verified against the stub key | `cmd/yubikey.go` | regenerated slot key and wrong serial are reported by name |
| `signForTPM`, `SignBlobPayload`, `verifyKeyPairMatch` on the public key | `cmd/policy_or.go`, `cmd/blob.go` | token-signed TPMT signatures and blob signatures verify; r/s padding over 20 runs |
| Interactive `setup` (menu of usable slots plus local files; default `9a`, never a shared slot), `--yubikey[=SERIAL] [--slot]`, `--local`, no-terminal fallback; `yubikey list` | `cmd/setup.go`, `main.go` | menu, default, retries, EOF, single non-`9a` candidate, no terminal; binary run against the live pcscd |
| PIN-policy warning (report, menu, after choosing); PIN instructions and the `mkinitcpio.conf` hint | `cmd/setup.go`, `cmd/yubikey.go` | `TestPINGuidance` |
| PIN taken from `/etc/mkinitcpio.conf` (after the environment, before the prompt); warning after a manual seal/reseal only when that file does not provide the PIN | `cmd/mkinitcpio.go`, `cmd/yubikey.go` | `TestReadMkinitcpioPIN`, `TestReadMkinitcpioPINMatchesBash`, `TestPINFromMkinitcpioConf`, `TestWarnIfNoUnattendedPIN` |
| §7 degradation: `PrepareSigningKey` pre-flight, `ResealSkippedError`, `ErrNVIndexReplaced` guard, one `SKIPPED:` block for all slots, `--require-key` | `cmd/reseal.go`, `cmd/nvram.go`, `main.go` | classification (skip before the write, never after it), block content, pre-flight with no PIN / unplugged / present |
| mkinitcpio post hook `SKIPPED:` branch; example config line | `initramfs/mkinitcpio/` | hook run with a stand-in `tpm2-kira` |
| `seal` refuses a mismatched key pair; `seal` and `info` name the token | `cmd/seal.go`, `cmd/info.go` | — |
| Packaging: `Suggests: pcscd` (not `Recommends`: the token is opt-in) and `optdepends` `pcsclite` | `debian/control`, `packaging/aur/PKGBUILD` | — |

**Not done yet**

- Ignoring `TPM2_KIRA_PIN` in `initramfs.conf`.
- Touch count announced up front (§4.4); per-signature "Touch the YubiKey"
  is printed.
- `info` staleness, `nvram restore`, attestation, and the README and
  SECURITY-BACKGROUND updates (§11), including the PIN in
  `/etc/mkinitcpio.conf`.

**Not verified**

- No real YubiKey has been used. The PIV layer is tested against an emulator
  written from the specification, and the card path through pcscd (connect,
  transmit, transactions with a card present) has not run against real
  hardware. A hardware check (`yubikey list`, `setup`, `seal`, `reseal` with
  and without the token) is the next thing to do.
- The swtpm integration suite runs with file-backed keys (all tests pass on
  the development machine except the two that need `tpm2_pcrextend`), but no
  test drives seal or reseal with a token-backed key, so the `SKIPPED:` path
  inside a real reseal has not run end to end.
