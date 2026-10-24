# History

Design decisions and removed features that used to be recorded as comments in
the source. Kept here so the code states what it *is*, not what it *was*.

Development mode: no backwards compatibility is maintained. Blobs, on-disk
formats and CLI flags may change without migration paths.

---

## Boot integration

### SSH in the initrd came from mkinitcpio-systemd-extras

Until the code screen got its own SSH server (2026-10-10), remote unlock
used the sd-network and sd-tinyssh hooks of mkinitcpio-systemd-extras:
the image copied the running system's /etc/systemd/network, tinysshd was
socket-activated by its own unit, and its command was
`tpm2-kira && systemd-tty-ask-password-agent --query --watch`. That
assumed a code could be computed whenever the admin arrived; after the
hold the OS separator had made the key's policy unsatisfiable, and the
remote admin got no code. Now the process that holds the boot listens
itself, so the confirmation in a session is the release, and the
network is configured for the image alone in control.conf
(docs/SSH.md).

### The SSH server was tinysshd

The first two versions (2026-10-10) had 'run' spawn a tinysshd per
connection whose command, 'tpm2-kira remote session', relayed the
terminal to run over /run/tpm2-kira/remote.sock and ran
systemd-tty-ask-password-agent for cryptsetup's own prompt. tinysshd and
the session ran as root, so the separate process isolated nothing; the
image needed tinysshd, a shell and the agent; the host key had to sit in
a file for tinysshd; logins were ssh-ed25519 only. Replaced the same day
by 'remote serve' (x/crypto/ssh, as nobody, in namespaces, under
Landlock, signing delegated to run) and run as the session's password
agent.

### The SSH CA's file was aSSH's format 1

The storage key the SSH CA is made under, and the CA itself, were
subject to the TPM's dictionary attack protection: during a lockout -
wrong PINs of any other object in the TPM - neither loaded, and the
image's SSH server had no certified host key. aSSH's format 2
(2026-10-24, with its authority opened by a PIN) makes both noDA. A CA
file of format 1 is not read: control creates the CA again, and clients
need its new `@cert-authority` line.

### The image's SSH host key was stored in clear

The first version (2026-10-10) copied a tinysshd key directory of the
image's own (TPM2_KIRA_SSH_HOSTKEYS) into the image unencrypted, as every
initramfs SSH server does. The same day it was replaced by a key sealed
to PCR 0+7 (TPM2_KIRA_SSH_HOSTKEY), the system's OpenSSH key by default,
following the sd-tinyssh TPM2 variants of mkinitcpio-systemd-extras -
but sealed to the values before the OS separator, because the code
screen's server runs ahead of it, and with tpm2-kira's own TPM code in
place of systemd-creds.

### The image's SSH host key was sealed to the TPM

From 2026-10-10 to 2026-10-23 the host key was an OpenSSH ed25519 key -
the running system's by default, or one of the image's own
(TPM2_KIRA_SSH_HOSTKEY) - whose seed every image build sealed to PCR 0+7
at the measure point; 'run' unsealed it at the code screen and kept it in
its memory. The key existed as a file on the root filesystem and, at
boot, in clear in a process: whoever read either once could sign as the
host anywhere, for good. It was replaced by an SSH CA created inside the
TPM, signing only in a state the signing key approved, which certifies a
host key the TPM makes for each boot under its NULL hierarchy: no key and
no secret is stored, the CA never leaves the TPM, and what a boot holds
in memory is useless after the next reboot. The clients trust the CA
(@cert-authority) instead of a key. A step in between, a long-term key in
the TPM unlocked by a secret sealed to the approved state, was dropped
before it shipped: the secret, once read from memory, would have kept
working across reboots.

### The SSH server was part of tpm2-kira

Until 2026-10-23 'remote serve' and run's side of it (the sandbox, the
control socket, the signing) were tpm2-kira's own files
(cmd/remote_serve.go, cmd/remote_privsep.go). They moved, with the TPM
host keys, into aSSH (assh/, a git submodule; github.com/tpm2-trust/assh), a project of its
own that other projects use too; tpm2-kira keeps what is its code
screen's (sessions, prompts, the console).

### The passphrase prompt was systemd's; tpm2-kira only ran before it

Until the key provider (2026-10-07), `tpm2-kira.service` showed the code,
held the boot with Type=notify until Enter, the phone's verdict or 90 s,
then sent READY and ended, and systemd's console agent asked for the
passphrase. The process had to give up the console at the end of the hold
(`TIOCNOTTY`) or the prompt never appeared. Now `systemd-cryptsetup` takes
the volume's key from `tpm2-kira-unlock.socket` (crypttab(5) AF_UNIX key
files, the socket in the key field of `/etc/crypttab`) and tpm2-kira asks
at its own prompt; the service stays until switch-root. The console is
still released with the hold, because other prompts (a token PIN, a volume
not routed through the socket) are systemd's.

### The hook rewrote the image's crypttab

The first key-provider branch (feat/unlock-disk, same day, never merged)
had the mkinitcpio hook put the socket into the key field of the image's
crypttab itself, which made it depend on sd-encrypt running first; it then
sourced sd-encrypt's build function to stand in for that hook altogether.
Dropped: the key source is configuration,
as it is for `tpm2-device=` and key files, and no hook of ours patches or
replaces a distribution hook. The crypttab line was then the documented
default for a few hours and gave way to `rd.luks.key=` on the kernel
command line, which is honoured in the initrd only and leaves the running
system's files alone (docs/UNLOCK-DISK.md §5).

### The existing passphrase went to cryptsetup on a pipe

Until 2026-10-14 the recovery passphrase that authorises luksAddKey and
luksKillSlot was written into a pipe on descriptor 3, and the prompt
refused an empty answer as "not a password". A disk encrypted with an
empty passphrase - an installer's placeholder, say - could then not be
enrolled at all, and cryptsetup refuses an empty pipe anyway ("Nothing
to read on input"). It reads an empty regular file as the empty
passphrase, so the passphrase now goes in a memfd, and the prompt takes
Enter alone; control flags such a disk red.

## control

### Guided or manual, and the one row

Until 2026-10-14 control asked at its first run how to guide, kept as
TPM2_KIRA_CONTROL=guided|manual in control.conf, switchable from the
overview's last entry. Guided put one row on top - the signing key, the
mkinitcpio configuration, the key's route, the slots, one rebuild, the
reboot ("part 1 of 2") - and the phone and the disk keys after it ("part
2"); manual was the same overview as one flat list. Both were one long
screen whose later steps appeared once the key and the hook were in
place, the network and SSH step and the debug switch appended at the
end; each step that changed the image offered its own rebuild, and the
vault was not in control at all. It became two steps: the boot chain
with its prerequisites first, then submenus each option of which is
gated by what the machine has, one rebuild for all of them. The key
moved to the TOTP codes, which it signs. A file with TPM2_KIRA_CONTROL
does not load; remove the line.

### The PIN and the SSH keys lived in control.conf's world

Until 2026-10-14 the YubiKey's PIN was a `TPM2_KIRA_PIN='...'` line in
control.conf (the file then 0600, the line read on its own, whatever the
other lines said), and the keys that may log in at boot were root's
`/root/.ssh/authorized_keys`, or a file `TPM2_KIRA_SSH_AUTHORIZED_KEYS`
named. control called the image out of date when control.conf was newer
than it - so storing the PIN at a seal asked for a rebuild that changed
nothing, and a key added to root's file was never noticed. A fingerprint
of the image's settings recorded at every build was tried the same day
and dropped as a detour: the PIN moved to `/etc/tpm2-kira/pin`, so
control.conf holds what the image is built with and its time is right
again; the keys moved to `/etc/tpm2-kira/authorized_keys`, and the image
names their SHA-256 in an empty file's name, which its listing shows. A
signature over the settings with the signing key was weighed and not
taken: it tells a change since control signed, not whether the image has
it, and the reseal after each build already signs what the image
measures. Both old lines are errors that say where the value goes now.

### The image carried everything, and the hooks decided in shell

Until 2026-10-16 every image got the code screen, its wait for
`/dev/tpmrm0` and `tpm2-kira-cap.service`, whether a slot was sealed or
the machine had a TPM at all ("a later seal needs no rebuild"). The
Bluetooth gate went in by a shell decision of each hook - `attest status
--json` for an enrolled phone, `attest signer`, `attest initramfs-deps`,
`attest config-check` - and `TPM2_KIRA_ATTEST_BLUETOOTH=always` packed it
with nothing but `seal.pub` checked, so a machine unlocking by password and
salt alone, without a TPM, still loaded the adapter's driver and started
the radio worker at boot. The network and SSH came from `remote
initramfs`, all or nothing. control told an image out of date by the
times of control.conf and the host key, the sum of the login keys in an
empty file's name (`authorized_keys.sha256-<sum>`), and a look for the
gate's files and firmware; step 1 had a "Build the boot image" step and
step 2 led with "Rebuild the boot image". It became the boot plan
(`initramfs plan`): one decision in Go, at the build, of what the image
carries - the disk unlock always, every other part only while something
uses it - named in the image with the digest of each part's settings,
which `run --plan` and the boot scripts follow and control compares with;
control builds the image once, when it is left. The four commands are
gone; an image without a plan is out of date.

## Key material

### The signing keys lived in /var/lib/tpm2-kira/keys

Until 2026-10-07 `setup` created `/var/lib/tpm2-kira/keys/` (seal.pub,
seal.key), and a failed NVRAM rewrite stashed the blob under
`/var/lib/tpm2-kira/recovery/`. Both moved to `/etc/tpm2-kira/` (`keys/`,
`recovery/`), where systemd keeps its own key material
(`/etc/systemd/tpm2-pcr-*`); nothing of tpm2-kira's is left under
`/var/lib`. No migration: an installed system moves the keys directory by
hand before the next `reseal`.

## Factor release

### The first draft had a separate combiner and a provider interface

PLAN-FACTORRELEASE.md as drafted kept hashpwd2 a separate program: a
`factor release` command printed the salt as one hex line on stdout (an
"interface 1" with exit codes 0-5), a derivation unit and a shell script
fed it with the password into hashpwd2, and the key file went to
`/run/cryptsetup-keys.d`. The release key had a `PolicyOR` with a
`PolicySigned` branch the phone could open after a PCR change. Reviewed
on 2026-10-07: the combiner is inside tpm2-kira (`cmd/combine.go`,
hashpwd2's bytes), the answer goes to systemd-cryptsetup over the key
socket, and the release key's policy is the slot's approval plus the
command code, with no branch the phone can open: only a boot the
machine's signing key approved at seal or reseal gets the factor.

## Attestation

### attest.conf had a mode: TPM2_KIRA_ATTEST=off|lazy

Until 2026-10-07 the phone was served at boot only with
`TPM2_KIRA_ATTEST=lazy` in `/etc/tpm2-kira/attest.conf` (`off` by
default), `attest gate` took `--mode lazy`, and `tpm2-kira run` decided
whether to coordinate a gate by that line. Removed with the enforced mode
below: there was nothing left to choose. A phone is served whenever one
is enrolled and the hook found the adapter; `attest.conf` keeps the
adapter and the timeouts, and a `TPM2_KIRA_ATTEST=` line is refused.
`run` knows the gate is in the image by the signer the hook put there
(`/etc/tpm2-kira/attest-signer.pem`).

### An enforced mode was planned

PLAN-BLE.md §7 designed `TPM2_KIRA_ATTEST=enforced`: hold the boot until
the phone's verdict is `ok`, with a fail-closed matrix and an image-pinned
anchor. Dropped on 2026-10-07, never implemented. The disk unlock goes
through systemd-cryptsetup's key-file socket, where a wrong or missing
answer falls back to systemd's own prompt; an enforced mode would have had
to never answer, a local software gate the plan itself rated worthless
without an authenticated image. The intention is that tpm2-kira informs
and the passphrase can always be entered by hand; enforcement, where
wanted, is a missing factor (PLAN-FACTORRELEASE.md).

## The unlock mode

### TPM2_KIRA_UNLOCK in control.conf

How the disk's key was made at boot was configured: TPM2_KIRA_UNLOCK in
/etc/tpm2-kira/control.conf (skip, password+salt, password+remotesalt),
copied into the initramfs, so an enrolment needed the mode set and a
rebuild, and a mode that did not fit the keyslots derived a key that
opened nothing - status had three notes only for such mismatches. Now the
keyslot's token in the volume's own LUKS2 header names the recipe, and the
key provider reads the header the moment the volume asks
(cmd/luks_header.go): nothing to configure, nothing to copy, nothing to
mismatch, and no rebuild after an enrolment. A leftover TPM2_KIRA_UNLOCK
line is an error that says to remove it. The mode names live on as the
token's mode values.

## LUKS keyslot token

### One token type, the mode in a field

The token's type was "tpm2-kira" for both modes, the mode a JSON field: a
plain 'cryptsetup luksDump', which shows only the types, could not tell a
password+salt keyslot from a password+remotesalt one. Now the type
carries the mode - tpm2-kira-salt and tpm2-kira-remotesalt ('+' is not
allowed in a token type) - and the mode field is gone. A token of the old
type is recognised only to say what to do now: remove it (cryptsetup
token remove --token-id N) and mark the keyslot anew.

### Every mode bound to a slot

For a short while every token carried `slot` (0 by default), whatever the
mode, and deleting a slot took every keyslot bound to it - the typed-salt
keyslot included, although no TPM is in its key. That made removing a
slot overwrite protection that did not depend on it. Now only
`password+remotesalt` binds (the slot whose enrolment releases its salt);
a `password+salt` token carries no `slot`, survives every slot, and
coexists with the remote-salt keyslot as the typed fallback.

### `slot` only for the remote salt

The LUKS2 token (`type: tpm2-kira`) first carried its `slot` field only in
`password+remotesalt` mode, as "the slot whose remote salt it is"; a
`password+salt` token named no slot. So nothing tied a typed-salt keyslot
to the slot whose protections it rode on, deleting a slot could not take
its keyslots with it, and a keyslot left behind was invisible as such. Now
every token carries `slot` (0 unless `--nvram` names another), deleting a
slot deletes its keyslots, and a keyslot outliving its slot is reported as
the slot being dirty. A token written before this change reads as bound to
slot 0, which is where every keyslot of a one-slot machine belonged anyway.

## Blob format

### Version 14 — a slot with phones has no TOTP key; phones carry no name

Until 2026-10-10 the first phone enrolled for a slot joined its TOTP key:
the code was shown next to the phone's and either could release the boot.
Now a slot is checked one way at a time - its TOTP key, or its phones - and
the first phone retires the key (the last one leaving brings a new one).
The phone's check covers what the code proves; keeping both was a second,
weaker path to the same verdict, and one more secret in an authenticator.
The fallback slot keeps its code for the boot without a phone.

In the same change the phone stopped sending its name (its model) and the
machine stopped storing and showing it, and the phone stopped using one
channel key and one id for every machine: each enrolment makes new ones,
kept in that machine's record (machine record version 4). What a machine
keeps of a phone - readable by anyone with TPM access - no longer names it
or links it to other machines (SECURITY-BACKGROUND §3.1).

### Version 13 — only what is used; the TPM's limit decides

The blob lost what only described how it was made: the tool's version (in
the TOTP part and in the attestation part), the event log's path, the time
and event counts of the calculation, the measure-point description and how
it was detected (one flag remains; `info` derives the extends from the
eventlog PCRs), the signing key files' paths (the key is found at the
default location or through `--privkey`, never through the blob), and the
attestation key's Name (computed from its public area). About 100 bytes for
a slot of register PCRs, more with eventlog PCRs, all of it room for phones
and, next, several kernel images per slot (docs/PLAN-SUPPORT-MULTIPLE-UKI.md).

`attest enrol` refused a phone when the blob would not fit with another
phone of the largest size the format allows, and assumed a 512-byte blob
signature when it had none: a second phone was refused on a TPM with room
for it. Now every write is compared with the TPM's `TPM2_PT_NV_INDEX_MAX`
for the blob at hand, before the old index is touched, and `seal` and
`reseal` check the same before raising the generation.

### Version 11 — the boot key

The attestation part gained a second TPM key, under the policy of the slot's
TOTP key. The phone seals a code to it at every attestation; the machine
shows the code, and the phone shows it too and waits for the person before
it signs anything (docs/SECURITY-BACKGROUND.md §3.4). Before, a boot that
matched the phone's profile was signed without a question, and nothing tied
the session to the screen in front of the person.

### Version 10 — one blob per slot; attestation as an optional part with typed methods

Remote attestation first kept its data in an NV index of its own per slot
(`0x01803020` + slot: attestation key, channel keys, the enrolled phones),
next to the sealed blob at `0x01803010` + slot and written by different
commands. The two could diverge: a TOTP key deleted while its enrolment
stayed, an enrolment made without a sealed slot and on another PCR bank, and
leftovers of one kind that the commands for the other did not see.

Version 10 puts it into the slot's blob, under the blob's signature. The
payload ends with an optional *attestation part* (identity, attestation key,
quoted PCRs, revision count) that holds typed *methods*; the phones over
Bluetooth LE are method 1, and another kind of verifier is another method.
`attest enrol` therefore needs a sealed slot, `attest unenrol` rewrites the
blob and needs the signing key, `reseal` and `seal` carry the part over, and
deleting a slot deletes everything. The record counter (`0x01803820` + slot)
stays an NV index: "can only count up" is a property of an index's type.

For one commit there were two blob versions, 9 without phones and 10 with
them, so that existing seals stayed valid. That was dropped at once: only
version 10 is read.

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
or the default location only (SECURITY-BACKGROUND §5.5), and since version 13
the blob no longer records the paths at all. A slot sealed with a custom key
needs `--privkey` on every reseal.

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

## Bluetooth in the initramfs

### The image's control.conf was the host's, filtered

Until 2026-10-10 the hooks copied `control.conf` into the image and
removed the PIN with `grep -v '^[[:space:]]*TPM2_KIRA_PIN='`. The parser
also accepts `TPM2_KIRA_PIN = '...'`, which that pattern lets through, so
a PIN in that spelling would have reached the image (a UKI on the ESP).
`control` never writes that spelling. Then for a day `attest image-config`
wrote the image's file from the parsed configuration, the radio settings
alone; now nothing of `control.conf` goes into the image at all. The gate
there takes the adapter that comes up, waits for it and a phone as long
as the code screen holds (`TPM2_KIRA_ATTEST_TIMEOUT` and `_ADAPTER_WAIT`
are gone), and logs every step when the boot settings in the TPM say
debug (`TPM2_KIRA_ATTEST_DEBUG` is gone). For a day that switch was
`tpm2-kira.debug=1` on the kernel command line; a unified kernel image
under Secure Boot has a command line nobody can edit at boot, so turning it
on meant a rebuild and a new PCR 11. It is NV index 0x01803000 now,
written by `control` with the signing key.

### The firmware came from the current boot's log alone

Until 2026-10-10 the hooks read `journalctl -k -b`: the firmware the
adapter loaded in the boot the image was built in. An Intel controller that
kept its firmware over a warm reboot names no file, the hook then fell back
to the files the modules declare (for Intel, legacy ones), and the next cold
start found its firmware missing in the initrd. Now the Bluetooth lines of
every boot the journal keeps are read, what was found is remembered per
adapter, an Intel `.sfi` brings its `.ddc`, and `control` shows the
firmware the image will get.

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

### go-tpm is pinned to an unreleased commit

go-tpm v0.9.8 cut an authorization value at its first zero byte in HMAC
sessions (`hmacKeyFromAuthValue`), where the TPM drops only trailing zeros
(Part 1, 19.6.5, Note 2): the HMACs disagreed and the TPM answered
`TPM_RC_BAD_AUTH`, or `TPM_RC_AUTH_FAIL` with a dictionary-attack count for
an object without NoDA. aSSH's per-boot host keys have random 32-byte
authorization values, so about one in eight failed to sign; aSSH worked
around it by drawing values without a zero byte (`hostkey.authValue`).

Upstream fixed it in google/go-tpm#446 (commit 36f2059, 2026-10-01), after
v0.9.8 and not yet in a release. Since 2026-10-24 aSSH, tpm2-kira and
tpm2-kira-vault require `v0.9.9-0.20261001171150-36f205946d7e`, and the
workaround is gone: host keys use plain random values, and
`TestHostKeysSign` checks values with zero bytes inside, first and at the
end. Move to the first go-tpm release that contains #446.

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
