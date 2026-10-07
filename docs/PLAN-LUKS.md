# PLAN — tpm2-kira and the LUKS keyslots

> **Status:** in implementation. Done: the keyslot token and `luks status`,
> `luks mark` (§2, §3), the unlock modes (§1). Next, in order: the
> `remotesalt` command name (§1), `luks enrol --mode password+salt`,
> `luks enrol --mode password+remotesalt`, `tpm2-kira status`, the network
> verifier (§6).
> **Changes a standing rule:** tpm2-kira may touch LUKS keyslots - only
> through the `luks` verb, only with `cryptsetup`, and every keyslot it adds
> is marked with a token (§2). `derive` and the `--out` paths stay as the
> way to run `cryptsetup` by hand.

## 1. Names

The modes say what tpm2-kira does with the disk's key, in the words a
person uses (decided 2026-10-07):

| `TPM2_KIRA_UNLOCK=` | what tpm2-kira does | without a released salt |
|---|---|---|
| `skip` | nothing: cryptsetup's own prompt asks for the LUKS passphrase (default) | - |
| `password+salt` | asks for a password and a salt, hands over hashpwd2's derivation | - |
| `password+remotesalt` | asks for the password; the salt is the one the verifier released and the TPM opened | no answer: cryptsetup's prompt, the recovery keyslot |

`password+remotesalt` exists only with an attestation: a verifier enrolled
for the slot and the remote salt enrolled with it. `luks mark` and `luks
enrol` refuse the mode otherwise, the hooks warn at image build, `run`
says so at boot. The same words name the token's `mode` (§2). What the
phone keeps is the **remote salt**; the command for it is
`tpm2-kira remotesalt enrol|status|rotate|unenrol` (today `factor …`,
renamed in the next step). "Factor" stays in the Go identifiers until the
rename of the code is its own change; PLAN-FACTORRELEASE.md is the design
of the mechanism and keeps its title. Later, with more than one verifier
able to hold a salt, the mode may name the source - `password+phone:salt`,
`password+server:salt`, an `identifier:salt` form; not yet.

## 2. Marking our keyslots: a LUKS2 token

LUKS2 keeps **tokens** in the header: JSON objects bound to keyslots,
listed by `cryptsetup luksDump`. The type name is free, and a token needs
no handler unless it is to activate the volume - ours does not, the key
still comes through the socket (Arch) or the keyscript (Debian). A token
of ours:

```json
{"type": "tpm2-kira", "keyslots": ["1"], "mode": "password+salt",
 "slot": 0, "label": "luks", "created": "2026-10-07T17:30:00Z"}
```

- `mode`: `password+salt` or `password+remotesalt` - how the key in this
  keyslot is made at the prompt.
- `slot`: the tpm2-kira slot whose remote salt it is (password+remotesalt only).
- `label`: the salt's label (PLAN-FACTORRELEASE §3); one enrolment can
  serve volumes with unrelated salts.
- `created`: when.

No key material, no secret; the header already holds the keyslot. Written
with `cryptsetup token import --json-file -`, read with
`cryptsetup luksDump --dump-json-metadata`. `luksDump` then shows
`Tokens: 0: tpm2-kira`, and tpm2-kira can find its own keyslots for
status, removal and rotation without guessing.

## 3. Commands

```
tpm2-kira luks status [<device>…] [--json]      # our keyslots per LUKS device, from the tokens
tpm2-kira luks mark   <device> --keyslot N --mode password+salt|password+remotesalt [--nvram N] [--label STR]
tpm2-kira luks enrol  <device> --mode password+salt|password+remotesalt [--nvram N] [--label STR]
tpm2-kira luks remove <device> --keyslot N
tpm2-kira luks rotate <device> --keyslot N
```

- `status` without a device looks at every `crypto_LUKS` block device
  (`lsblk`). For each keyslot it says whose it is: `tpm2-kira, password+salt`,
  `tpm2-kira, password+remotesalt, slot 0`, or `not tpm2-kira's` - the
  recovery passphrase, or a key enrolled by other means.
- `mark` writes the token for a keyslot that exists - made with `derive`
  or hashpwd2 and `luksAddKey` by hand, or before tokens existed.
- `enrol` is the whole thing: ask the password (and the salt, or run the
  remote salt's round trip with the verifier), derive, `cryptsetup
  luksAddKey` (which asks an existing passphrase to authorise - the
  recovery keyslot `enrol` insists on), import the token, set the unlock
  mode in `unlock.conf`, say "rebuild the initramfs". The derived key goes
  to `cryptsetup` through a pipe, never a file.
- `remove` is `luksKillSlot` plus the token's removal; refuses when it
  would leave no keyslot without a token (the recovery passphrase).
- `rotate` is `enrol` of a new keyslot and `remove` of the old one.

## 4. One overview

```
tpm2-kira status
  slot 0   TOTP sealed to 0e,2e,7e,11u (generation 12); release key present
           verifiers: phone "Pixel" (BLE, remote salt kept 2026-10-07)
  unlock   mode password+remotesalt (/etc/tpm2-kira/unlock.conf)
  /dev/vda2  keyslot 0 not tpm2-kira's; keyslot 2 password+remotesalt (slot 0, label luks); keyslot 1 password+salt
```

`attest status`, `remotesalt status`, `luks status` and `unlock.conf` in
one place, which is what a person wants to know before a reboot.

## 5. What stays by hand

`derive --out` and `remotesalt enrol --out` write the key to tmpfs for a
`luksAddKey` run by hand; `luks mark` then records it. People who do not
want tpm2-kira near their header keep that path; `luks status` tells them
the same as everyone.

## 6. More verifiers than a phone

The attestation commands are transport-neutral in name; the slot's blob
anticipates more methods than the phone (one typed block today). A
network verifier - a server that attests the state and may keep the
remote salt (PLAN-FACTORRELEASE §12.5) - is a *verifier kind*, not a new
command set:

```
tpm2-kira attest enrol                          # a phone over BLE, as today
tpm2-kira attest enrol --server https://host    # the same handshake over TCP
tpm2-kira attest status                         # phones and servers, per slot
tpm2-kira attest unenrol --verifier <id>
tpm2-kira remotesalt enrol --verifier <id>      # which verifier keeps the salt
```

The gate serves both at boot - the radio worker for BLE, a network worker
for the server, one coordinator, one `Release` message. What a server adds
is availability; what it loses is the thing in your pocket. A policy per
machine, not a mechanism.

## 7. Testing

| | How |
|---|---|
| token round trip | root-gated: a LUKS2 loop image, `luksAddKey`, `luks mark`, `luksDump` shows the token, `luks status` lists it; `luks remove` takes keyslot and token |
| status parsing | the `--dump-json-metadata` of a real header as test data, with and without our tokens |
| `enrol` | root-gated, both modes; the key through the pipe opens the header |
| the machines | `luks status` on the Arch and Debian VMs, whose keyslot 1 is password+salt's already (marked with `luks mark`) |
