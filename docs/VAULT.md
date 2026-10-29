# The vault: the disk's key from this TPM and a vault (`tpm+vault`)

The vault is remote attestation over TLS: before it releases its part of
the disk's key, tpm2-kira-vault verifies a quote of this TPM against the
slot's approved boot state. The code (at the console or over SSH) and the
phone (at the machine) are the other two ways the boot is checked.

> Arch and Debian. Experimental. The machine unlocks unattended when the
> vault's checks pass, or once an operator approves the boot - on the
> vault, or over the vault's operator REST interface, where the approval
> can carry an operator's **pepper** that is part of the key (§12).
>
> Two programs: **tpm2-kira** on the machine, and **tpm2-kira-vault**, a
> separate service with a TPM of its own, in its own repository beside this
> one (`../tpm2-kira-vault`). Their contract is the Go package
> `vaultproto` in this repository. What is planned beyond it is
> [PLAN-VAULT.md](PLAN-VAULT.md); how the four ways of making the disk's key
> compare, [DISK-KEY.md](DISK-KEY.md).

A keyslot in mode `tpm+vault` opens without anybody typing: its key is
made from a part kept in this machine's TPM and a part kept by the vault.
Both parts open only in a boot state the slot's signing key approved, and
only before the boot is capped. The vault releases its part only to a
fresh TPM quote of such a state, and stops releasing it for a machine an
operator revokes. Without the vault, the recovery passphrase in its own
keyslot opens the disk at cryptsetup's prompt.

```bash
vault#    tpm2-kira-vault token create --name db-03     # prints the line below
machine#  tpm2-kira luks enrol /dev/sda2 --mode tpm+vault \
              --url https://vault:8443 --pin sha256:… --token …
```

Contents: [1 The idea](#1-the-idea) ·
[2 What protects the key](#2-what-protects-the-key) ·
[3 Setting it up](#3-setting-it-up) · [4 Enrolment](#4-enrolment) ·
[5 At boot](#5-at-boot) · [6 The vault](#6-the-vault) ·
[7 The machine's side](#7-the-machines-side) ·
[8 The protocol](#8-the-protocol) · [9 Threats](#9-threats) ·
[10 The code](#10-the-code) · [11 Tests](#11-tests) ·
[12 Operator approval and the pepper](#12-operator-approval-and-the-pepper) · [13 Known limits](#13-known-limits)

## 1. The idea

```
key = hex( HKDF-SHA256(ikm = L ‖ R [‖ P], salt = "",
                       info = "tpm2-kira/vault/v1" ‖ lp(label) [‖ "pepper"], len = 32) )
```

64 hexadecimal characters, the keyslot's passphrase. The derivation string
and the label are the contract with every enrolled keyslot.

| Part | Where it is kept | Who can open it |
|---|---|---|
| **L**, local, 32 bytes | in the slot's blob in the machine's TPM NV (attestation method 2), wrapped with `TPM2_MakeCredential` for the TPM's EK and the slot's release key | this TPM, in a boot state the slot's signing key approved, before `cap` |
| **R**, remote, 32 bytes | only in the vault, wrapped the same way, encrypted there under a key sealed in the **vault's** TPM | the vault releases it (§5); then only this machine's TPM opens it, under the same policy as L |
| **P**, pepper (optional, per keyslot) | with an operator; typed once on the machine at enrolment, never sent then, never stored by the vault | given with each approval over the operator interface; the vault passes it on once (§12) |

R is drawn on the machine at enrolment; the vault never sees it in the
clear. With a pepper, the slot's blob keeps an HMAC of the key (the
pepper check) to tell a mistyped pepper from the right one at boot. Neither part is ever stored in the clear anywhere; the key exists
only in the moment it is derived and handed to cryptsetup.

## 2. What protects the key

Three layers, each depending on PCR state:

1. **The machine's TPM.** L and R open only through the release key's
   policy (`attest/releasekey.go`): the slot's approval - PolicyPCR over
   the sealed selection, PolicyNV over the generation, the signing key's
   signature, PolicyAuthorize (SECURITY-BACKGROUND.md §4) - then
   PolicyCommandCode(ActivateCredential). After `cap` the generation index
   is read-locked, so in the running system, root included, neither part
   opens. A copied or relayed answer of the vault is useless on any other
   TPM.
2. **The vault's check** (`vaultproto.VerifyRelease`). The machine quotes
   the slot's sealed selection with its attestation key over a fresh
   challenge of the vault, and sends the slot's approval signature and
   generation. The vault rebuilds the approved policy from the quoted
   values and verifies the signature with the signing key it pinned at
   enrolment. So it releases R exactly for the boot states the machine's
   own signing key approved - no list of PCR values on the vault, and a
   approve after a kernel update needs nothing there - and refuses a
   generation lower than the highest it has seen (an approval an approval
   revoked). It also refuses a revoked device, rate-limits, locks a device
   after repeated failures, and logs every request.
3. **The vault's TPM.** Each device record is encrypted with a key sealed
   in the vault's TPM to the vault's own PCRs (default PCR 7). A copy of
   the vault's disk or a backup opens nothing; a vault booted in another
   state releases nothing.

What the vault adds over a local-only key: a machine can be **revoked** -
reported stolen, it no longer unlocks, even in a good boot state - and it
does not unlock away from the network that reaches the vault. What the
vault cannot do: open a disk.

## 3. Setting it up

**On the vault host** (a machine with a TPM 2.0), as root:

```bash
make -C tpm2-kira-vault build && sudo make -C tpm2-kira-vault install   # /usr/bin and the unit
tpm2-kira-vault init --url https://vault.example:8443 --pcrs 7
systemctl enable --now tpm2-kira-vault
# open TCP 8443 in the firewall for the machines
```

`init` checks that the TPM can seal and unseal, and creates
`/var/lib/tpm2-kira-vault` (0700): the TLS key with a self-signed ECDSA
P-256 certificate (valid 100 years), the configuration. It prints the
**pin** (`sha256:` over the certificate's SubjectPublicKeyInfo) and the
**vault recovery key**, shown once: write it down and keep it offline
(§6.5). `--pcrs ""` binds the device keys to the TPM only, not to the
vault's boot state; init warns about that.

**For each machine:**

1. The machine's boot image needs its network: `tpm2-kira control`,
   step 2, "Network and SSH at boot" (SSH.md §1); the network is enough,
   SSH is not needed. `vault enrol` warns when it is off.
2. On the vault: `tpm2-kira-vault token create --name NAME [--mode
   approve] [--ttl 1h]`. It prints the token, the URL, the pin and the
   exact command for the machine. A token works once. For a machine the
   vault knows already (a new TPM, a new slot): `--replace DEVICE`.
3. On the machine, with a recovery passphrase in another keyslot - in
   `tpm2-kira control`, step 2, "Disk unlock", "This TPM + a vault": it
   sets up the network when there is none, asks the URL, the pin and the
   token, asks the vault whether it answers with the pinned key before
   anything is enrolled, and shows afterwards, at every look, whether
   the vault still knows this device. Or by hand:
   `tpm2-kira luks enrol <device> --mode tpm+vault --url … --pin … --token
   … [--nvram N] [--label L] [--name NAME]`. It enrols with the vault,
   adds the keyslot (authorised by the recovery passphrase, asked) and
   marks it. Or in steps: `tpm2-kira vault enrol … --out
   /run/tpm2-kira/luks.key`, `cryptsetup luksAddKey`, `tpm2-kira luks mark
   <device> --keyslot N --mode tpm+vault`.
4. Nothing to rebuild for the key itself: the vault's address is in the
   slot's blob. The next boot unlocks unattended.

**With operator approval and a pepper** (§12):

```bash
vault#    tpm2-kira-vault config set operator-listen :8444    # serve stopped; or init --operator-listen :8444
vault#    tpm2-kira-vault operator add alice                  # the bearer token, once, and a curl line
machine#  tpm2-kira luks enrol /dev/sda2 --mode tpm+vault --pepper --url … --pin … --token …
                                                              # asks the pepper twice
anywhere$ curl -k --pinnedpubkey sha256//<pin, base64> -H "Authorization: Bearer $TOKEN" \
              https://vault:8444/v1/requests
anywhere$ curl -k --pinnedpubkey sha256//<pin, base64> -H "Authorization: Bearer $TOKEN" \
              -d '{"pepper":"…"}' https://vault:8444/v1/requests/<id>/approve
```

## 4. Enrolment

`vaultEnrolKey` (`internal/vaultkey/vault.go`), on the booted machine, with the signing
key (as slot approve):

1. Refuse unless the recovery keyslot is confirmed (`luks enrol` checks
   the device has a keyslot that is not tpm2-kira's).
2. Give the slot what it lacks: the attestation part (device ID,
   attestation key, the EK algorithm with a certificate if the TPM has
   one) and the release key under the slot's policy. A slot already
   enrolled with a vault is refused.
3. Draw L and R; wrap both for this TPM's EK and the release key's name.
   Check the blob still fits its NV index with the vault method in it.
4. `POST /v1/enrol` with the token, the device's public data (EK, EK
   certificate, AK), the slot's approval data (signing key, policyRef,
   the generation index's Name, the generation, the sealed PCR selection)
   and the wrapped R. The vault answers with a credential for (EK, name of
   AK); the machine opens it with the AK and returns the secret (`POST
   /v1/enrol/confirm`): proof that the AK lives in that TPM.
5. Write the vault's URL and pin, the label and the wrapped L into the
   slot's blob (signed, in NV). Nothing of R is kept.
6. Derive the key from L and R once, for `luksAddKey`; wipe L and R.

That the TPM opens both parts under the slot's policy is proven by the
next boot, in the initrd. `slot add` and `slot approve` keep the vault method (seal
keeps the slot's policyRef, so the release key stays valid); a phone can
be enrolled next to it and removed again without touching it.

## 5. At boot

```mermaid
sequenceDiagram
    participant M as run (initrd)
    participant V as vault
    participant T as machine's TPM
    M->>T: ActivateCredential: L (release key under the slot's policy)
    M->>V: POST /v1/challenge {device_id}
    V->>M: {request_id, nonce, expires_in}
    M->>T: Quote(AK, QualifyingData(device, request, nonce), slot's selection)
    M->>V: POST /v1/release {quote, values, generation, approval}
    V->>V: VerifyRelease, revocation, lock, rate, mode
    alt auto, checks pass
        V->>M: released {remote}
    else approve mode
        V->>M: pending {retry_after}; M sends the same request again
    else
        V->>M: denied {reason}
    end
    M->>T: ActivateCredential: R
    M->>M: key = HKDF(L ‖ R); the hold ends; cryptsetup asks, gets the key
```

- **While the code screen holds.** On a UKI system the separator extends
  the PCRs right after the hold, and the parts open only before it. So
  `run` starts the attempt for every slot with the vault method as soon as
  it starts, and the attempt lasts exactly as long as the hold (90 s by
  default; until confirmed with the SSH server's hold 0). A key made ends
  the hold on its own; the key provider then answers the volume (Arch:
  systemd-cryptsetup on the key socket; Debian: the keyscript) with it.
- **L first.** When the TPM does not open the local part, this boot state
  is not one the signing key approved, and the vault is not asked.
- **With a pepper.** The keyslot's key needs the pepper the approval
  carries; one that does not fit the slot's pepper check is never handed
  to cryptsetup: `run` says so and asks the vault again, for a new
  approval, while the code screen holds. A release without a pepper for
  such a keyslot, or with one for a keyslot without, is refused.
- **The network coming up.** A vault not reachable yet is tried again each
  second; an answer - a refusal, a vault whose key is not the pinned one -
  is final.
- **The pin.** TLS 1.3; the certificate's SubjectPublicKeyInfo must hash
  to the pin; no chain, no expiry (the initrd has no clock).
- **Without a key** (no network, refused, revoked, pending too long, the
  TPM refused): the code screen holds as without a vault, Enter or the
  SSH session continues, and cryptsetup's own prompt follows - also in
  the SSH session (SSH.md §6) - where the recovery passphrase works.
- **What it says.** On the console and in the log (Arch: the journal;
  Debian: `/run/initramfs/tpm2-kira.log`):

```
vault: slot 0: asking the vault at https://172.17.2.198:8443 for the disk's remote part ...
vault: slot 0: the vault at … is not reachable yet (… network is unreachable); trying until it is
vault: slot 0: the vault waits for an operator's approval of this boot
vault: slot 0: the pepper given with the approval does not fit this keyslot; asking the vault for a new approval
vault: slot 0: the vault waits for an operator's approval of this boot
vault: slot 0: released; the key is made
unlock: making the key for vda3_crypt, as its header says
unlock: answered for vda3_crypt (64 bytes)
```

or `vault: slot 0: no key: the vault refused: "the device is revoked"`,
then `unlock: no key for vda3_crypt: not tpm2-kira's to answer;
cryptsetup's own prompt follows (…)`.

When a volume has several of tpm2-kira's keyslots, the tpm+vault one
wins: it needs nobody (then password+phonesalt, then password+salt).

## 6. The vault

`tpm2-kira-vault`, one binary, no cgo, run by a hardened systemd unit
(root without capabilities beyond binding the port, only `/dev/tpmrm0`,
`ProtectSystem=strict`, its state and runtime directories, a system call
filter, no core dumps). Without `CAP_DAC_OVERRIDE`, root reaches the TPM
through its group: the unit has `SupplementaryGroups=tss`, because
`/dev/tpmrm0` is `root:tss` on Arch but `tss:tss` on Debian (found when
the vault first ran on Debian: "permission denied" at the first
enrolment).

### 6.1 Release rules

| Rule | Value |
|---|---|
| challenge | 32 random bytes, valid 120 s, for one request; a terminal answer (released, denied) consumes it |
| pending | a request in approve mode stays pending 15 min, then is denied; the machine re-sends the same request every 5 s and is answered by its ID; an approved request is verified again when answered, and answered for 120 s after the approval |
| pepper | a device enrolled with a pepper is always in approve mode (`device mode … auto` is refused); its approval must carry a pepper (1-256 bytes), a plain device's must not; the pepper is held in memory with the approved request, sent once with the release, then wiped - also when the approval expires or the device is revoked; never written, never logged ("approved by alice, with a pepper") |
| failures | 5 failed verifications in a row lock the device until `device unlock`; a success resets the count |
| rate | at most 10 challenges per device per minute |
| generation | the highest verified generation is kept; a lower one is refused |
| revoked | denied, "the device is revoked" |
| the vault's own boot state changed | denied, "the vault's own boot state changed: run reseal"; not counted against the device |
| audit | every enrolment, challenge, verification, release, denial and admin action, append-only, synced after each line |

Pending requests live in memory only: after a restart, the machine starts
with a new challenge. Request bodies are limited to 1 MiB.

### 6.2 Keys at rest

Each device record's wrapped R is encrypted with AES-256-GCM under a
per-device key K_dev, with the device ID as AAD. K_dev is a sealed data
object under the owner hierarchy's storage primary (re-created on each
use), with PolicyPCR over the vault's selection (SHA-256 bank), created
and unsealed through salted, encrypted sessions, and unsealed for each
release only, then wiped. A copy of K_dev is encrypted to the **vault
recovery key**, an X25519 key pair made at `init`: the vault keeps only
its public half, so enrolment can encrypt to it while the server never
holds the private half.

### 6.3 Admin interface and operator interface

**Admin:** HTTP over a root-only Unix socket
(`/run/tpm2-kira-vault/admin.sock`, 0600); the CLI is its client: `GET
/v1/devices[/{id}]`, `POST /v1/devices/{id}/revoke|unrevoke|unlock|mode`,
`GET /v1/requests`, `POST /v1/requests/{id}/approve|deny`, `POST
/v1/tokens`, `GET /v1/audit[?follow=1]`, `GET|POST /v1/operators`,
`DELETE /v1/operators/{name}`. The audit names the actor "admin".

**Operator:** the REST interface over the network, §12.

### 6.4 State directory

```
/var/lib/tpm2-kira-vault/
  config.json           listen address, URL, the vault's PCRs, TPM path, admin socket, recovery public key
  tls/key.pem, cert.pem
  devices/<id>.json     pinned device data, release state, the encrypted wrapped R,
                        sealed K_dev, K_dev encrypted to the recovery key
  tokens/<sha256>.json  unused tokens, stored only as their hash
  operators/<name>.json operators' bearer tokens, stored only as their hash
  audit.log
```

Files are 0600, written atomically (temp file, fsync, rename, fsync of
the directory). `init` and `reseal` work on the directory directly and
refuse while `serve` holds its lock.

### 6.5 Recovery

- **The vault's boot state changed** (a firmware update, a Secure Boot
  change): `systemctl stop tpm2-kira-vault; tpm2-kira-vault reseal [--pcrs
  7]` (asks the recovery key; from stdin when not a terminal); `systemctl
  start tpm2-kira-vault`. `reseal` opens the K_dev copies and seals each
  to the current PCR values (and a new selection, given `--pcrs`).
- **The recovery key is lost and the boot state changed:** the records
  cannot be opened. Each machine unlocks with its recovery passphrase and
  is enrolled again with a `--replace` token.
- **The vault is gone:** machines fall back to cryptsetup's prompt and
  their recovery passphrase. A backup of the state directory needs the
  same TPM, or the recovery key and `reseal` on the new one.
- **A machine was reported stolen:** `tpm2-kira-vault device revoke
  DEVICE`.

### 6.6 Commands

| Command | |
|---|---|
| `init [--dir] [--listen :8443] [--url] [--pcrs 7] [--tpm /dev/tpmrm0] [--admin-socket]` | create the state directory |
| `serve [--dir]` | run the vault (the unit does this) |
| `token create --name NAME [--mode auto\|approve] [--ttl 1h] [--replace DEVICE]` | a one-time enrolment token, with the machine's command line |
| `devices` | the enrolled machines: mode, state, generation, last release |
| `device show\|revoke\|unrevoke\|unlock DEVICE` | one machine |
| `device mode DEVICE auto\|approve` | release at once, or after an operator's approval |
| `requests` | releases waiting for approval |
| `request approve\|deny ID` | decide one |
| `audit [--follow]` | the audit log |
| `reseal [--dir] [--pcrs 7]` | seal every device key to the vault's current PCRs |
| `config set operator-listen ADDR\|"" [--dir]` | turn the operator interface on (an address, e.g. `:8444`) or off; serve stopped |
| `operator add NAME` | an operator: prints the bearer token once, the pin for curl, the URL and a curl line |
| `operators`, `operator remove NAME` | list, remove |

DEVICE is a hex device ID or a unique name. The admin commands take
`--socket`, or `--dir` for the socket of that directory's configuration.
`devices` and `requests` show whether a device needs a pepper. `request
approve` sends none: a pepper device is approved over the operator
interface.

## 7. The machine's side

- **Configuration.** None in control.conf: the vault's URL and pin are in
  the slot's blob, signed with it, so an enrolment needs no rebuild. The
  network is the image's (`TPM2_KIRA_NET_*`, SSH.md). The image may have no
  resolver: an IP address in the URL needs none.
- **The blob.** Attestation method 2 (SECURITY-BACKGROUND.md §10): URL,
  pin, label, the wrapped L, and with a pepper the pepper check. The attestation part carries the device ID,
  the attestation key and the release key, shared with the phone method.
- **The LUKS token.** Type `tpm2-kira-vault`, mode `tpm+vault`, bound to
  the slot (`"slot"`) and carrying the label. `luks status` and `status`
  describe it; deleting the slot makes the keyslot dirty.
- **Commands:**

```
tpm2-kira luks enrol <device> --mode tpm+vault --url URL --pin PIN --token T
                     [--pepper] [--nvram N] [--label L] [--name NAME] [--existing-key-file F]
tpm2-kira luks mark  <device> --keyslot N --mode tpm+vault [--nvram N]
tpm2-kira vault enrol   --url URL --pin PIN --token T --out PATH [--pepper] [--nvram N] [--label L] [--name NAME] [--yes]
tpm2-kira vault status  [--nvram N]     the slot's vault, and whether it answers for this machine
tpm2-kira vault unenrol [--nvram N]     the vault method and L out of the blob; revoke on the vault,
                                        remove the keyslot by hand
tpm2-kira status                        "enrolled with the vault at …"; notes a tpm+vault keyslot
                                        whose slot has no vault, and a vault without a keyslot
```

## 8. The protocol

JSON over HTTPS, `[]byte` as base64 (`vaultproto/proto.go`):

| Path | Request | Answer |
|---|---|---|
| `POST /v1/enrol` | `EnrolRequest`: token, device ID, name, EK, EK certificate, AK, signing key, policyRef, generation index Name, generation, selection, wrapped R, label, whether the key needs a pepper (never the pepper) | `EnrolChallenge`: enrol ID, a credential for (EK, AK Name) |
| `POST /v1/enrol/confirm` | `EnrolConfirm`: enrol ID, the opened secret | `EnrolResult`: device ID, mode |
| `POST /v1/challenge` | `ChallengeRequest`: device ID | `ChallengeResponse`: request ID, 32-byte nonce, seconds valid |
| `POST /v1/release` | `ReleaseRequest`: request ID, device ID, the quote (TPMS_ATTEST and its signature), the PCR values, generation, approval signature | `ReleaseResponse`: `released` with the wrapped R (and, for a pepper device, the operator's pepper), `pending` with `retry_after`, or `denied` with the reason |

Errors are 4xx with `{"error": …}`. The quote's qualifying data is
`SHA-256("tpm2-kira/vault/release/v1" ‖ lp(device ID) ‖ lp(request ID) ‖
lp(nonce))`. `VerifyRelease` checks, against the device pinned at
enrolment: the quote is signed by its AK, is a TPM quote
(`TPM_GENERATED_VALUE`, `TPM_ST_ATTEST_QUOTE`) with that qualifying data,
covers exactly the pinned selection, and the values reproduce its digest;
the generation is not below the minimum; the signing key's approval
verifies over `H(ApprovedPolicy(PolicyPCR(values), genIndexName, gen) ‖
policyRef)`. The policy digests are computed in software and are the very
functions tpm2-kira seals with (`internal/nvslot/policy.go` calls them).

## 9. Threats

| Attacker has | Result |
|---|---|
| the machine | L in its TPM; R withheld once the device is revoked, or unreachable away from the vault's network |
| the machine, the vault reachable, not revoked | unlocks only in an approved boot state, as the owner's boot would; a tampered boot gets neither part. Approve mode - an operator's approval, with a pepper if enrolled so - closes the rest |
| a tampered boot chain | the TPM refuses L; the vault refuses the quote on its own |
| the vault's disk or a backup | records encrypted under keys sealed in the vault's TPM |
| root on the running vault | the wrapped R of every device: useless without each machine's TPM in an approved state; can deny service |
| a relay or a recorded answer | opens only on the machine's TPM, under its policy |
| a vault impersonated on the network | the pin fails; it could only withhold R, which the real one may too |
| the machine and root on the vault, a keyslot with a pepper | still no key: the pepper is with the operators, the vault never keeps it (a pepper given to a compromised running vault is seen, though) |
| an operator's token | can approve releases and read requests and devices, nothing else; cannot revoke, enrol or read the audit |
| root on the running machine | the disk is open already; after `cap` no part opens again |

Availability is the dominant risk: no vault, no unattended boot. The
recovery keyslot is mandatory, and the console prompt is always there.

## 10. The code

| Where | What |
|---|---|
| `vaultproto/` | messages, `QualifyingData`, `PinOf`, `VerifyRelease`, the policy digests |
| `internal/vaultkey/vault.go` | the key's derivation, the pinned client, the boot's release (`startVaultKeys`, `openVaultKey`, `fetchRemote`), `vault enrol\|status\|unenrol` |
| `internal/phonegate/factor.go`, `attest/releasekey.go` | the release key and the wrap/unwrap shared with the phone salt |
| `internal/nvslot/attestation.go` | attestation method 2 |
| `internal/admin/luks.go`, `internal/diskkey/header.go`, `internal/diskkey/unlock.go` | the mode, the token, the recipe, the key provider |
| `internal/bootrun/run.go` | the attempt started with `run`, ended with the hold; a key made ends it |
| `../tpm2-kira-vault/internal/server` | the machine-facing protocol and the rules (§6.1), the admin interface |
| `../tpm2-kira-vault/internal/keys` | AES-GCM, the recovery key, the TPM sealer |
| `../tpm2-kira-vault/internal/state` | the state directory, tokens, the lock, the audit log |
| `../tpm2-kira-vault/packaging/` | the systemd unit |

## 11. Tests

- **vaultproto** (`go test ./vaultproto`): an approved boot is released;
  refused are another nonce, request or device, a moved PCR, values that
  are not the quoted ones, a rolled-back generation, a generation the
  approval is not for, another selection, a quote by another key,
  something that is not a quote; an approval of the slot is accepted without a change on
  the vault; the JSON field names.
- **tpm2-kira, unit** (`internal/admin/vault_test.go`): the key's derivation
  (labels, order, pepper), the vault method in the blob, the pinned client
  (the right key, another key, a vault not reached, its error words
  without escape sequences), the key provider and the recipe's order, the
  token.
- **tpm2-kira, swtpm** (`TestVaultPepper`): the pepper asked at
  enrolment and never sent; a mistyped pepper caught and the vault asked
  again; a release without a pepper refused.
- **tpm2-kira, swtpm** (`TestVaultKeyRoundTrip`): enrolment against a
  vault that speaks the protocol (a wrong token refused, the AK proven, a
  second enrolment refused); the boot's key equals the enrolment's; the
  vault's PolicyPCR digest equals the TPM's trial session; after a PCR
  moved the TPM refuses L and the vault is not asked, and asked directly
  the vault refuses the quote; unenrolment.
- **tpm2-kira-vault, unit**: enrolment and release with a simulated
  machine, tokens (wrong, expired, reused, replace), a wrong AK proof,
  challenge expiry and reuse, rollback, the lock and unlock, revoke, the
  rate limit, approve mode (approve, deny, expiry, an approved request of
  a device revoked meanwhile), the vault's boot state changed, the audit
  log without secrets, the pin, the CLI end to end; the pepper (forced
  approve mode, refused approvals, released once, never in the state
  directory, wiped on expiry and revocation); the operator interface
  (401s, the endpoints allowed and refused, the body limit, the failed-
  authentication limit, a removed operator); all on an injected clock.
- **tpm2-kira-vault, swtpm**: the sealer under PolicyPCR, unsealing
  refused after a PCR moved, `reseal` with the recovery key; the vault end
  to end with a moved PCR and `reseal`, and a pepper device approved over
  the operator interface with a bearer token.
- **On the test VMs** (2026-10-11): the vault on the Arch VM (PCR 7,
  Secure Boot on), the Debian VM as the machine (slot 0 sealed to PCR
  0,2,7,8,9; `luks enrol --mode tpm+vault` added keyslot 2). Three boots:
  - **auto:** back in 45 s with nothing typed; the vault released at
    generation 3, the hold ended a second later, `run` answered with the
    64-byte key;
  - **revoked:** denied ("the device is revoked"), the code screen held,
    confirmed over the initrd's SSH, cryptsetup's own prompt answered there
    with the recovery passphrase;
  - **approve mode:** pending until `request approve`, then on its own;
    the image had been rebuilt and approved in between (generation 4), and
    the vault accepted it without a change.

  Then the other way round (the same day): a second vault on the Debian
  VM (PCR 7, Secure Boot off), the **Arch VM as the machine** - UKI with
  Secure Boot, slot 0 sealed to PCR 0,2,7,11, systemd in the initrd, the
  key over the key socket:
  - **auto:** back in 32 s with nothing typed. The vault released 2.5 s
    after the first try, the key was made at 08:05:10.685, the code screen
    ended (READY) at .811, systemd-cryptsetup had the key at 08:05:11.4,
    and the separator ran at 08:05:19 - the parts were opened well before
    it. The vault accepted generation 23 (enrolled at 15, approved by
    every image build since);
  - **revoked:** denied; the code screen held, confirmed over SSH, and
    systemd-cryptsetup's own question came into the session through
    ask-password; the session that left it was asked again in the next,
    and the recovery passphrase opened the disk.

  The operator interface and the pepper, the same day: the Arch vault
  with `operator-listen :8444` and operator `alice`, the Debian VM
  enrolled again with `--pepper` (the vault forced approve mode). From
  this workstation with curl: no token → 401, an admin path → 404, a wrong
  pin → curl refused. One boot: the request appeared, `{}` was refused
  (400), a mistyped pepper was released and caught by the machine's check
  ("does not fit … asking the vault for a new approval"), the new request
  approved with the right pepper opened the disk; the pepper was in
  neither the vault's state directory nor its journal nor the machine's
  log.

  In each boot the first try came before the network was up, and the
  retry worked.

## 12. Operator approval and the pepper

**The operator interface** is a second HTTPS listener of `serve`, apart
from the machines' so the two can be firewalled apart, off until
`operator_listen` is set (`init --operator-listen :8444`, or `config set
operator-listen :8444` with serve stopped). Same certificate, TLS 1.3:
operators pin it as machines do (curl: `-k --pinnedpubkey
sha256//<base64>`, which `operator add` and `init` print).

| Endpoint | |
|---|---|
| `GET /v1/requests` | the pending and approved requests: device, pepper yes/no, generation, the quoted PCR values, where from, until when |
| `POST /v1/requests/{id}/approve` | `{}` to release, `{"pepper":"…"}` for a device enrolled with one |
| `POST /v1/requests/{id}/deny` | deny |
| `GET /v1/devices`, `GET /v1/devices/{id}` | the devices (by ID or unique name) |

Nothing else is served there (404). Authentication is a bearer token per
operator (`Authorization: Bearer …`), 32 random bytes from `operator add
NAME`, shown once and stored only as its SHA-256, compared in constant
time; a missing or wrong one gets 401 and is audited, and after 10
failures in a minute an address is refused without its token being
checked. Bodies are at most 4 KiB. The audit names the operator.

**The pepper** (§1) makes an operator part of the key: a device enrolled
with `--pepper` is released only on an approval that carries the pepper,
and its key cannot be made without it - not by the machine, not by
whoever holds the vault. What the machine and the vault do with it is in
§5 and §6.1.

## 13. Known limits

- The pepper passes through the vault's memory at every approval: a
  compromised running vault sees it then. Wiping it is best effort (Go
  decodes JSON through strings).
- The operator interface has no roles: every operator may approve every
  device.
- On Debian the code screen does not know a volume's recipe before it
  asks (no routing on the kernel command line), so after a refusal it
  says "continue to cryptsetup's prompt" without naming the vault.
- The attempt lasts as long as the hold: approve mode needs a hold long
  enough for the operator (the SSH server's hold 0, or a longer `--hold`).
- The vault's port must be open to the machines; the test VM's rule was a
  runtime one.
