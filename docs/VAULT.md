# The disk's key from two TPMs: local part and vault (`tpm+vault`)

> **Status:** implemented on `feat/remote-unlock` (2026-10-11): tpm2-kira's
> side (`cmd/vault.go`, `vault enrol|status|unenrol`, `luks enrol|mark
> --mode tpm+vault`, the boot's release in `run`), `vaultproto`, and the
> round trip on swtpm against the protocol (`cmd/vault_swtpm_test.go`);
> tpm2-kira-vault in its own repository beside this one.
> Version 1: unattended release by policy. Version 2 (planned): an
> operator approves each release through the vault's REST interface and
> may add a pepper (§8).
>
> The contract between both sides is the Go package `vaultproto`
> (messages, the release check, the policy digests). The vault is a
> separate program, **tpm2-kira-vault** (its own repository beside this
> one), with a TPM of its own.

## 1. The idea

A keyslot in mode `tpm+vault` opens with a key derived from two 32-byte
parts:

```
key = hex( HKDF-SHA256(ikm = L ‖ R [‖ P], salt = "",
                       info = "tpm2-kira/vault/v1" ‖ lp(label) [‖ "pepper"], len = 32) )
```

| Part | Where it is kept | Who can open it |
|---|---|---|
| **L**, local | in the slot's blob, in the machine's TPM NV, wrapped (`TPM2_MakeCredential`) for the TPM's EK and the slot's release key | this TPM, in a boot state the slot's signing key approved, before `cap` |
| **R**, remote | in the vault, wrapped the same way, encrypted under a key sealed in the **vault's** TPM | the vault releases it (§4); then only this machine's TPM opens it, under the same policy as L |
| **P**, pepper (reserved) | with an operator | given at the vault's approval, version 2 (§8) |

The machine unlocks unattended: nothing is typed. `run` opens both parts
while the code screen holds - they open only in the approved boot state,
which on a UKI system ends with the hold (the separator follows it) - and a
key made ends the hold on its own; the key provider then answers the
volume with it. If the vault does not answer, refuses, or the TPM does not
open a part, the code screen holds as it does without a vault, and after
it cryptsetup's own prompt follows, where the **recovery passphrase** of a
second keyslot opens the disk. That keyslot is mandatory; enrolment refuses
without it.

### 1.1 What the PCR state guards, on both sides

1. **The machine's TPM.** L and R open only through the release key's
   policy: the slot's approval (PolicyPCR over the sealed selection,
   PolicyNV over the generation, the signing key's signature,
   PolicyAuthorize), then PolicyCommandCode(ActivateCredential)
   (`attest/releasekey.go`, PLAN-FACTORRELEASE.md §3.2). After `cap` the
   generation index is read-locked, so in the running system - root
   included - neither part opens. A copied or relayed answer of the vault
   is useless on any other TPM.
2. **The vault's check** (`vaultproto.VerifyRelease`). The machine quotes
   the slot's selection with its attestation key over a fresh challenge of
   the vault, and sends the slot's approval signature and generation. The
   vault rebuilds the approved policy from the quoted values and verifies
   the signature with the signing key it pinned at enrolment. So it
   releases R exactly for the boot states the machine's own signing key
   approved - no list of PCR values on the vault, and a reseal after a
   kernel update needs nothing there - and refuses a generation lower than
   the highest it has seen (an approval a reseal revoked). It also refuses
   a revoked device, rate-limits, and logs every request.
3. **The vault's TPM.** Each device record is encrypted with a key sealed
   in the vault's TPM to the vault's own PCRs (default PCR 7). A copy of
   the vault's disk or a backup opens nothing; a vault booted in another
   state releases nothing.

What a vault adds over a local-only key: a machine can be **revoked** -
reported stolen, it no longer unlocks, even in a good boot state, and it
does not unlock away from the network that reaches the vault. What the
vault cannot do: open a disk. It never holds R in the clear, and without
the machine's TPM in an approved state its records are nothing.

## 2. Roles

| | tpm2-kira (machine) | tpm2-kira-vault |
|---|---|---|
| holds | L (blob), the AK, the release key | the wrapped R, the pinned device record |
| decides | nothing: its TPM enforces the policy | whether to release, by §4 |
| TPM use | AK quote, ActivateCredential under the slot's policy | sealing the record keys to its PCRs |

## 3. Enrolment

On the booted machine, with the signing key (as reseal), and a one-time
token an operator created on the vault:

```
vault:    tpm2-kira-vault token create --name db-03 [--mode auto|approve] [--ttl 1h]
          → token, the vault's URL as configured, its pin sha256:…
machine:  tpm2-kira vault enrol --url https://vault:8443 --pin sha256:… --token … --out /run/tpm2-kira/luks.key
          cryptsetup luksAddKey /dev/… /run/tpm2-kira/luks.key
          tpm2-kira luks mark /dev/… --keyslot N --mode tpm+vault
```

1. Refuse unless the recovery keyslot is confirmed.
2. Create the slot's attestation part if it has none (device ID, AK, EK
   algorithm) and the release key if it has none.
3. Draw L and R; wrap both for this TPM's EK and the release key's name.
4. `POST /v1/enrol` with the device's public data, the slot's approval
   data and the wrapped R. The vault answers with a credential for (EK,
   name of AK); the machine opens it with the AK and returns the secret
   (`POST /v1/enrol/confirm`): proof that the AK lives in that TPM.
5. Write the vault's URL and pin and the wrapped L into the slot's blob
   (signed, in NV). Nothing of R is kept.
6. Derive the key from L and R once, write it to `--out` (tmpfs, 0600) for
   `cryptsetup luksAddKey`; wipe L and R.

That the TPM opens both parts under the slot's policy is proven by the next
boot, in the initrd, as for the remote salt.

## 4. Release

```mermaid
sequenceDiagram
    participant M as run (initrd)
    participant V as vault
    participant T as machine's TPM
    M->>V: POST /v1/challenge {device_id}
    V->>M: {request_id, nonce, expires_in}
    M->>T: Quote(AK, QualifyingData(device, request, nonce), slot's selection)
    M->>V: POST /v1/release {quote, values, generation, approval}
    V->>V: VerifyRelease, revocation, rate limit, mode
    alt auto, checks pass
        V->>M: 200 released {remote}
    else approve mode (v2: operator over REST)
        V->>M: 200 pending {retry_after}; M sends the same request again
    else
        V->>M: 200 denied {reason}
    end
    M->>T: ActivateCredential(RK under the slot's policy, EK) for L and R
    M->>M: key = HKDF(L ‖ R), answer cryptsetup, wipe
```

The machine pins the vault's key: TLS 1.3, the certificate's
SubjectPublicKeyInfo must hash to the pin; no chain, no expiry (the initrd
has no clock). A failed pin is a refused vault, not a warning.

Bounds on the machine: the attempt lasts as long as the code screen holds
(90 s by default, until confirmed with the SSH server's hold 0); a vault
not reachable yet (the network coming up) is tried again each second,
a refusal is final. The network comes from the image's network setting
(REMOTE-SSH.md), which must be on; `vault enrol` says so when it is off.
The image has no resolver of its own on every system: an IP address in
the URL needs none.

### 4.1 The vault's rules

| Rule | Value |
|---|---|
| challenge | 32 random bytes, valid 120 s, for one request; a terminal answer (released, denied) consumes it |
| pending | a request in approve mode stays pending 15 min, then is denied |
| failures | 5 failed verifications in a row lock the device until an operator unlocks it |
| rate | at most 10 challenges per device per minute |
| generation | the highest verified generation is kept; a lower one is refused |
| audit | every enrolment, challenge, verification, release, denial and admin action, append-only |

## 5. The machine's configuration

The vault's URL and pin are in the slot's blob (written by `vault enrol`,
signed with the rest of it): how the disk's key is made needs no image
rebuild and nothing in control.conf. The network is the image's
(`TPM2_KIRA_NET_*`), independent of SSH. `tpm2-kira status` shows the slot's
vault and notes a tpm+vault keyslot whose slot has none; `tpm2-kira vault
status` asks the vault whether it knows the machine.

## 6. The vault

`tpm2-kira-vault`, one binary:

```
tpm2-kira-vault init   [--dir /var/lib/tpm2-kira-vault] [--listen :8443] [--url https://…] [--pcrs 7]
tpm2-kira-vault serve  [--dir …]
tpm2-kira-vault token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE]
tpm2-kira-vault devices
tpm2-kira-vault device show|revoke|unrevoke|unlock|mode DEVICE [auto|approve]
tpm2-kira-vault requests
tpm2-kira-vault request approve|deny ID
tpm2-kira-vault audit [--follow]
tpm2-kira-vault reseal [--pcrs 7]     # asks for the recovery key
```

- **Keys at rest.** Each device record's wrapped R is encrypted with
  AES-256-GCM under a per-device key K_dev. K_dev is sealed in the vault's
  TPM (a sealed data object under the owner hierarchy's storage primary,
  PolicyPCR over the vault's selection), and unsealed for each release
  only. A copy of K_dev is also encrypted to the **vault recovery key**, an
  X25519 key pair made at `init`: the vault keeps only its public half, so
  enrolment can encrypt to it while the server never holds the private
  half, which is shown once and kept offline. After a firmware or Secure
  Boot change of the vault, `reseal` takes it and seals every K_dev to the
  current PCR values.
- **Admin interface.** The same handlers as version 2's operator REST
  interface, served on a root-only Unix socket; the CLI is its client.
- **TLS.** A self-signed ECDSA P-256 certificate made at `init`; its pin is
  what machines enrol with.

## 7. Threats

| Attacker has | Result |
|---|---|
| the machine | L in its TPM; R withheld once the device is revoked, or unreachable away from the vault's network |
| the machine, the vault reachable, not revoked | unlocks only in an approved boot state, i.e. as the owner's boot would; a tampered boot gets neither part. Version 2's approval closes the rest |
| the vault's disk or a backup | records encrypted under keys sealed in the vault's TPM |
| root on the running vault | wrapped R of every device: useless without each machine's TPM in an approved state; can deny service |
| a relay or a recorded answer | opens only on the machine's TPM, under its policy |
| root on the running machine | the disk is open already; after `cap` no part opens again |

Availability is the dominant risk, as in PLAN-REMOTEUNLOCKING.md §9.3: no
vault, no unattended boot. The recovery keyslot is the answer, and the
console prompt is always there.

## 8. Version 2 (planned)

- The operator REST interface on TCP with authentication:
  `GET /v1/requests`, `POST /v1/requests/{id}/approve` (optionally with a
  pepper), `POST /v1/requests/{id}/deny`. The machine-facing protocol does
  not change: a request in approve mode is pending until then.
- **Pepper.** A device may be enrolled with a pepper: then the key is
  derived from L, R and P, and the operator supplies P with every approval.
  The derivation reserves it (§1); enabling it for a keyslot is a new
  enrolment.
