# Holding the signing key on a YubiKey

tpm2-kira can keep its PolicySigned recovery key in a YubiKey PIV slot instead
of a PEM file on disk. The key is then never readable — not by root, not from a
stolen disk — and using it needs the physical token plus a PIN.

A key file on disk remains the default. Everything here is opt-in.

---

## What needs the token, and what does not

| Command | Needs the YubiKey? |
|---|---|
| `reveal`, `reveal-plain`, `run` | **No.** The TPM releases the secret on matching PCRs alone. This is what runs at boot, in the initramfs. |
| `info`, `nvram list/status/delete` | No. |
| `seal`, `setup` | Yes — the NVRAM write policy is PolicySigned. |
| `reseal` | **Yes, always** — even when the PCR values still match. Unsealing may succeed through the PCR branch, but writing the new blob back needs a signature. |

The last row is the one that shapes day-to-day use: after a kernel or initramfs
update you need the token plugged in to reseal. If it is not there, tpm2-kira
says so and changes nothing — see [When the token is
absent](#when-the-token-is-absent).

---

## tpm2-kira never writes to the token

There is no key generation, no certificate import and no management-key
handling in tpm2-kira. It reads a slot's public key, verifies a PIN, and asks
the card to sign. Nothing else.

That is deliberate. It keeps the card code small enough to trust in a recovery
path, and it means a bug in tpm2-kira cannot damage or lock a key — which
matters if the slot also holds your Secure Boot signing key.

**Populating a slot is `ykman`'s job.** The rest of this document assumes it.

---

## Requirements

```bash
# Arch
sudo pacman -S pcsclite yubikey-manager
sudo systemctl enable --now pcscd

# Debian / Ubuntu
sudo apt install pcscd yubikey-manager
sudo systemctl enable --now pcscd
```

tpm2-kira talks to `pcscd` over its socket and links no PC/SC library, so the
binary stays statically linked and the initramfs needs nothing extra. `pcscd`
must be running when you seal or reseal; it is not needed at boot.

### pcsc-lite 2.x asks polkit first

This one is worth setting up before you need it, because it fails in the least
convenient place.

pcsc-lite 2.x (Arch, Debian trixie and newer) checks polkit before accepting any
client, and the shipped policy is:

```xml
<allow_any>no</allow_any>
<allow_inactive>no</allow_inactive>
<allow_active>yes</allow_active>
```

There is no exemption for root. An interactive `sudo tpm2-kira reseal` normally
still counts as an active session and works. A reseal that runs **unattended** —
from the mkinitcpio post hook inside a pacman transaction, from a systemd unit,
from cron or over ssh without a seat — has no active session, so pcscd refuses
it and closes the connection.

tpm2-kira reports that explicitly rather than as an unhelpful socket error, but
the fix is a polkit rule:

```javascript
// /etc/polkit-1/rules.d/50-tpm2-kira-pcsc.rules
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.user == "root") {
        return polkit.Result.YES;
    }
});
```

That grants root access to the daemon, which is the same privilege level that
already owns `/dev/tpm0` and the signing key, so it concedes nothing new. pcsc-lite
1.9.x (Debian bookworm) has no polkit check and needs none of this.

---

## Preparing a key

### Option A — a fresh key, generated on the token

This is the recommended setup. The key is created inside the YubiKey and has
never existed anywhere else.

```bash
# 1. Generate an ECC P-256 key in slot 9a, on the token.
#    --pin-policy ONCE   one PIN verification covers a whole reseal
#    --touch-policy NEVER  no touch needed; the reseal after an initramfs
#                          rebuild runs unattended, with nobody there to touch it
ykman piv keys generate \
    --algorithm ECCP256 \
    --pin-policy ONCE \
    --touch-policy NEVER \
    9a /tmp/seal.pub

# 2. PIV exposes a slot's public key through its certificate, so give the slot
#    a self-signed one. The subject is cosmetic.
ykman piv certificates generate --subject "CN=tpm2-kira" 9a /tmp/seal.pub

rm /tmp/seal.pub

# 3. Set a PIN if you have not already. The factory default is 123456.
ykman piv access change-pin
```

Then register it with tpm2-kira:

```bash
sudo tpm2-kira yubikey adopt --key 'yubikey:slot=9a'
```

`adopt` is read-only. It reports what the slot holds, checks that your TPM can
actually load the key for PolicySigned, caches the public key at
`/var/lib/tpm2-kira/keys/seal.pub`, and prints the reference to use:

```
YubiKey 12345678, slot 9a (PIV Authentication)
  Key:         ECDSA-P-256
  Fingerprint: 3f9a1c4e7b2d8051
  PIN policy:   once per session
  Touch policy: never
  Origin:       generated on the token
  TPM check:   the TPM can load this key for PolicySigned

  Public key cached at: /var/lib/tpm2-kira/keys/seal.pub

Seal against this key with:
    sudo tpm2-kira seal --privkey 'yubikey:serial=12345678;slot=9a' --pubkey /var/lib/tpm2-kira/keys/seal.pub
```

Finally, seal:

```bash
export TPM2_KIRA_PIN=12345678

sudo -E tpm2-kira seal \
    --pcrs "0,7" \
    --privkey 'yubikey:serial=12345678;slot=9a' \
    --pubkey /var/lib/tpm2-kira/keys/seal.pub
```

Scan the QR code into your authenticator app. The key reference is stored in the
sealed blob, so later reseals need no flags at all.

> `sudo -E` passes `TPM2_KIRA_PIN` through. Without `-E`, sudo drops it and
> tpm2-kira will prompt instead — which is fine interactively.

### Option B — reusing a key you already have on the token

If a slot is already populated, for example with the key sbctl uses to sign your
Secure Boot components, skip the generation step entirely:

```bash
sudo tpm2-kira yubikey list                       # see what is in each slot
sudo tpm2-kira yubikey adopt --key 'yubikey:slot=9c'
```

Any key the TPM can load works: ECC P-256, ECC P-384 or RSA-2048. RSA-4096 is
accepted by the card but many TPMs refuse it in `TPM2_LoadExternal`, and `adopt`
tells you so rather than letting you find out during a recovery.

Read [Sharing a slot with sbctl](#sharing-a-slot-with-sbctl) before doing this —
there is one ordering rule that matters.

### Moving from an existing PEM key

Generate a fresh key on the token as in Option A, then reseal onto it:

```bash
sudo -E tpm2-kira reseal \
    --privkey 'yubikey:serial=12345678;slot=9a' \
    --pubkey /var/lib/tpm2-kira/keys/seal.pub
```

Reseal unseals with the old policy and re-binds the new blob to the new key, so
the TOTP secret is preserved and your authenticator app keeps working.

Once that succeeds, and only then, remove the old private key:

```bash
sudo shred -u /var/lib/tpm2-kira/keys/seal.key
```

There is no import path in tpm2-kira. A key that was imported has existed off
the token, which defeats the point of moving it there; `yubikey list` reports
imported keys as such.

---

## Choosing a slot and its policies

`adopt` accepts any PIV key slot — `9a`, `9c`, `9d`, `9e`, or the retired slots
`82`–`95` — and reports the policies it finds rather than insisting on one
configuration. What the choice costs:

| Slot | Note |
|---|---|
| **9a** (PIV Authentication) | Recommended for a dedicated tpm2-kira key. Its PIN policy can be `ONCE`. |
| **9c** (Digital Signature) | PIV **mandates** PIN policy `always`, so the PIN is verified before every signature. tpm2-kira handles that, but the PIN must be available for the whole run. This is the usual home for an sbctl key. |
| 9d, 9e, 82–95 | Work the same way. `9e` needs no PIN at all in PIV, which is weaker. |

| Touch policy | Effect on tpm2-kira |
|---|---|
| `NEVER` | Recommended. The reseal that runs automatically after an initramfs rebuild has nobody present to touch the token. |
| `CACHED` | One touch covers 15 seconds, so usually one touch per reseal. Workable interactively. |
| `ALWAYS` | One touch **per signature**. A reseal signs about three times per NVRAM slot, so a four-slot machine wants a dozen touches — and an unattended reseal will simply time out. |

A reseal performs roughly three signatures per NVRAM slot: one to unseal through
the PolicySigned branch, one over the blob metadata, and one for the NVRAM write.

---

## The PIN

tpm2-kira looks for the PIN in this order:

1. **`TPM2_KIRA_PIN`** environment variable.
2. **`--pin-file <path>`** — refused unless the file's mode denies access to
   other users (`chmod 600`).
3. **An interactive prompt**, with echo off, when stdin is a terminal.

If none of those yields a PIN, the key counts as unavailable and `reseal` takes
the skip path below instead of hanging on a prompt nobody would see.

The PIN never appears in output, including under `--debug`.

### What an environment variable costs

`TPM2_KIRA_PIN` is visible in `/proc/<pid>/environ`, which is root-only — and
`reseal` already runs as root, so no privilege boundary is crossed. It does land
in your shell history if you type it inline, and it is inherited by child
processes. The mitigating fact is that the PIN alone authorises nothing: without
physical possession of the token it is useless. That is exactly the property you
are buying by moving the key onto hardware.

### Lockout safety

A PIV PIN allows **three attempts**. Exhausting them requires the PUK;
exhausting the PUK destroys the slot permanently. tpm2-kira is careful here:

- The token is opened once per process and the PIN verified once, so a reseal
  across several NVRAM slots does not retry a wrong PIN per slot.
- A rejected PIN **aborts the whole run** immediately. Nothing else is tried.
- If only one attempt remains, tpm2-kira **refuses to try at all** and tells you
  to verify the PIN by hand first.
- `reseal` and `yubikey status` report the remaining attempts when it is below
  three.

A successful verification resets the counter, so slots with PIN policy `always`
are not a risk in themselves.

---

## When the token is absent

`reseal` cannot do anything useful without the key, so it does nothing — and
says so clearly rather than failing:

```
tpm2-kira: SKIPPED: resealing did not happen — the signing key was not available.
  NVRAM slot:    0x01803010 (slot #0)
  Key reference: yubikey:serial=12345678;slot=9a
  Reason:        no YubiKey with serial 12345678 is present
  Consequence:   the sealed policy still binds the PCR values from before this
                 change. At the next boot tpm2-kira will report a PCR MISMATCH
                 and show no TOTP code. That is expected here — it is not
                 evidence of tampering.
  Affected PCRs: 0 (register), 7 (register)
  Nothing was changed: the sealed secret in NVRAM is untouched.
  To fix:        make the key available and run:
                     export TPM2_KIRA_PIN=...
                     sudo tpm2-kira reseal --nvram 0x01803010
```

The sealed blob is left exactly as it was — this is checked before the TPM is
touched, not discovered halfway through. Plug the token in, reseal, and the next
boot shows a code again.

Pass `--require-key` to turn the warning into a failure instead, for scripts
that must not silently skip.

---

## Sharing a slot with sbctl

Using one key for both Secure Boot signing and TOTP resealing is a design
tpm2-kira already endorses for file-based keys (see SECURITY-BACKGROUND.md §11):
the same key that signs your boot components authorises resealing, with no extra
secret to manage. Moving it onto a token strengthens that, and tpm2-kira's
read-only posture means it cannot damage the key it is borrowing.

Two things follow.

**One token gates two things.** Losing it costs both Secure Boot signing and
TOTP recovery. Keep a backup plan (below).

**Secure Boot key rotation has a mandatory order**, because a PIV slot holds one
key at a time. Rotating closes both PolicyOR doors at once: enrolling new Secure
Boot keys moves PCR 7, and replacing the slot key invalidates the PolicySigned
branch, which is bound to the old key. Do both before resealing and nothing can
unseal the blob.

The order works because a reseal needs the *old* key only to unseal and the
*new* key only to write:

```
1. replace the slot key K_old -> K_new        (PCR 7 has not moved yet)
2. sudo -E tpm2-kira reseal --pubkey <new.pub>
      unseals through the PCR branch, re-binds the signed branch to K_new
3. sbctl enroll-keys with K_new               (PCR 7 moves now)
4. reboot -> PCR mismatch -> sudo -E tpm2-kira reseal
      unseals through PolicySigned with K_new, re-binds PCR 7
```

Step 2 is the one that must not be skipped: it is the only moment when the blob
can be re-pointed at the new key without needing the old one, because the PCR
branch still opens on its own.

**The simplest way to avoid all of this is not to share the slot.** Put the
sbctl key in `9c` and a dedicated tpm2-kira key in `9a` on the same token — one
device, two independent keys, no rotation coupling.

---

## Backups: a lost token is a lost recovery key

A lost PEM file can be restored from backup. A lost token cannot, and the
signing key is the only recovery path for a secret that is still sealed in the
TPM. PolicyOR has exactly two branches, so a second independent token cannot
simply be added.

The options are:

1. **Keep an offline PEM backup key** and treat the token as the everyday key.
   Switching to the backup is a reseal with `--pubkey`/`--privkey` pointing at
   it. This partially gives back what the token removed — the key exists in a
   file again — so keep that file offline.
2. **Accept the loss.** If the token goes, `tpm2-kira seal` afresh and re-enrol
   your authenticator app. The TOTP secret cannot be carried across.

Decide which before you need it.

---

## Troubleshooting

**`pcscd is not running or its socket is not reachable`**

```bash
sudo systemctl enable --now pcscd
ls -l /run/pcscd/pcscd.comm
```

**`no smart card reader has a card in it`** — the YubiKey is not plugged in, or
its CCID interface is disabled:

```bash
ykman config usb --list      # "OTP", "FIDO2", "PIV" ... PIV needs CCID enabled
ykman config usb --enable PIV
```

**`no YubiKey with serial N is present`** — a different token is plugged in.
`tpm2-kira yubikey list` shows the serials. A reference without `serial=` uses
whichever token is found.

**`slot 9a holds no key`** — the slot was never populated, or has a key but no
certificate on firmware older than 5.3. Run the `ykman piv certificates
generate` step from Option A.

**`the TPM cannot load this key`** — usually RSA-4096. Use ECC P-256 or
RSA-2048.

**`pcscd closed the connection during the handshake`** — almost always polkit
refusing an unattended client on pcsc-lite 2.x. Check the daemon log:

```bash
sudo journalctl -u pcscd | grep -i "unauthorized"
```

`Rejected unauthorized PC/SC client` confirms it; install the polkit rule from
[pcsc-lite 2.x asks polkit first](#pcsc-lite-2x-asks-polkit-first).

**`pcscd accepted none of the protocol versions this build implements`** —
tpm2-kira speaks 4.5 (pcsc-lite 2.x) and 4.4 (1.9.x) and refuses to guess at a
layout it was not written against, because misreading it would corrupt commands
rather than fail cleanly. Please report it with `pcscd --version`.

**Wrong PIN, and now only one attempt remains** — tpm2-kira will refuse to try
again. Verify the PIN by hand:

```bash
ykman piv access change-pin      # asks for the current PIN first
ykman piv access unblock-pin     # if it is already blocked; needs the PUK
```

---

## Commands

```bash
tpm2-kira yubikey list                             # tokens, slots, policies, PIN retries
tpm2-kira yubikey adopt   --key 'yubikey:slot=9a'  # validate and cache the public key
tpm2-kira yubikey status  --key 'yubikey:slot=9a'  # is it present? retries left?
tpm2-kira yubikey export-pubkey --key 'yubikey:slot=9a' --out seal.pub
```

Reference syntax:

```
yubikey:                          first token found, slot 9a
yubikey:slot=9c                   first token found, slot 9c
yubikey:serial=12345678;slot=9a   that specific token
```

Anything that does not begin with `yubikey:` is a filesystem path, so existing
`--privkey /path/to/key.pem` invocations are unchanged.


---

## Testing without hardware

The card code is exercised end to end without a YubiKey, using the vsmartcard
virtual reader:

```bash
make test-docker                      # pcsc-lite 2.x   (protocol 4.5)
make test-docker BASE=debian:bookworm # pcsc-lite 1.9.x (protocol 4.4)
make test-docker-all                  # both
```

That runs the unit tests, the software-TPM integration suite, and the PC/SC
tests: a virtual PIV card backed by a software key, reached through a real
`pcscd`, driven by `internal/piv`. Both pcsc-lite generations are worth running,
because `internal/pcsc` implements the wire format by hand and only a live
daemon can tell whether it is right — the command enum being off by one was
found exactly this way.

With a local `pcscd` and `vsmartcard-vpcd` installed, the PC/SC tests alone are:

```bash
make test-pcsc
```
