# Signing keys

The signing key is the recovery path. When a firmware or kernel update changes the
PCR values, the PCR branch of the policy stops matching and the key is what lets
you reseal against the new state instead of starting over with a new TOTP secret.
It is never needed at boot.

That makes it as security-critical as the TPM policy itself: whoever holds it can
unseal regardless of PCR state. See
[SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §4.6 for what that does and does
not mean.

`tpm2-kira setup` creates an ECDSA P-256 pair at `/var/lib/tpm2-kira/keys/` and
that is the right choice for most installations. This document covers the
alternatives.

---

## Using your own key

By default, `setup` generates keys at `/var/lib/tpm2-kira/keys/`. You can supply
your own — **RSA-2048, ECDSA P-256 or ECDSA P-384**:

```bash
tpm2-kira seal --pubkey /path/to/key.pub --privkey /path/to/key.pem
```

`--pubkey` accepts a raw public key or an X.509 certificate. Both paths are
stored in the sealed blob, so later `reseal` calls need no flags.

**Keep the private key mode 0400, owned by root.** That is what `setup` writes,
and whenever the key is opened for signing — `seal`, `reseal`, `nvram restore` —
tpm2-kira checks it and reports anything looser:

```
WARNING: the signing key /var/lib/tpm2-kira/keys/seal.key is mode 0644.
  Other accounts on this machine can read it. The signing key is the recovery
  master key: whoever holds it can unseal the secret whatever the PCRs say, so
  its only protection on disk is this mode.
      sudo chmod 400 /var/lib/tpm2-kira/keys/seal.key
```

It is a warning rather than a refusal: a loose key still works, because being
unable to reseal at the moment you need to would be worse. A key that is merely
owner-writable (0600) gets a one-line note instead, since that exposes it to
nobody.

**RSA-4096 does not work.** The PolicySigned branch needs the public key loaded
into the TPM with `TPM2_LoadExternal`, and TPMs reject 4096-bit RSA there — so
does swtpm. tpm2-kira fails at seal time with a hint rather than leaving you to
discover it during a recovery. Check a key before committing to it:

```bash
openssl rsa -in key.pem -noout -text | head -1     # "Private-Key: (2048 bit)"
```

## Sharing a key with sbctl (Secure Boot)

The same key that signs your boot components can authorise TOTP resealing, so
there is no second secret to manage. It needs one preparation step, because
**sbctl's own keys cannot be used**: `sbctl create-keys` generates RSA-4096, and
sbctl offers no option to change that.

Check what you have:

```bash
sudo openssl rsa -in /var/lib/sbctl/keys/db/db.key -noout -text | head -1
```

If it says 4096, either keep a dedicated tpm2-kira key (the default, and the
simplest choice) or create a Secure Boot db key that both tools can use. RSA-2048
is the right size: it is what UEFI firmware expects for a db entry, and it is
universally supported by TPMs.

```bash
# Generate an RSA-2048 db key and self-signed certificate.
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout db.key -out db.pem -subj "/CN=my Secure Boot db/"

# Hand it to sbctl, which will use it to sign boot components.
sudo sbctl import-keys --db-key db.key --db-cert db.pem
# ...then enroll and sign as usual: sbctl enroll-keys, sbctl sign-all

# Point tpm2-kira at the same key.
sudo tpm2-kira seal --pcrs "0,7" \
    --pubkey /var/lib/sbctl/keys/db/db.pem \
    --privkey /var/lib/sbctl/keys/db/db.key
```

Two consequences worth knowing before you choose this:

**One key now gates two things.** Compromise or loss costs both Secure Boot
signing and TOTP recovery. That is the trade you are making for having one
secret instead of two.

**Rotating Secure Boot keys has a mandatory order.** Enrolling new keys moves
PCR 7 *and* invalidates the PolicySigned branch, which is bound to the old key.
Do both before resealing and nothing can unseal the blob. Reseal onto the new
key while PCR 7 has not moved yet, so the PCR branch still opens on its own:

```
1. create the new key pair, and sbctl import-keys it
2. sudo tpm2-kira reseal --pubkey <new db.pem> --privkey <new db.key>
3. sudo sbctl enroll-keys        # PCR 7 moves now
4. reboot, then sudo tpm2-kira reseal
```

Step 2 is the one that must not be skipped: it is the only moment when the blob
can be re-pointed at the new key without needing the old one. Attempting it
later fails cleanly — reseal checks that the key it was given matches the key
being sealed against — but the blob is then only recoverable with the old key.

A YubiKey avoids the size problem entirely, since an ECC P-256 slot key is
universally supported: see [docs/YUBIKEY.md](YUBIKEY.md).

## Holding the key on a YubiKey
The signing key can live in a YubiKey PIV slot instead of a PEM file, so it is
never readable and using it needs the physical token plus a PIN. A key file on
disk stays the default; this is opt-in.

The token is needed only for `seal`, `setup` and `reseal`. `reveal` and `run` —
everything that happens at boot — never touch the signing key, so no token is
needed to see a TOTP code.

```bash
sudo pacman -S pcsclite yubikey-manager     # or: apt install pcscd yubikey-manager
sudo systemctl enable --now pcscd
```

On pcsc-lite 2.x (Arch, Debian trixie) `pcscd` asks polkit before accepting a
client, and the shipped policy allows only active login sessions — with no
exemption for root. Interactive `sudo` is fine; a systemd unit, a timer or cron
is not. That needs a one-file polkit rule, and an unattended reseal needs the
PIN somewhere the hook can read it. Both are covered in
[docs/YUBIKEY.md](YUBIKEY.md#pcsc-lite-2x-asks-polkit-first): on Arch the
PIN goes in a 0600 drop-in under `/etc/mkinitcpio.conf.d/`, which mkinitcpio
sources but never copies into the image. **Not** in Debian's `initramfs.conf`,
which *is* copied into the image and so lands on unencrypted `/boot`.

**Prepare the key.** tpm2-kira never writes to a token: it reads a slot's public
key, verifies the PIN, and asks the card to sign. Creating the key is `ykman`'s
job, which keeps tpm2-kira from being able to damage a key the slot may share
with something else.

```bash
# Generate an ECC P-256 key inside the token, in slot 9a.
#   ONCE  — one PIN check covers a whole reseal
#   NEVER — no touch required; the reseal after an initramfs rebuild is unattended
ykman piv keys generate --algorithm ECCP256 \
    --pin-policy ONCE --touch-policy NEVER 9a /tmp/seal.pub

# PIV exposes a public key through the slot certificate, so give the slot one.
ykman piv certificates generate --subject "CN=tpm2-kira" 9a /tmp/seal.pub
rm /tmp/seal.pub

ykman piv access change-pin                  # the factory default is 123456
```

**Then just run setup.** On a terminal it looks for connected tokens, lists the
keys it finds, and offers them — a key file stays the default, so pressing Enter
gives you the behaviour from [Quick Start](#quick-start):

```
Looking for a hardware token that could hold the signing key...

The signing key authorises resealing after a firmware or kernel update.
It is only needed then — never at boot — so it can live on a token that
you unplug the rest of the time.

Found these keys on connected tokens:
  1) YubiKey 12345678, slot 9a (PIV Authentication) — ECDSA-P-256
       PIN once per session, touch never

Where should the signing key live?
  [Enter]  a key file at /var/lib/tpm2-kira/keys/seal.key  (default)
  [1]      the token slot above

Choice [Enter]:
```

Choosing the slot validates it, checks your TPM can load the key for
PolicySigned, and caches the public key so later commands work with the token
unplugged — no separate `adopt` step.

No private key is written. Two files are:

| File | Contents |
| --- | --- |
| `keys/seal.pub` | the public key, cached so `reveal`, `info` and the blob signature check work with the token unplugged |
| `keys/seal.key` | a *reference* naming the token slot — not key material |

`seal.key` is the path every command defaults to and the reseal hook passes, so
it has to resolve for both variants. For a token-held key it therefore holds a
pointer rather than a key:

```
# tpm2-kira signing key reference — this file is NOT a private key.
#
# The signing key lives on a hardware token:
#
#     yubikey:serial=12345678;slot=9a
...
-----BEGIN TPM2-KIRA KEY REFERENCE-----
eXViaWtleTpzZXJpYWw9MTIzNDU2Nzg7c2xvdD05YQ==
-----END TPM2-KIRA KEY REFERENCE-----
```

sbctl does the same thing for a Secure Boot key held in a TPM: `db.key` keeps
its name and carries a `TSS2 PRIVATE KEY` block instead of a `PRIVATE KEY` one.
The gain is that one well-known path works for both variants, so no script,
hook or flag has to know which you chose.

Consequences worth knowing:

- It is mode 0644, not 0400. A slot number is not a secret, and the permission
  warning stays quiet about it.
- It is not worth backing up, and losing it loses nothing: pass the reference to
  `--privkey`, or run `tpm2-kira yubikey adopt` to write it again.
- Nothing overwrites a real key to put one there. If `seal.key` already holds
  key material, `setup` and `yubikey adopt` leave it alone and say so — that
  file may be the only copy of a key that cannot be regenerated.

setup stops there and prints the `seal` command to run next. Because the
reference is on disk, that command needs no key flags at all — only the PIN,
since sealing signs. Reading a public key from a slot needs no PIN, which is why
setup itself never asks for one.

### Where the signing key is looked for, in order

`reseal` and `nvram restore` resolve the key from the first of these that
answers:

1. **`--privkey` on the command line.** A flag someone typed is an instruction.
2. **The reference stored in the sealed blob** (`private_key_ref`), recorded at
   seal time.
3. **`/var/lib/tpm2-kira/keys/seal.key`** — the key, or the reference naming a
   token.

Then, whichever key that yields, its public half is fingerprinted and compared
with the one the blob records. A mismatch stops the operation before anything is
written.

> **Known wart: a stale blob reference outranks a corrected file.** Because step 2
> comes before step 3, moving the key to a different token or slot is not enough
> to fix resealing. `yubikey adopt` rewrites `seal.key` correctly, but the blob
> still names the old token and the blob wins, so `reseal` reports
> `no YubiKey with serial <old> is present` while the right token is plugged in
> and the file names it. It degrades safely — resealing is skipped, nothing is
> overwritten, and the next boot shows a PCR MISMATCH rather than losing the
> secret — but the way out is not the `reseal --nvram <slot>` the message
> suggests. Name the key once, explicitly:
>
> ```bash
> sudo -E tpm2-kira reseal --nvram 0x01803010 \
>     --privkey 'yubikey:serial=<new>;slot=9a'
> ```
>
> That re-records the reference in the blob, and later reseals need no flags
> again. Removing the reference from the blob entirely is the better fix, since
> where a key lives is local state and does not belong in a portable artifact;
> see [PLAN-YUBIKEY.md](PLAN-YUBIKEY.md).

If a token is connected but none of its slots holds a key, setup prints the
`ykman` commands above and lets you stop there to run them; nothing is created,
so `setup` can simply be run again.

Two flags skip the question, for scripts and for anyone who already knows:

```bash
sudo tpm2-kira setup --yubikey                  # first token found
sudo tpm2-kira setup --yubikey 'yubikey:slot=9c'
sudo tpm2-kira setup --local                    # a key file, no questions
```

Setup never asks when it is not run from a terminal — a package hook gets the
key-file default silently, exactly as before.

**Adopting a slot for an existing installation.** `setup` declines once
`/var/lib/tpm2-kira/keys` exists, so to move an already-configured system onto a
token, register the slot and reseal onto it:

```bash
sudo tpm2-kira yubikey adopt --key 'yubikey:slot=9a'

export TPM2_KIRA_PIN=12345678
sudo -E tpm2-kira reseal \
    --privkey 'yubikey:serial=12345678;slot=9a' \
    --pubkey /var/lib/tpm2-kira/keys/seal.pub
```

`adopt` is read-only: it reports the slot's key and policies, checks the TPM can
load it, and caches the public key. Resealing preserves the TOTP secret, so your
authenticator keeps working. Once it succeeds, shred the old key file.

Already have a key in a slot — the one sbctl uses to sign your Secure Boot
components, say? Skip the generation step and `adopt` it directly. Any key the
TPM can load works (ECC P-256/P-384, RSA-2048).

**Variant: importing a key generated outside the YubiKey.** Use this when the
key already exists — an RSA-2048 Secure Boot db key that sbctl keeps using from
a file, for instance — or when you want an offline backup of the recovery key,
which generating on the token cannot give you.

```bash
# An existing key, or a fresh one made off the token:
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out seal.key
#   ...or reuse /var/lib/sbctl/keys/db/db.key, if it is RSA-2048

# Import it, setting the policies at the same time.
#   --password is needed if the key file is encrypted.
ykman piv keys import --pin-policy ONCE --touch-policy NEVER 9a seal.key

# PIV exposes a public key through the slot certificate, so the slot needs one.
# Either import a certificate you already have, verifying it matches the key...
ykman piv certificates import --verify 9a db.pem
# ...or generate a self-signed one from the public half.
openssl pkey -in seal.key -pubout -out seal.pub
ykman piv certificates generate 9a seal.pub

sudo tpm2-kira yubikey adopt --key 'yubikey:slot=9a'
```

`adopt` and `yubikey list` report `Origin: imported — this key has existed
outside the token`, so the distinction stays visible later; `ykman piv keys info
9a` says the same.

Then decide what happens to the key file, because that is now where the security
of the whole arrangement rests:

- **Shred it** (`shred -u seal.key`) if the token is meant to be the only copy.
  You get the same protection as an on-token key, minus the guarantee that it
  never existed elsewhere — whether it reached a backup, a snapshot or an
  unencrypted disk before you deleted it is a question only you can answer.
- **Keep it offline** if you would rather have a backup. Losing the token
  otherwise means losing the recovery key, and re-sealing with a new TOTP secret
  and a fresh authenticator enrolment. An imported key is the straightforward
  answer to that, at the cost of a file existing somewhere.

Generating on the token (above) is still the better default when you have no
reason to hold a copy.

**Without the token, `reseal` warns and changes nothing:**

```
tpm2-kira: SKIPPED: resealing did not happen — the signing key was not available.
  Reason:        no YubiKey with serial 12345678 is present
  Consequence:   ... at the next boot tpm2-kira will report a PCR MISMATCH
                 and show no TOTP code. That is expected here — it is not
                 evidence of tampering.
  Affected PCRs: 0 (register), 7 (register)
```

The sealed secret is left untouched. Plug the token in, reseal, and the next boot
shows a code again. `--require-key` turns the warning into a failure for scripts.

See **[docs/YUBIKEY.md](YUBIKEY.md)** for slot and policy trade-offs, PIN
handling and lockout safety, the mandatory ordering when rotating a Secure Boot
key that lives in the same slot, backup strategy, and troubleshooting.
