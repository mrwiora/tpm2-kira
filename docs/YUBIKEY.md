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

Set this up before you need it, because it fails in the least convenient place.

pcsc-lite 2.x checks polkit before accepting **any** client, and refuses by
closing the connection. The shipped policy
(`/usr/share/polkit-1/actions/org.debian.pcsc-lite.policy`) is:

```xml
<action id="org.debian.pcsc-lite.access_pcsc">   <!-- and .access_card -->
  <defaults>
    <allow_any>no</allow_any>
    <allow_inactive>no</allow_inactive>
    <allow_active>yes</allow_active>
  </defaults>
</action>
```

There is **no exemption for root**. Only a process in an *active* login session
is allowed, which means:

| How you run it | Works? |
|---|---|
| `sudo tpm2-kira reseal` from a terminal you are logged into | Yes — the session is active |
| The reseal hook during `mkinitcpio -P` run from that terminal | Usually, it inherits the session |
| `pacman -Syu` triggering the hook from a terminal | Usually |
| A systemd service or timer | **No** — no session |
| cron, or `ssh host tpm2-kira reseal` without a seat | **No** |
| A rescue shell or a serial console | Often **no** |

Which pcsc-lite you have decides whether this applies at all:

```bash
pcscd --version          # 2.x asks polkit; 1.9.x has no polkit support
```

Arch and Debian trixie ship 2.x. Debian bookworm ships 1.9.9 and needs none of
this.

#### The rule

Both Arch (polkit 127) and Debian bookworm and newer (polkit 122+) use
JavaScript rules in `/etc/polkit-1/rules.d/`, so the same file works on both:

```javascript
// /etc/polkit-1/rules.d/50-tpm2-kira-pcsc.rules
//
// tpm2-kira reads a signing key from a YubiKey PIV slot when resealing. That
// runs as root, often unattended from an initramfs hook, where there is no
// active login session for polkit to authorise.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.user == "root") {
        return polkit.Result.YES;
    }
});
```

```bash
sudo install -m 644 -o root -g root \
    50-tpm2-kira-pcsc.rules /etc/polkit-1/rules.d/
sudo systemctl restart polkit        # not always needed; polkit watches the dir
```

Verify it:

```bash
sudo systemd-run --pipe --wait tpm2-kira yubikey list
```

`systemd-run` deliberately creates a session-less context, which is the case
that fails without the rule. If it lists your token, unattended reseals will
work.

**What this concedes:** root may talk to `pcscd` and to any card in a reader.
Root already owns `/dev/tpm0` and, on a file-key install, the signing key
itself — so on a single-user machine this grants nothing new. On a machine
where other people's smart cards get plugged in, it does let root talk to them;
narrow `subject.user` to a dedicated account if that matters.

**If you would rather not grant it**, the alternatives are to reseal
interactively (where an active session already authorises you) and let the
unattended reseal print its `SKIPPED` warning, or to run `pcscd` with
`--disable-polkit`, which turns the check off for every client rather than just
for root — a broader concession than the rule above.

#### Debian with polkit older than 0.106

Debian bullseye and older use `.pkla` files instead, but they also ship
pcsc-lite 1.9.x, which has no polkit check. If you meet a 2.x build with an old
polkit, the equivalent is:

```ini
# /etc/polkit-1/localauthority/50-local.d/50-tpm2-kira-pcsc.pkla
[tpm2-kira pcsc access]
Identity=unix-user:root
Action=org.debian.pcsc-lite.access_pcsc;org.debian.pcsc-lite.access_card
ResultAny=yes
```

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

### The PIN for an unattended reseal

The sealed blob records *which* key to use — the slot reference — but never the
PIN. NVRAM reads are open by design (the secret is protected by the sealed
object's policy, not by read control), so anything in the blob is readable by
any process that can reach the TPM and by anyone who takes the disk.

That leaves the reseal that runs automatically after an initramfs rebuild, which
has no terminal to prompt at.

#### Arch: the mkinitcpio configuration

```bash
# /etc/mkinitcpio.conf.d/tpm2-kira.conf
TPM2_KIRA_PIN=12345678
```

```bash
sudo chmod 600 /etc/mkinitcpio.conf.d/tpm2-kira.conf
```

The reseal hook reads it from there. This is safe on Arch for one specific
reason: mkinitcpio *sources* its configuration at build time and never copies
it into the image, so the PIN stays on the encrypted root.

**Use a drop-in, not `/etc/mkinitcpio.conf` itself.** The main file is mode 0644
by default, which would let every local user on the machine read the PIN. A
drop-in in `/etc/mkinitcpio.conf.d/` can be 0600, and mkinitcpio 42 and later
concatenate those files into the configuration it sources. The hook warns if it
finds the PIN in a file others can read.

#### Debian: not in `initramfs.conf`

There is no equivalent on Debian, and the obvious file is a trap.
`mkinitramfs` copies `/etc/initramfs-tools/initramfs.conf` and `conf.d/*` **into
the image**, and so does tpm2-kira's own hook for
`/etc/tpm2-kira/initramfs.conf`. The image lives on `/boot`, which is not
encrypted — that is the premise this whole project rests on. A PIN there would
be written in cleartext to the one partition an evil-maid attacker can read.

The build hook refuses to ship a config that sets `TPM2_KIRA_PIN`, rather than
trusting a comment to prevent it.

Debian's reseal hook does not reseal anyway (every PCR source is read from the
running system, so it would bind to the image you are leaving), so this affects
only a reseal you script yourself. Put the PIN in that script's environment, or
in a root-only file it reads.

#### Or avoid the question entirely

1. **Use a slot whose PIN policy is `never`** — `ykman piv keys generate
   --pin-policy NEVER`. The token being plugged in is then the authorisation.
   That is a coherent model: possession of the token is the factor, and no
   secret sits on disk at all. It is the best answer if you leave the token in
   during updates.
2. **Let the reseal be skipped** and run it by hand afterwards. This is the
   default, and it matches what tpm2-kira already argues for PCR 8/9 on Debian
   — keeping a human in the loop is the point.

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
tpm2-kira already endorses (see SECURITY-BACKGROUND.md §11). On a token it is
also easier than with files: a PIV slot can hold an ECC P-256 key, whereas
sbctl's own generated keys are RSA-4096, which the TPM refuses to load — sharing
a *file* key means creating an RSA-2048 pair by hand and importing it into
sbctl. The README covers that case.
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

There is a virtual YubiKey. `internal/virtualpiv` emulates the PIV application
— backed by a software key, honouring PIN and touch policy, answering GET SERIAL
and GET METADATA — and attaches to the vsmartcard virtual reader, where `pcscd`
sees it as an ordinary card. Paired with a software TPM it runs the entire
feature with nothing plugged in:

```bash
make test-docker                      # pcsc-lite 2.x   (protocol 4.5)
make test-docker BASE=debian:bookworm # pcsc-lite 1.9.x (protocol 4.4)
make test-docker-all                  # both
```

That runs four passes:

| Pass | Covers |
|---|---|
| unit | key references, blob v9, the DER-to-raw signature conversion, PIV APDUs against a mock |
| integration | seal, reseal, reveal and NVRAM restore against a software TPM |
| PC/SC | the hand-written pcscd wire format against a live daemon, and the PIV layer over it |
| YubiKey end-to-end | **both simulators at once**: seal and reseal with a key that only exists on the virtual token |

The last pass is the one that covers the feature as a user meets it: a key
reference on the command line, a PIN from the environment, the PC/SC transport,
PIV APDUs, `TPM2_PolicySigned`, and the NVRAM write. It also checks the
behaviours that are awkward to test by hand — a slot with PIN policy `always`
really is re-verified once per signature, a wrong PIN costs exactly one attempt
and then stops, unplugging the token mid-workflow produces the `SKIPPED` report
with the blob untouched, and swapping in a different token is diagnosed by name.

Running both pcsc-lite generations matters because `internal/pcsc` implements
the wire format by hand and only a live daemon can tell whether it is right —
the command enum being off by one, and the protocol version differing between
generations, were both found this way.

With a local `pcscd` and `vsmartcard-vpcd` installed, the card passes alone are:

```bash
make test-pcsc                                          # transport and PIV layer
go test -tags="integration pcsc" -run TestYubiKey -v .  # end to end
go test -tags="integration pcsc" ./...                  # everything
```

The virtual reader is a machine-wide resource and `go test ./...` runs packages
concurrently, so the emulator takes an advisory lock (`flock` on
`$TMPDIR/tpm2-kira-vpcd.lock`) for as long as a card is attached. Without it two
test processes attach cards to the same reader and pick up each other's, which
fails intermittently and looks like a bug in the code under test. The lock lives
on an open file description, so a crashed test cannot wedge the suite.

What this does **not** cover is a real YubiKey. The emulator follows the specs
tpm2-kira was written against, so anything where real firmware differs — timing,
extended APDU support over its CCID interface, quirks in a particular firmware
revision — still needs the hardware. `tpm2-kira yubikey list` with a token
plugged in is the check.
