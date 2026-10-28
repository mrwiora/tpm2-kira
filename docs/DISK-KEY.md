# The disk's key

How the key of a LUKS volume is made at boot is not configured anywhere:
the boot reads it from the volume's own LUKS2 header. The tpm2-kira token
of a keyslot names the recipe, the same on Arch and Debian, and an
enrolment needs no image rebuild. tpm2-kira never opens the disk; it
hands the key to `systemd-cryptsetup` (Arch) or `cryptroot`'s keyscript
(Debian), and their own prompt with the recovery passphrase is always the
fallback.

`tpm2-kira luks status | enrol | remove | mark | route | derive`, and
`vault` for the vault's side.

## The four cases

| the keyslot's token says | at boot, after the code screen |
|---|---|
| *(no token of tpm2-kira's)* | tpm2-kira stays out of it: cryptsetup's own prompt asks for the LUKS passphrase |
| `password+salt` | tpm2-kira asks for a **password** and a **salt** and hands over their derivation (Argon2id, 1 GiB) |
| `password+phonesalt` | tpm2-kira asks for the **password**; the salt is the one the phone released after verifying the machine and this TPM opened ([below](#password--phone-salt-passwordphonesalt)). Only with an attestation set up. Without a salt from the phone (no phone in range, nothing released) it asks for a typed salt as in `password+salt`, which opens a keyslot enrolled that way; Ctrl-C then leads to cryptsetup's own prompt |
| `tpm+vault` | nothing is asked: a local part from this TPM and a remote part from the vault, both opened only in an approved boot state, while the code screen holds; a key made ends the hold on its own ([VAULT.md](VAULT.md)) |

In every case a wrong answer, or Ctrl-C at tpm2-kira's prompt, goes to
cryptsetup's own prompt, where the recovery passphrase works - keep one
in its own keyslot. The derivation needs 1 GiB of memory in the initramfs
and takes some seconds; the keyboard layout in the initramfs must be the
one the password was typed with (`sd-vconsole` on Arch, the `keymap`
hook on Debian).

## The token

`luks mark` marks a keyslot as tpm2-kira's with a LUKS2 token in the
header (no key material). The token's type carries the mode, so a plain
`cryptsetup luksDump` tells them apart: `tpm2-kira-salt` for
`password+salt`, `tpm2-kira-phonesalt` for `password+phonesalt` (`+` is
not allowed in a token type, so the type spells it out). A `password+salt` keyslot is bound to nothing: no TPM is
in its key, and no slot's deletion takes it. A `password+phonesalt`
keyslot carries `"slot": N` - the slot whose enrolment releases its salt
(slot 0 unless `--nvram` names another) - and is deleted with that slot
([SLOT.md](SLOT.md#deleting-a-slot)). The two coexist on one
device: at boot the phone's salt is tried first, the typed salt is the
fallback. `luks enrol` adds the keyslot and marks it in one step; its design is
[PLAN-LUKS.md](PLAN-LUKS.md).

## password + salt (`password+salt`)

Nothing but what you type: a password and a salt, combined with Argon2id
(1 GiB, 16 passes, 4 lanes, 64 bytes). No TPM is in the key, so the
keyslot survives every slot, and it is the fallback of a
`password+phonesalt` keyslot when the phone is not there. `luks derive`
makes the key by hand, `luks enrol --mode password+salt` in one step.

A keyslot for `password+salt`, made on the unlocked system:

```bash
sudo mkdir -m 700 -p /run/tpm2-kira
sudo tpm2-kira luks derive --out /run/tpm2-kira/luks.key     # asks password (twice) and salt
sudo cryptsetup luksAddKey /dev/nvme0n1p2 /run/tpm2-kira/luks.key
sudo cryptsetup open --test-passphrase /dev/nvme0n1p2 --key-file /run/tpm2-kira/luks.key
sudo rm /run/tpm2-kira/luks.key
sudo tpm2-kira luks mark /dev/nvme0n1p2 --keyslot 1 --mode password+salt
```

## password + phone salt (`password+phonesalt`)

With a phone enrolled, the disk can need **both** your password and a
salt the phone keeps - the *phone salt*
(its design: [PLAN-PHONESALT.md](PLAN-PHONESALT.md)): a value only this
machine's TPM can open, and only in a boot your signing key approved. It
is released by the attestation and by nothing else: the phone enrolled
with `phone enrol`, over Bluetooth LE, hands it back after a verdict you
accept. The key in the LUKS keyslot is the derivation of password and salt,
as in `password+salt` - only that nobody types the salt.
Whoever has the disk and the password still needs the phone and this
machine; whoever has the phone and the machine still needs the password.

1. **Recovery passphrase first**, in its own keyslot, typed at
   cryptsetup's prompt - long, not the password below, written down
   somewhere safe. It is the way in without the phone, at cryptsetup's
   own prompt. `phone salt enrol` asks whether it exists.

   ```bash
   sudo cryptsetup luksAddKey /dev/nvme0n1p2
   ```

2. **Enrol the phone salt.** On the unlocked system, with Marify open on
   the phone:

   ```bash
   sudo mkdir -m 700 -p /run/tpm2-kira
   sudo tpm2-kira phone salt enrol --out /run/tpm2-kira/luks.key
   ```

   The phone shows the ordinary verdict screen with a card "Keep this
   machine's phone salt"; accepting the verdict keeps it. The phone
   hands it straight back, the TPM opens it, and only if the round trip
   gives back what was sent does tpm2-kira ask for your password and
   write the derived key - once, to tmpfs. The first enrolment of a slot
   also adds the release key to its blob (needs the signing key).

3. **Add the derived key**, remove the file, mark the keyslot - the mark
   is all the boot needs, it reads the header:

   ```bash
   sudo cryptsetup luksAddKey /dev/nvme0n1p2 /run/tpm2-kira/luks.key
   sudo cryptsetup open --test-passphrase /dev/nvme0n1p2 --key-file /run/tpm2-kira/luks.key
   sudo rm /run/tpm2-kira/luks.key
   sudo tpm2-kira luks mark /dev/nvme0n1p2 --keyslot 2 --mode password+phonesalt
   ```

At boot: code screen, the phone verifies and hands the salt back, the
TPM opens it before the OS separator, and tpm2-kira's prompt says `The
verifier released the disk's salt` and asks for the *password*. It
derives the key (1 GiB of memory, some seconds) and gives it to
`systemd-cryptsetup`. No phone, no verdict, or a TPM that refused: no
answer from tpm2-kira, cryptsetup's own prompt, the recovery passphrase.
`phone salt status` says which slots have one (`--json` for scripts);
`phone salt rotate` gives the phone a new salt and derives the new key,
after which the old keyslot is removed by hand (`cryptsetup luksKillSlot`);
`phone salt unenrol` takes the release key out of the slot, so what the
phone keeps can never be opened again, and the keyslot is removed by
hand. The phone side runs on Android; the iOS app is tested separately.

`/etc/crypttab` is not touched and does not need to be: only if a volume
is kept there with `x-initrd.attach` instead of on the command line, the
same socket goes into that line's key field
(`cryptroot UUID=… /run/tpm2-kira/unlock.sock x-initrd.attach`), and
`sd-encrypt` copies it into the image as it is. Volumes with `none` or
`-` as key file are still asked for by systemd's own console prompt;
volumes with a key file or a token (`tpm2-device=`, `fido2-device=`,
`pkcs11-uri=`) are not tpm2-kira's.

## TPM + vault (`tpm+vault`)

A keyslot in mode `tpm+vault` opens without anybody typing: a local part
in this machine's TPM and a remote part from
[tpm2-kira-vault](../../tpm2-kira-vault), both opening only in a boot state
your signing key approved. Revoked on the vault, the machine no longer
unlocks; without the vault, the recovery passphrase does.

```bash
sudo tpm2-kira luks enrol /dev/sda2 --mode tpm+vault --url https://vault:8443 --pin sha256:… --token …
```

Setting up both sides, the protocol, the vault's rules and recovery:
[VAULT.md](VAULT.md).

## The route: where the initrd takes the key from

### Arch (systemd in the initrd)

The passphrase is asked at tpm2-kira's prompt, after the code screen, for
every volume whose *key file* is tpm2-kira's socket,
`/run/tpm2-kira/unlock.sock`. That is `crypttab(5)`'s own way of taking a
key from a service ("AF_UNIX key files"): `systemd-cryptsetup` connects
to the socket and reads the key when it activates the volume. tpm2-kira
is meant for the main disk, which on a systemd initrd is named on the
kernel command line; name its key file there too, next to
`rd.luks.name=`:

```
rd.luks.name=<UUID>=cryptroot rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock
```

`<UUID>` is the LUKS UUID (`cryptsetup luksUUID /dev/<partition>`), the
same in both. `rd.luks.key=` is honoured in the initrd only
(`systemd-cryptsetup-generator(8)`), so the running system sees no
change. With a UKI the command line is the file in your preset
(`/etc/kernel/cmdline` or `/etc/cmdline.d/`); with a boot loader it is
the entry's `options` line. `rd.luks.key=/run/tpm2-kira/unlock.sock`
without a UUID routes every volume named on the command line.

Both parameters stay; a second `rd.luks.name=` with the socket as its
"name" makes systemd set up a volume called `/run/tpm2-kira/unlock.sock`
and no `cryptroot` ("Failed to start Cryptography Setup for
/run/tpm2-kira/unlock.sock").

**tpm2-kira does not edit the command line, it tells you what it should
read**: `tpm2-kira luks route` reads the files the command line comes from
(`/etc/cmdline.d/*.conf`, else `/etc/kernel/cmdline`; boot loader
entries; `/etc/crypttab`), names what is wrong for every device with a
keyslot of tpm2-kira's - the parameter missing, a doubled `rd.luks.name=`,
the socket as the volume's name, another key file - and prints the line
as it should read. `luks enrol` ends with it, `tpm2-kira status` notes it,
and `mkinitcpio -P` runs it (the hook's `the volume <UUID> is unlocked
through tpm2-kira's prompt`, or a warning with the lines to change).

The passphrase prompt is tpm2-kira's: `systemd-cryptsetup`
activates the volume with every option in your `crypttab`, connects to
`/run/tpm2-kira/unlock.sock` for the key, tpm2-kira asks `Passphrase
for disk <volume>:` and answers with what you type, or with the key the
token's recipe makes. tpm2-kira never opens the disk itself; it only
provides the key. A typo is not fatal: `systemd-cryptsetup` then asks on
its own prompt for the remaining two tries, as it does for a wrong key
file, and a recovery passphrase in another LUKS keyslot works at either
prompt. There is no mode in which tpm2-kira withholds the prompt: the
passphrase can always be entered by hand.

### Debian (initramfs-tools)

There is no `systemd-cryptsetup` in a Debian initramfs; `cryptroot` runs
a `keyscript=` from `/etc/crypttab` instead and reads the key from its
stdout. Add tpm2-kira's to the root volume's line:

```
vda3_crypt UUID=… none luks,discard,keyscript=/lib/cryptsetup/scripts/tpm2-kira
```

and `sudo update-initramfs -u`. The keyscript asks the same socket
`systemd-cryptsetup` would on Arch (`tpm2-kira unlock-key`): the display
started by `init-premount` answers once the code screen is confirmed,
with what you type at `🔐 Passphrase for disk vda3_crypt:`
(or, with a phone and a factor, the key derived from your password).
`cryptroot` re-runs the keyscript for each of its tries (`tries=`, 3 by
default): the first ones are tpm2-kira's prompt, the last is cryptsetup's
own, for the recovery passphrase; Ctrl-C at tpm2-kira's prompt goes
there at once. Without the socket (the `once` mode of `/etc/tpm2-kira/initramfs.conf`,
or `run` failed) the keyscript is
cryptsetup's own prompt, as without tpm2-kira. (On Arch, `systemd-cryptsetup`
tries a key file once: after a wrong answer at tpm2-kira's prompt its own
prompt follows.)

What the display reported at boot - when the volume asked, when the hold
ended, when the prompt opened and answered - is in
`/run/initramfs/tpm2-kira.log` after the boot (on Arch:
`journalctl -b -u tpm2-kira.service`). Tested on Debian 13 with
initramfs-tools 0.148 and cryptsetup 2.7.

## How systemd takes the key, and why this way

What systemd does to unlock a disk at boot, where it lets another program
provide the key, and how tpm2-kira uses exactly that and nothing else.
Everything here was checked against systemd 262 and mkinitcpio 42
(`crypttab(5)`, `systemd-cryptsetup@.service(8)`, `systemd.exec(5)`, the
installed binaries and the sd-encrypt install script).

### What sd-encrypt is

`sd-encrypt` is a mkinitcpio *install hook*: a bash function that runs at
image build time and copies things into the initramfs. It runs nothing at
boot. What it copies:

- `systemd-cryptsetup` and `systemd-cryptsetup-generator`;
- `cryptsetup.target`, the console password agent
  (`systemd-ask-password-console.{path,service}`);
- the dm-crypt, dm-integrity and crypto kernel modules, the TPM drivers,
  the device-mapper and FIDO udev rules;
- the LUKS2 token plugins for TPM2 and FIDO2, libcryptsetup, libfido2;
- the NvPCR definitions;
- the lines of the host's `/etc/crypttab` whose options contain
  `x-initrd.attach`, as the image's `/etc/crypttab` (mode 0600).

That is all. The unlock itself is systemd's, at boot:

1. `systemd-cryptsetup-generator` runs before any unit (generators always
   do). It reads the image's `/etc/crypttab` and the kernel command line
   (`rd.luks.name=`, `rd.luks.key=`, `rd.luks.options=`) and writes one
   `systemd-cryptsetup@<volume>.service` per volume, ordered
   `After=cryptsetup-pre.target`, `Before=cryptsetup.target`, with the
   device, key file and options as `ExecStart` arguments. So the crypttab
   information is in the image at build time and turned into units before
   the first service starts: nothing can be unlocked without it.
2. `systemd-pcrosseparator.service` (the OS separator, PCR 11) is
   `Before=cryptsetup-pre.target`: every PCR measurement that must precede
   the disk is done before any volume is touched.
3. `systemd-cryptsetup attach <volume> <device> <key> <options>` runs for
   each volume, opens the LUKS header, obtains a key (below), unlocks a
   keyslot and creates `/dev/mapper/<volume>`. A wrong key fails the unit;
   `cryptsetup.target` then fails and systemd drops to the emergency shell.
4. `cryptsetup.target` is reached; the root file system can be mounted.

### Where systemd-cryptsetup takes the key from

In this order, per volume, all documented in `crypttab(5)`:

| source | how it is configured | who provides it |
|---|---|---|
| a **credential** `cryptsetup.passphrase` / `cryptsetup.key` | `ImportCredential=`/`LoadCredential=` on the unit (a drop-in) | PID 1, from a file, an encrypted credential or a socket |
| a **key file** (third field) | path in `/etc/crypttab` or `rd.luks.key=` | the file system, or `/run/cryptsetup-keys.d/<volume>.key` |
| an **AF_UNIX key file** | a socket path in the key field | **any service listening there** |
| a **LUKS2 token** (`tpm2-device=`, `fido2-device=`, `pkcs11-uri=`) | options | the token plugin, from the header |
| the **kernel keyring** (`password-cache=`) | options | a passphrase typed earlier in this boot |
| the **password agent** | nothing (the default) | `systemd-tty-ask-password-agent` on the console, or plymouth |

The third row is the one made for a program like tpm2-kira. `crypttab(5)`:
when the key file is an `AF_UNIX` stream socket, `systemd-cryptsetup`
connects to it, reads the key until EOF, and connects from an abstract
socket named `\0<random>/cryptsetup/<volume>` so that the provider can
tell the volumes apart (`/cryptsetup-tpm2/`, `/cryptsetup-fido2-salt/`
and `/cryptsetup-pkcs11/` when a token plugin wants its *saved* key, not a
passphrase). The bytes are used exactly as a key file's bytes would be: a
typed passphrase without a trailing newline opens the same keyslot.

### The secure way to plug in

**Configure, do not patch.** A key source is the administrator's
statement, in the same place `tpm2-device=auto` or a key file would be
written. tpm2-kira is for the main disk, and on a systemd initrd the
main disk is named on the kernel command line (`rd.luks.name=`), so its
key file is named there too:

```
rd.luks.name=<UUID>=cryptroot rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock
```

`rd.luks.key=` is "the analogue of the third crypttab(5) field", honoured
in the initrd only: the generator passes the path to `systemd-cryptsetup`
as the key file, and the main system never sees it. `/etc/crypttab` is
not touched. `rd.luks.key=/run/tpm2-kira/unlock.sock` without a UUID
applies to every volume named on the command line.

A volume kept in `/etc/crypttab` with `x-initrd.attach` instead takes
the socket in that line's key field:

```
cryptroot  UUID=…  /run/tpm2-kira/unlock.sock  x-initrd.attach,discard
```

sd-encrypt copies the line into the image unchanged and the generator
turns it into the unit. After switch-root the main system's
`systemd-cryptsetup@cryptroot.service` finds the volume already active
and exits 0; the socket's absence there is irrelevant. This is the form
for a second volume, or for a setup that does not name the disk on the
command line; it is not the default, because it changes a file of the
running system for something that happens in the initrd only.

Either way no hook rewrites anything, no hook replaces another, the order
of hooks does not matter, and reading the configuration tells the truth.

**Provide the socket with a socket unit.** `tpm2-kira-unlock.socket`
creates `/run/tpm2-kira/unlock.sock` (root, 0600) `Before=cryptsetup-pre.target`
and hands it to `tpm2-kira.service` (`Sockets=`, `LISTEN_FDS`). The socket
exists before any `systemd-cryptsetup@` unit can run, whether or not the
service is up yet; a connection simply waits.

**Answer only systemd-cryptsetup, only after the hold.** The provider
refuses a peer of another uid (`SO_PEERCRED`, what the password agent
demands of a sender too), refuses a peer name that is not
`/cryptsetup/<volume>`, gives nothing to token requests (it holds no saved
token keys), and answers a request only after the code screen's hold has
ended (`sd_notify(READY)`) and the units READY let loose have printed
their console lines - the last of them `systemd-pcrnvdone.service`, "TPM
PCR NvPCR Initialization Separator", watched until active with a cap of
3 s for a machine where it never runs - one volume at a time at its own
prompt.
A derived key (password+salt, password+phonesalt) or the vault's key
goes the same way: the transfer never changes.

**Treat the bytes like libcryptsetup does.** `systemd-cryptsetup` locks
its memory (`mlockall`), keeps the key in guarded buffers and erases them
(`explicit_bzero`). tpm2-kira reads the passphrase into one fixed buffer
of cryptsetup's limit (512 bytes, no growing copy), `mlock`s it, wipes it
to its full capacity after the answer, on Backspace and on cancel, and is
not dumpable while it serves keys. Neither side can zero the kernel's
socket buffer between write and read, and neither can protect against a
hibernation image; the initrd has no swap and no hibernation.

### When the answer is wrong: systemd's prompt is the fallback

The chain, from the most convenient to the one that always works: in
a `password+phonesalt` keyslot (the recipe read from the volume's own
header at boot), the password and the salt the phone returned;
without a salt from the phone (no phone in range, nothing released), the
password and a **typed** salt - the `password+salt` variant, which opens
a keyslot enrolled that way, if there is one; and at Ctrl-C, or when the
derived key opens nothing, systemd's own prompt and the recovery
passphrase. Each step is offered at tpm2-kira's prompt and says which it
is.

What `systemd-cryptsetup` does with a key that does not open the volume
decides whether a typo at tpm2-kira's prompt, or a tpm2-kira that cannot
answer, is a reboot or a second chance. It is a second chance, by
systemd's design. From `src/cryptsetup/cryptsetup.c` (systemd 262), the
attach loop runs `tries` times (default 3, `rd.luks.options=<UUID>=tries=N`):

1. **Try 1: the key file**, our socket. The bytes are tried against every
   keyslot. A wrong key logs `Failed to activate with key file '…'. (Key
   data incorrect?)` and returns `-EAGAIN`; a key file that cannot be
   read (`… key file '…' missing.`) and an empty answer do the same.
2. On `-EAGAIN` the loop "invalidates one of the passed fields, so that we
   fall back to the next best thing": `key_file = NULL`.
3. **Tries 2 and 3: a passphrase from the password agent** - the console
   prompt that sd-encrypt installs (`systemd-ask-password-console`), on
   the console tpm2-kira gave up at the end of its hold. Any keyslot's
   passphrase works, so a recovery passphrase in a second keyslot is the
   way out of a lost or wrong tpm2-kira answer.
4. Only after the last try: `Too many attempts to activate; giving up.`;
   the unit fails, `cryptsetup.target` fails, the initrd reaches
   `emergency.target`. In an initrd `sulogin` finds the root account
   locked and offers nothing but Enter, which fails again: a reboot.
   `rd.emergency=reboot` or `=poweroff` turns that into one directly.
   Secure Boot changes none of this; it decides what is loaded, not what
   a failed unit does.

The end-to-end test (`unlock_integration_test.go`, root) checks both the
wrong answer and the no-answer case with `headless=true`, which makes the
agent step fail with `Password querying disabled via 'headless' option.`
instead of prompting - exactly where the fallback prompt would be.

What this means for tpm2-kira:

- **The manual passphrase is always there.** Whatever tpm2-kira does -
  asks and gets a typo, is cancelled with Ctrl-C, cannot derive a key, has
  no phone, crashes - the next try is systemd's own prompt, with the
  volume's passphrase or a recovery passphrase. tpm2-kira adds a way to
  unlock; it never takes the ordinary way away.
- **Therefore there is no enforced mode.** An enforced mode would have to
  hold the connection open and never answer until the phone approved,
  because closing it is the fallback, not a refusal - and it would still
  be a local software gate that an image without it bypasses (PLAN-BLE.md
  §7.4). The intention is the opposite: tpm2-kira does its work, the
  phone's verdict informs the person at the keyboard, and the passphrase
  can always be entered by hand. What enforces, if anything, is a missing
  phone salt ([below](#password--phone-salt-passwordphonesalt)): a key the disk needs and the machine
  does not have until the phone releases it, with the recovery passphrase
  as the manual way in.
- **Prompt options** of `crypttab(5)` - `timeout`, `verify`,
  `password-cache`, `headless`, `password-echo` - describe the agent
  prompt and apply to the fallback only; `tries` counts tpm2-kira's answer
  as the first attempt. Plymouth shows the fallback prompt, not tpm2-kira's.

### Kept as an option, not used

A credential drop-in (`LoadCredential=cryptsetup.passphrase:<socket>` on
`systemd-cryptsetup@.service`) would reach every volume without any
command-line or crypttab change, with the volume in the credential peer
name (`\0<random>/unit/<unit>/<credential>`); it also reaches token
volumes that do not want a passphrase, and its behaviour after a wrong
credential is not verified.
