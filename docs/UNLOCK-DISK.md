# Unlocking the disk through tpm2-kira: working with sd-encrypt the way it was meant

What systemd does to unlock a disk at boot, where it lets another program
provide the key, and how tpm2-kira uses exactly that and nothing else.
Everything here was checked against systemd 262 and mkinitcpio 42
(`crypttab(5)`, `systemd-cryptsetup@.service(8)`, `systemd.exec(5)`, the
installed binaries and the sd-encrypt install script).

## 1. What sd-encrypt is

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

## 2. Where systemd-cryptsetup takes the key from

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

## 3. The secure way to plug in

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
ended (`sd_notify(READY)`), one volume at a time at its own prompt.
Factor release will be the same provider answering with a derived key.
The transfer never changes.

**Treat the bytes like libcryptsetup does.** `systemd-cryptsetup` locks
its memory (`mlockall`), keeps the key in guarded buffers and erases them
(`explicit_bzero`). tpm2-kira reads the passphrase into one fixed buffer
of cryptsetup's limit (512 bytes, no growing copy), `mlock`s it, wipes it
to its full capacity after the answer, on Backspace and on cancel, and is
not dumpable while it serves keys. Neither side can zero the kernel's
socket buffer between write and read, and neither can protect against a
hibernation image; the initrd has no swap and no hibernation.

## 4. When the answer is wrong: systemd's prompt is the fallback

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
  factor (PLAN-FACTORRELEASE.md): a key the disk needs and the machine
  does not have until the phone releases it, with the recovery passphrase
  as the manual way in.
- **Prompt options** of `crypttab(5)` - `timeout`, `verify`,
  `password-cache`, `headless`, `password-echo` - describe the agent
  prompt and apply to the fallback only; `tries` counts tpm2-kira's answer
  as the first attempt. Plymouth shows the fallback prompt, not tpm2-kira's.

## 5. Kept as an option, not used

A credential drop-in (`LoadCredential=cryptsetup.passphrase:<socket>` on
`systemd-cryptsetup@.service`) would reach every volume without any
command-line or crypttab change, with the volume in the credential peer
name (`\0<random>/unit/<unit>/<credential>`); it also reaches token
volumes that do not want a passphrase, and its behaviour after a wrong
credential is not verified.

## 6. What was tried and dropped

Rewriting the image's crypttab from the hook (and then sourcing
sd-encrypt's build function to be allowed to run after it) worked, but it
made the hook order matter, hid the key source from the configuration and
replaced a distribution hook to avoid asking for one parameter. Telling
the administrator to put the socket into `/etc/crypttab` by default was
the next step and also dropped: it edits a file of the running system for
the initrd's sake, when the command line already names the disk. The
parameter is the right answer; see HISTORY.md.
