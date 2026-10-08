package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/matthias/tpm2-kira/cmd"
)

// The help in two layers: 'tpm2-kira help' is one screen - the commands
// grouped by what a person is doing - and 'tpm2-kira help <command>' (or
// '<command> --help') is that command's page: its subcommands, options and
// examples. Nothing is said twice; the overview points at the pages.

// isHelp says whether an argument asks for help.
func isHelp(arg string) bool {
	return arg == "help" || arg == "-h" || arg == "--help"
}

// printUsage is the overview.
func printUsage() {
	fmt.Print(`tpm2-kira - a boot code from the TPM, a phone that verifies the boot, and
the disk's key at the prompt

USAGE
  tpm2-kira <command> [subcommand] [options]
  tpm2-kira help <command>       that command's page: subcommands, options, examples

GUIDED
  control      One screen: what this machine has, which protections are in
               place, the recommended next step - and runs the step you pick

SETTING UP THE MACHINE (what control runs; by hand for specific settings)
  setup        Create the signing key (local files, or the key in a YubiKey)
  seal         Seal a new TOTP key to the boot state (PCRs) in a TPM slot
  reseal       Approve the current boot state for a slot (after a boot change;
               the initramfs hooks run it)
  status       The one page before a reboot: slots, phones, unlock mode,
               LUKS keyslots, and what does not fit together
  info         Show a slot's blob in full: its TOTP policy, the phones
  nvram        The TPM's slots: list, status, delete, restore

THE PHONE (the Marify app, over Bluetooth LE)
  attest       enrol, unenrol, status, gate, signer, ekcert, quote, verify,
               config-check: the phone verifies this boot
  remote-salt  enrol, rotate, status, unenrol: the salt of the disk's key,
               kept by the phone, opened only by this TPM in an approved boot

THE DISK'S KEY (mode in /etc/tpm2-kira/unlock.conf)
  luks         status, enrol, remove, mark, route: tpm2-kira's LUKS keyslots,
               and where the initrd takes the key from
  derive       hashpwd2 by hand: password and salt to a key file for luksAddKey

AT BOOT (run by the initramfs units and hooks)
  run          Show the code, hold for Enter, serve the disk's key, coordinate
               the phone
  cap          Lock the code until the next boot (when the initrd is left)
  unlock-key   Debian keyscript: the disk's key from 'run --unlock', else askpass

BY HAND
  reveal       The current code (reveal-plain: without colour)
  yubikey      list: the YubiKeys and the keys in their PIV slots
  pcrtips      What each PCR measures
  version      The version

GLOBAL OPTIONS (before the command)
  --tpm PATH      TPM device (default /dev/tpmrm0; /dev/tpm0 without a kernel
                  resource manager)
  --nvram INDEX   A slot, 0-15, or a full NV index such as 0x01803010. Without
                  it most commands take every populated slot
  --debug         Debug output

FIRST STEPS
  tpm2-kira control                                  guided, step by step; or:
  tpm2-kira setup && tpm2-kira seal                  a code at every boot
  tpm2-kira attest enrol                             the phone verifies the boot
  tpm2-kira luks enrol /dev/sda2 --mode password+remotesalt
                                                     the disk's key from your
                                                     password and the phone's salt
  then rebuild the initramfs: mkinitcpio -P (Arch), update-initramfs -u (Debian)

More: tpm2-kira help status | seal | run | attest | remote-salt | luks | nvram;
docs/ and README.md
`)
}

// printHelp prints a command's page, or the overview after a note when
// there is none.
func printHelp(topic string) {
	topic = strings.TrimPrefix(topic, "--")
	if topic == "reveal-plain" {
		topic = "reveal"
	}
	if page, ok := helpPages[topic]; ok {
		fmt.Print(page)
		return
	}
	names := make([]string, 0, len(helpPages))
	for n := range helpPages {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr, "tpm2-kira: no help page %q; there is one for: %s\n\n", topic, strings.Join(names, ", "))
	printUsage()
}

// helpPages are the pages of 'tpm2-kira help <command>'. A command with
// subcommands has one page; the subcommands are on it.
var helpPages = map[string]string{
	"control": `tpm2-kira control [--tpm PATH]

The guided way through the protections. It first looks at what the
machine has - the TPM and its banks (the SHA-1 bank only where there is
no SHA-256 one with a SHA-256 event log), how it booted and so which PCRs
to seal to, the initramfs kind, a Bluetooth adapter, the LUKS devices -
and at what is configured: the signing key, the slots, the phone, the
keyslots, the unlock mode, the route of the key. One screen shows both,
the protections in the order they build on each other -

  1  Signing key                               setup
  2  TOTP code at boot                         seal (slot 0 and the fallback slot)
  3  Attestation by phone                      attest enrol
  4  Disk key from password + salt             luks enrol --mode password+salt
  5  Disk key from password + remote salt      luks enrol --mode password+remotesalt

- each marked done, possible, or blocked with the reason, and the
recommended next one. Pick a number and it runs that step with the
functions the commands on the right use, then shows the screen again.
Run again later, it shows the state and what is left. On leaving it
names the initramfs rebuild. Without a terminal it prints the screen
and leaves (a script's look).

  tpm2-kira control
`,

	"setup": `tpm2-kira setup [--yubikey[=SERIAL] [--slot SLOT] | --local]

Creates /etc/tpm2-kira/keys/ with seal.pub and seal.key, the signing key
that approves PCR values and authorises every write to a slot. It first
looks for a YubiKey: when one holds a usable key, it asks on the terminal
whether to use it or local key files (without a terminal: local files).
With a YubiKey, seal.key only names the token and the PIV slot and seal.pub
is the token's public key: no private key is written, and setup needs no
PIN. An existing keys directory stops setup; changes after that are made
with seal and reseal.

  --yubikey[=SERIAL]  Take the key from a YubiKey without asking; SERIAL
                      picks the token when several are in. The slot must hold
                      a key already: tpm2-kira never writes to a token
  --slot SLOT         The PIV slot with --yubikey (default 9a; an sbctl key
                      in 9c only when named)
  --local             Local key files, without looking for a YubiKey

The signing key can also be the sbctl secure boot DB key: point seal and
reseal's --privkey at it to approve the boot state with the key that signs
the boot components.

  tpm2-kira setup
  tpm2-kira setup --yubikey
  tpm2-kira setup --yubikey=12345678 --slot 9c
`,

	"seal": `tpm2-kira seal [--nvram N] [--pcrs LIST] [--measure-point M] [--pubkey PATH]
                [--privkey PATH] [--sha1] [--verify-uki=false]

Generates a TOTP key inside the TPM and seals it in a slot to the boot
state. The key never leaves the TPM: the TPM computes every code, and only
under a policy the signing key approved (PolicyAuthorize): the PCR values,
and the slot's generation, which every reseal raises to revoke the older
approvals. Pair the code with the Marify app, or any TOTP app, from the QR
code shown.

Without --pcrs the selection is what this boot measured: the firmware and
the secure boot state (0e,2e,7e), plus PCR 11 computed from the unified
kernel image when one booted (11u), or GRUB's PCRs 8 and 9 predicted from
grub.cfg when GRUB did (8e,9e). Without --pcrs and --nvram, two slots are
sealed: slot 0 with that selection, and slot 1, the fallback, with 0e,7e
alone - a boot whose kernel changed unpredicted still shows slot 1's code,
which says the machine is not simply lost. With --pcrs or --nvram, one
slot: the one named (else 0), the PCRs named (else the selection).

  --pcrs LIST        PCRs with a source suffix each:
                       r  read from the TPM's registers (default)
                       e  replayed from the event log (PCRs 0-12)
                       u[:PATH]  computed from the unified kernel image (PCR 11)
                     "0e,2e,7e"  "0e,2e,7e,11u"  "0e,2,4,7e"
                     PCRs 0-7, 9 and 12-14 are sealed to their values before
                     systemd-pcrosseparator.service: the code shows before
                     it, and the separator then locks the key until the next
                     boot. On Debian with GRUB, 8 and 9 are predicted from
                     grub.cfg and the files it loads (docs/SEALING.md)
  --measure-point M  systemd's enter-initrd extend of PCR 11, which happens
                     before tpm2-kira runs: auto (default), on, off
  --pubkey PATH      The signing key's public half, PEM, X.509 or raw, RSA or
                     ECDSA (default: ` + cmd.DefaultPublicKeyPath + `)
  --privkey PATH     The private half (default: the key from setup). Both
                     paths are kept in the blob so reseal finds them
  --sha1             The SHA-1 PCR bank: only for a TPM whose event log has
                     no SHA-256 digests
  --verify-uki       Check the PCR 11 computation against this boot's event
                     log first (default true)

  tpm2-kira seal                          slot 0 as measured, slot 1 the fallback
  tpm2-kira seal --pcrs "0e,2e,7e,11u"    slot 0 with these
  tpm2-kira seal --nvram 2 --pcrs "0e,7e"
  tpm2-kira seal --sha1 --pcrs "0e,2e,7e"
`,

	"reseal": `tpm2-kira reseal [--nvram N] [--pcrs LIST] [--measure-point M] [--privkey PATH]
                  [--pubkey PATH] [--require-key]

Approves the current (predicted next) boot state for a slot, with the
signing key: a new generation, the older approvals revoked. It never needs
the PCRs to match and never reads the TOTP key. The initramfs hooks run it
after every image rebuild; a slot sealed with the key on a YubiKey needs
the token and its PIN (` + cmd.PINEnvVar + `, or TPM2_KIRA_PIN='...' in
/etc/mkinitcpio.conf, root-only; else asked).

  --pcrs LIST        A new selection (default: the slot's, with its sources)
  --measure-point M  As for seal: auto (default), on, off
  --privkey PATH     The signing key (default: the key from setup). It
                     verifies the blob's signature, authorises the write and
                     approves the PCR values; a path kept in the blob is
                     never used to find it
  --pubkey PATH      Must belong to --privkey (default: derived from it)
  --require-key      With a YubiKey: fail when the token or its PIN is not
                     at hand. By default reseal then prints SKIPPED, leaves
                     every slot as it is, and exits 0

  tpm2-kira reseal
  tpm2-kira reseal --nvram 0 --pcrs "0e,2,4,7e"
  tpm2-kira reseal --privkey /path/to/my-key.key
`,

	"status": `tpm2-kira status [--json] [--privkey PATH] [--unlock-conf PATH]

The overview, read-only: every slot with what it is sealed to, its
generation (does the TPM's index match, or is a reseal due), whether this
machine's key signed it, its phones and whether a remote salt is enrolled;
the unlock mode from /etc/tpm2-kira/unlock.conf; every LUKS device's
keyslots and which are tpm2-kira's. Then the notes: what does not fit
together and what to run - a mode without a keyslot for it, a keyslot
whose mode is not set, a remote salt that is not enrolled, no fallback
slot, a slot that needs a reseal. Root for the LUKS headers.

  --json              Machine-readable
  --privkey PATH      The signing key the blobs are checked with
  --unlock-conf PATH  (default ` + cmd.DefaultUnlockConfigPath + `)
`,

	"info": `tpm2-kira info [--nvram N] [--json] [--privkey PATH]

Shows a slot's blob: the TOTP key's policy (PCRs, sources, generation), the
remote attestation set up for it (attestation key, phones, release key for
the remote salt), and whether the blob is signed by this machine's key.

  --json          Machine-readable
  --privkey PATH  The signing key the blobs are verified with (default: the
                  key from setup). A blob that does not verify is shown as
                  untrusted, and no file it names is opened

  tpm2-kira info
  tpm2-kira info --nvram 0x01803010 --json
`,

	"nvram": `tpm2-kira nvram list | status | delete [--yes] | restore FILE   [--nvram N]

The TPM's slots: 0-15 are the NV indices 0x01803010-0x0180301F.

  list             Every NV index the TPM holds
  status           A slot's NV index: size, attributes, written
  delete           Delete the slot - or every populated slot without --nvram,
                   which asks on a terminal or needs --yes
  restore FILE     Put back a blob that a failed write stashed in
                   ` + cmd.NVRAMRecoveryDir + `/ (slot-0x<index>-<time>.blob):
                   the sealed TOTP key survives a lost index. It is approved
                   and written as reseal does it, with the signing key
                   (--privkey PATH, --pubkey PATH; default: the key from
                   setup), into an empty slot; the file is removed after

  tpm2-kira nvram list
  tpm2-kira nvram delete --nvram 0
  tpm2-kira nvram restore ` + cmd.NVRAMRecoveryDir + `/slot-0x01803010-1759823456.blob
`,

	"reveal": `tpm2-kira reveal [--nvram N]          tpm2-kira reveal-plain [--nvram N]

The current code of a slot, in the coloured KIRA format or plain. The TPM
computes it under the slot's policy: in a boot the signing key approved,
before the OS separator (after 'cap' there is no code until the next boot).
`,

	"run": `tpm2-kira run [--hold S] [--gate SOCKET] [--unlock SOCKET]

What the initramfs runs: shows the code of every slot and holds the boot
for Enter; with a phone enrolled, coordinates the Bluetooth gate and shows
the phone's code in the slot's line as soon as the phone is in; with
--unlock, serves the disk's key to systemd-cryptsetup (rd.luks.key=<UUID>=
/run/tpm2-kira/unlock.sock) or the Debian keyscript, in the mode of
/etc/tpm2-kira/unlock.conf:

  skip                    nothing; cryptsetup's own prompt (default)
  password+salt           asks a password and a salt; hashpwd2's derivation
  password+remotesalt     asks the password; the salt the phone released

Ctrl-C at the prompt skips to cryptsetup's own prompt, where the recovery
passphrase works. The log of the boot: journalctl -b -u tpm2-kira.service
(Arch), /run/initramfs/tpm2-kira.log (Debian).

  --hold S         Seconds to wait for Enter (default 90; 0: at once). A fresh
                   code every 30 seconds; Enter releases the boot
  --gate SOCKET    Be the coordinator of the gate on this socket: hold the TPM
                   for the radio worker ('attest gate --coordinator'), read
                   the phone's receipt, release the boot on its verdict
  --unlock SOCKET  Serve the disk's key on this socket (the unit sets
                   ` + cmd.DefaultUnlockSocket + `)
`,

	"cap": `tpm2-kira cap

Read-locks every slot's generation until the next boot: no code can be
computed in the running OS. The boot integration runs it when the initrd is
left; by hand only for a test.
`,

	"unlock-key": `tpm2-kira unlock-key [--socket PATH] [--wait DUR] [VOLUME]

The Debian keyscript (/lib/cryptsetup/scripts/tpm2-kira runs it, VOLUME
from CRYPTTAB_NAME): the volume's key from the socket of 'run --unlock' to
stdout, as systemd-cryptsetup would ask it. Without the socket, or without
a key to give (mode skip, no remote salt, Ctrl-C), it becomes cryptsetup's
own prompt, /lib/cryptsetup/askpass. On the last of cryptroot's tries the
keyscript asks at askpass directly.

  --socket PATH  (default ` + cmd.DefaultUnlockSocket + `)
  --wait DUR     How long to wait for the socket (default 5s)
`,

	"attest": attestUsage,

	"remote-salt": factorUsage,

	"luks": `tpm2-kira luks status [<device>…] [--json]
tpm2-kira luks enrol  <device> --mode password+salt|password+remotesalt [options]
tpm2-kira luks remove <device> --keyslot N
tpm2-kira luks route  [<device>…] [--cmdline FILE]… [--crypttab FILE] [--json]
tpm2-kira luks mark   <device> --keyslot N --mode password+salt|password+remotesalt [options]

tpm2-kira's LUKS keyslots. Every keyslot it adds is marked with a LUKS2
token of type tpm2-kira in the header ({"mode","slot","label","created"};
no secret), so status, removal and rotation know which are its own. The
recovery passphrase stays in a keyslot of its own, unmarked: cryptsetup's
prompt is always the fallback (docs/PLAN-LUKS.md).

  status    Every crypto_LUKS device (or the ones named): per keyslot whose
            it is - tpm2-kira, password+salt; tpm2-kira, password+remotesalt,
            slot 0; or not tpm2-kira's
  enrol     The whole thing in one step: asks the password and the salt (or
            runs the remote salt's hand-over with the phone), derives the
            key, asks an existing passphrase of the device (the recovery
            one) to authorise, 'cryptsetup luksAddKey' (a device whose every
            keyslot is tpm2-kira's is refused), imports the token, sets the
            mode in /etc/tpm2-kira/unlock.conf. Then rebuild the initramfs.
              --nvram N               the slot whose phone keeps the salt
              --label STR             the remote salt's label (default luks)
              --existing-key-file F   a passphrase file to authorise (scripts)
              --no-config             leave unlock.conf alone
              --privkey --pubkey --adapter --timeout --adapter-wait  as remote-salt enrol
  remove    'cryptsetup luksKillSlot' for a keyslot tpm2-kira marked, and
            its token. A remaining passphrase, asked, authorises it
            (--existing-key-file F for scripts). Never the last keyslot,
            never one that is not tpm2-kira's
  mark      The token for a keyslot made by hand (derive or remote-salt enrol
            --out, then luksAddKey): --keyslot N --mode M [--nvram N --label STR]
  route     Where the initrd is told to take the key from tpm2-kira, for
            every device with a keyslot of ours (or the ones named): the
            kernel command line (/etc/cmdline.d/*.conf or /etc/kernel/cmdline,
            boot loader entries) needs rd.luks.key=<UUID>=/run/tpm2-kira/unlock.sock
            next to rd.luks.name=; /etc/crypttab the socket as key file with
            x-initrd.attach, or on Debian keyscript=/lib/cryptsetup/scripts/tpm2-kira.
            Nothing is edited: a wrong line is named and the line is printed
            as it should read. Exit 1 while something is wrong. 'luks enrol'
            ends with it, 'status' notes it, the mkinitcpio hook runs it

  tpm2-kira luks status
  tpm2-kira luks enrol /dev/sda2 --mode password+salt
  tpm2-kira luks enrol /dev/sda2 --mode password+remotesalt
  tpm2-kira luks remove /dev/sda2 --keyslot 1
  tpm2-kira luks route
  tpm2-kira luks mark /dev/sda2 --keyslot 1 --mode password+salt
`,

	"derive": `tpm2-kira derive --out PATH

hashpwd2 by hand: asks a password and a salt and writes the derived key
(Argon2id, 1 GiB, 16 passes; base64) to PATH on tmpfs, for
'cryptsetup luksAddKey <device> PATH' and 'luks mark' afterwards - the
password+salt mode without 'luks enrol'. Remove the file after use.

  tpm2-kira derive --out /run/tpm2-kira/luks.key
`,

	"yubikey": `tpm2-kira yubikey list

The YubiKeys plugged in and the keys in their PIV slots, and which of them
tpm2-kira can use as the signing key. Read-only; no PIN. With the signing
key on a YubiKey, seal and reseal need the token and its PIN (see
'help reseal'); reveal, run and info never do.
`,

	"pcrtips": `tpm2-kira pcrtips

What each PCR measures and which to seal to: 0,2,7 by default; 8 and 9 on
Debian with GRUB; 11 with a unified kernel image (docs/SEALING.md).
`,
}
