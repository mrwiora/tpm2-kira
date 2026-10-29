package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mrwiora/tpm2-kira/internal/admin"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/signing"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
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

Everything but the help needs root: the TPM, the keys in /etc/tpm2-kira,
the LUKS headers and the initramfs are root's. How a disk's key is made
is in its own LUKS header (the keyslot's token), read at boot: there is
no unlock mode to set anywhere.

GUIDED
  control      One screen: what this machine has, which protections are in
               place, the recommended next step - and runs the step you pick

THE SLOT (a boot state your signing key approved; what control runs)
  setup        Create the signing key (local files, or the key in a YubiKey)
  slot         add, approve, info, list, status, delete, restore: add seals a
               TOTP key to the boot state (PCRs); approve approves the boot
               state after a change (the initramfs hooks run it)
  status       The one page before a reboot: slots, phones, LUKS
               keyslots, and what does not fit together

WHO CHECKS THE BOOT
  reveal       The code of a slot's TOTP key (reveal-plain: without colour)
  phone        enrol, unenrol, status, gate, ekcert, quote, verify: the
               Marify app verifies this boot over Bluetooth LE, in place of
               the code; salt enrol|rotate|status|unenrol: the phone keeps
               the salt of the disk's key, opened only by this TPM in an
               approved boot

WHERE THE CODE SCREEN IS
  (the console, always; set in control:) SSH in the boot image, with the
  host key certified by the SSH CA in the TPM ('help ssh-child')

THE DISK'S KEY (the recipe in each volume's LUKS header)
  luks         status, enrol, remove, mark, route, derive: tpm2-kira's LUKS
               keyslots - password+salt, password+phonesalt, tpm+vault - and
               where the initrd takes the key from
  vault        enrol, status, unenrol: the key from this TPM and
               tpm2-kira-vault, unattended (mode tpm+vault)

THE BOOT IMAGE
  initramfs    plan: what the boot image carries - the disk unlock, and each
               part the machine uses (codes, phone, vault, network, SSH)
  The image carries tpm2-kira-boot alone, which the units and scripts run
  (its pages are here too: tpm2-kira help run):
    run          Show the code, hold for Enter, start the parts the image's
                 plan names: the phone's gate, SSH, the vault, the disk's key
    cap          Lock the code until the next boot (when the initrd is left)
    unlock-key   Debian keyscript: the disk's key from 'run --unlock', else
                 askpass
    ssh-child    The SSH server's unprivileged half, started by run
    gate-child   The phone's radio worker, started by run

BY HAND
  yubikey      list: the YubiKeys and the keys in their PIV slots
  pcrtips      What each PCR measures
  version      The version

GLOBAL OPTIONS (before the command, or after it as the command's own)
  --tpm PATH      TPM device (default /dev/tpmrm0; /dev/tpm0 without a kernel
                  resource manager)
  --nvram INDEX   A slot, 0-15, or a full NV index such as 0x01803010. Without
                  it most commands take every populated slot
  --debug         Debug output
  An option after the command wins over the same one before it; a command
  without one of them ignores it.

FIRST STEPS
  tpm2-kira control                                  guided, in two steps; or:
  tpm2-kira setup && tpm2-kira slot add             a code at every boot
  tpm2-kira phone enrol                              the phone verifies the boot
  tpm2-kira luks enrol /dev/sda2 --mode password+phonesalt
                                                     the disk's key from your
                                                     password and the phone's salt
  then rebuild the initramfs: mkinitcpio -P (Arch), update-initramfs -u (Debian)

More: tpm2-kira help slot | status | phone | luks | vault | run | initramfs |
ssh-child | gate-child; docs/ and README.md
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

The guided way through the protections, in two steps.

Step 1, the boot chain, is the first screen until it is in place. On
top the prerequisites, each a line - met (green), not met (red, with
what to do or the risk), or information: a usable TPM (information:
the disk unlock works without one), the initramfs
system, tpm2-kira's hook files installed, systemd and sd-encrypt in
mkinitcpio's HOOKS, the LUKS devices, a recovery passphrase (a keyslot
that is not tpm2-kira's) on each, no keyslot opening with an empty
passphrase (red: anybody with the disk opens it), Secure Boot. Under it
the steps:

  mkinitcpio adoption        sd-tpm2-kira into HOOKS, written when you say so
  Kernel command line        the key's route: rd.luks.key= names the socket
    adoption                 (crypttab on Debian), written when you say so
  Continue to step 2         once both are in place

Step 2 is what the machine combines, in submenus; on top the machine's
status, judged line by line (green good, red not good with the risk in
brackets: the SHA-1 bank, Secure Boot disabled or in Setup Mode, a slot
sealed without the kernel measured, an endorsement key no known vendor
vouches for, a loose file holding the PIN, an empty passphrase, a vault
that does not answer):

  Signing key and TOTP codes setup (and the YubiKey's PIN, stored); the
                             standard sealing, slot 0 to the evaluated PCRs
                             (or custom ones) and slot 1 the fallback; every
                             slot a line, picking it deletes the slot whole
  Attestation by phone       phone enrol; Bluetooth in every boot image
  Disk unlock                password + salt; password + phone salt (the
                             phone); this TPM + a vault - each a keyslot,
                             enrolled it offers the removal
  Network and SSH at boot    the image's network (DHCP or static), the SSH
                             server with the code screen
  Debug at boot              the switch in the TPM

Every option is open, done, or greyed with the reason this machine
cannot have it (no TPM, no Bluetooth adapter, no wired interface, no
recovery passphrase, an option it builds on missing). An option that
needs another one control can set up offers it on the way: the vault and
SSH set up the image's network first. The vault is asked before the
enrolment - does it answer, with the pinned key - and at every look at
the machine whether it still knows this device. What changes the boot
image only marks it out of date - the status' "Boot image" line says
why, against the boot plan ('tpm2-kira help initramfs'): a part in use
now and not in the image, or in it with other settings. The image is
built once, when you quit control, after you said yes; step 2 leads
with "Ready to reboot" once the image is current and this boot did not
go through it.

The steps run without the commands' advisory warnings (a weak selection,
SHA-1, Secure Boot off): the status says the same, judged and in red,
and nothing is said twice. A slot whose deletion stopped halfway is
dirty, marked [!] and recommended first, until a run removes the rest.
Control alone writes the configuration, /etc/tpm2-kira/control.conf: the
radio settings and the image's network and SSH server - what the image is
built with, nothing else; and beside it aSSH's, /etc/tpm2-kira/assh.conf:
the SSH CA and its slots (the PCRs it signs in), the port, the keys that
may log in. Beside them: the YubiKey's PIN, checked on the token, in
/etc/tpm2-kira/pin (root's alone), and the keys that may log in at boot in
/etc/tpm2-kira/authorized_keys.
Every other file stays yours to edit, with two exceptions, each asked
for every time: the HOOKS of mkinitcpio.conf and the key's route.
Sealing both slots, each QR code gets a cleared screen of its own, held
until the scan is confirmed: it is shown this once.
On leaving it names the initramfs rebuild. Forms: arrow keys and Enter,
Esc leaves (in a submenu: back to step 2), ACCESSIBLE=1 for plain
prompts. Without a terminal it prints both steps and leaves (a script's
look).

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
with slot add and slot approve.

  --yubikey[=SERIAL]  Take the key from a YubiKey without asking; SERIAL
                      picks the token when several are in. The slot must hold
                      a key already: tpm2-kira never writes to a token
  --slot SLOT         The PIV slot with --yubikey (default 9a; an sbctl key
                      in 9c only when named)
  --local             Local key files, without looking for a YubiKey

The signing key can also be the sbctl secure boot DB key: point the
--privkey of slot add and slot approve at it to approve the boot state
with the key that signs the boot components.

  tpm2-kira setup
  tpm2-kira setup --yubikey
  tpm2-kira setup --yubikey=12345678 --slot 9c
`,

	"slot": `tpm2-kira slot add     [--nvram N] [--pcrs LIST] [--measure-point M]
                       [--pubkey PATH] [--privkey PATH] [--sha1]
                       [--verify-uki=false]
tpm2-kira slot approve [--nvram N] [--pcrs LIST] [--measure-point M]
                       [--privkey PATH] [--pubkey PATH] [--require-key]
tpm2-kira slot info    [--nvram N] [--json] [--privkey PATH]
tpm2-kira slot list | status | delete [--yes] | restore FILE   [--nvram N]

A slot is a boot state your signing key approved: PCR values and a
generation, in one of the TPM's slots 0-15 (the NV indices
0x01803010-0x0180301F). What is sealed to it - a TOTP key, or a phone's
enrolment - and everything else that needs the approved boot state (the
phone's salt, the vault's part, the SSH CA) works only in that state.

add
Generates a TOTP key inside the TPM and seals it in a slot to the boot
state. The key never leaves the TPM: the TPM computes every code, and only
under a policy the signing key approved (PolicyAuthorize): the PCR values,
and the slot's generation, which every approval raises to revoke the older
approvals. Pair the code with the Marify app, or any TOTP app, from the QR
code shown.

Without --pcrs the selection is what this boot measured: the firmware and
the secure boot state (0e,2e,7e), plus PCR 11 computed from the unified
kernel image when one booted (11u), or GRUB's PCRs 8 and 9 predicted from
grub.cfg when GRUB did (8e,9e); without an event log to read, the
registers as they are (0,2,7). Without --pcrs and --nvram, two slots are
sealed: slot 0 with that selection, and slot 1, the fallback, with 0e,7e
alone (0,7 without a log) - a boot whose kernel changed unpredicted still shows slot 1's code,
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
                     ECDSA (default: ` + signing.DefaultPublicKeyPath + `)
  --privkey PATH     The private half (default: the key from setup)
  --sha1             The SHA-1 PCR bank: only for a TPM whose event log has
                     no SHA-256 digests
  --verify-uki       Check the PCR 11 computation against this boot's event
                     log first (default true)

  tpm2-kira slot add                        slot 0 as measured, 1 the fallback
  tpm2-kira slot add --pcrs "0e,2e,7e,11u"  slot 0 with these
  tpm2-kira slot add --nvram 2 --pcrs "0e,7e"
  tpm2-kira slot add --sha1 --pcrs "0e,2e,7e"

approve
Approves the current (predicted next) boot state for a slot, with the
signing key: a new generation, the older approvals revoked. It never needs
the PCRs to match and never reads the TOTP key. Without --nvram it also
approves the SSH CA (` + admin.DefaultSSHCA + `) for the next boot, in each of
its slots (assh.conf's) that has no approval. The initramfs hooks run it
after every image rebuild; a slot sealed with the key on a YubiKey needs
the token and its PIN (` + signing.PINEnvVar + `, or /etc/tpm2-kira/pin, which
control stores, root-only; else asked).

  --pcrs LIST        A new selection (default: the slot's, with its sources)
  --measure-point M  As for add: auto (default), on, off
  --privkey PATH     The signing key (default: the key from setup). It
                     verifies the blob's signature, authorises the write and
                     approves the PCR values
  --pubkey PATH      Must belong to --privkey (default: derived from it)
  --require-key      With a YubiKey: fail when the token or its PIN is not
                     at hand. By default approve then prints SKIPPED, leaves
                     every slot as it is, and exits 0

  tpm2-kira slot approve
  tpm2-kira slot approve --nvram 0 --pcrs "0e,2,4,7e"
  tpm2-kira slot approve --privkey /path/to/my-key.key

info
Shows a slot's blob: the TOTP key's policy (PCRs, sources, generation), the
attestation set up for it - the phone at the machine, the vault over TLS
(attestation key, phones, the vault, release key) - and whether the blob is
signed by this machine's key.

  --json          Machine-readable
  --privkey PATH  The signing key the blobs are verified with (default: the
                  key from setup). A blob that does not verify is shown as
                  untrusted, and no file it names is opened

  tpm2-kira slot info
  tpm2-kira slot info --nvram 0x01803010 --json

list, status, delete, restore
The TPM's slots: 0-15 are the NV indices 0x01803010-0x0180301F.

  list             Every NV index the TPM holds
  status           A slot's NV index: size, attributes, written
  delete           Delete the slot's indices in the TPM - or every populated
                   slot's without --nvram, which asks on a terminal or needs
                   --yes. A LUKS keyslot bound to the slot stays and leaves
                   the slot dirty; 'tpm2-kira control' (the slot's line)
                   deletes a slot whole
  restore FILE     Put back a blob that a failed write stashed in
                   ` + nvslot.NVRAMRecoveryDir + `/ (slot-0x<index>-<time>.blob):
                   the sealed TOTP key survives a lost index. It is approved
                   and written as approve does it, with the signing key
                   (--privkey PATH, --pubkey PATH; default: the key from
                   setup), into an empty slot; the file is removed after

  tpm2-kira slot list
  tpm2-kira slot delete --nvram 0
  tpm2-kira slot restore ` + nvslot.NVRAMRecoveryDir + `/slot-0x01803010-1759823456.blob
`,

	"status": `tpm2-kira status [--json] [--privkey PATH] [--conf PATH]

The overview, read-only: every slot with what it is sealed to, its
generation (does the TPM's index match, or is an approval due), whether this
machine's key signed it, its phones and whether a phone salt is enrolled;
every LUKS device's keyslots and which are tpm2-kira's (how a key is made
is each keyslot's token, read from the header at boot). Then the notes:
what does not fit together and what to run - a phone salt without a
keyslot for it, a keyslot bound to a slot that is gone, no fallback
slot, a slot that needs an approval. Root for the LUKS headers.

  --json              Machine-readable
  --privkey PATH      The signing key the blobs are checked with
  --conf PATH         The configuration file (default ` + admin.DefaultControlConfigPath + `)
`,

	"reveal": `tpm2-kira reveal [--nvram N]          tpm2-kira reveal-plain [--nvram N]

The current code of a slot, in the coloured KIRA format or plain. The TPM
computes it under the slot's policy: in a boot the signing key approved,
before the OS separator (after 'cap' there is no code until the next boot).
`,

	"run": `tpm2-kira-boot run [--plan DIR] [--hold S] [--unlock SOCKET] [--ssh [--ssh-conf PATH] ...]

What the initramfs runs, the same on Arch and Debian: shows the code of
every slot and holds the boot for Enter; waits up to 5 s for the TPM when
a part of the plan needs it; with a phone enrolled, starts the Bluetooth
gate's radio worker ('gate-child', nobody, confined), coordinates it and shows
the phone's code in the slot's line as soon as the phone is in; with
--unlock, serves the disk's key to systemd-cryptsetup (rd.luks.key=<UUID>=
/run/tpm2-kira/unlock.sock) or the Debian keyscript, made as the volume's
LUKS2 header says (the token of tpm2-kira's keyslot):

  no token                nothing; cryptsetup's own prompt
  password+salt           asks a password and a salt; Argon2id
  password+phonesalt     asks the password; the salt the phone released
  tpm+vault               asks nothing: the TPM's local part and the vault's
                          remote part, opened while the code screen holds; a
                          key made ends the hold on its own

Ctrl-C at the prompt skips to cryptsetup's own prompt, where the recovery
passphrase works. The log of the boot: journalctl -b -u tpm2-kira.service
(Arch), /run/initramfs/tpm2-kira.log (Debian).

  --plan DIR       Start only what the boot image names in DIR (the units pass
                   ` + imageplan.Dir + `, 'tpm2-kira help initramfs'): without
                   the codes in it the TPM is not asked for them, without the
                   phone no gate is coordinated, without the vault none is
                   asked. Without --plan, all it finds
  --hold S         Seconds to wait for Enter (default 90; 0: at once). A fresh
                   code every 30 seconds; Enter releases the boot
  --unlock SOCKET  Serve the disk's key on this socket (Debian's boot
                   script passes ` + diskkey.DefaultUnlockSocket + `; under
                   systemd the socket unit hands its socket over instead)
  --ssh            Be the SSH server ('ssh-child', unprivileged): the
                   codes are shown and confirmed in an SSH session, the
                   password is asked there; the console says where to log
                   in, and Enter there continues at the console instead
  --ssh-hold S     With --ssh, in place of --hold (default 0: until a
                   confirmation comes)
  --ssh-conf PATH  aSSH's settings (default ` + sshscreen.DefaultConf + `, the
                   image's copy): the address (ASSH_LISTEN), the keys that
                   may log in (ASSH_AUTHORIZED_KEYS), the SSH CA (ASSH_CA,
                   ` + admin.DefaultSSHCA + `, an EFI variable). At the start,
                   before the OS separator, the TPM makes this boot's host
                   key and the CA certifies it through the first slot whose
                   PCRs hold an approved state, then the window (PCR 15) is
                   extended: the CA certifies nothing more until the next
                   boot. When it does not certify, a temporary key is served
                   - made in the TPM too, not certified - and the console
                   shows its fingerprint
`,

	"phone": attestUsage + "\n" + factorUsage,

	"gate-child": `tpm2-kira-boot gate-child [--debug]

The phone's radio worker at boot (docs/PHONE.md). With a phone in the
image's plan, 'run' is the gate's coordinator: it holds the TPM, issues
the quotes, opens the boot key and the phone salt, and reads the phone's
receipt. It starts this binary again as 'gate-child', the half that
listens to the radio: as nobody with CAP_NET_ADMIN and CAP_NET_RAW alone
(the HCI user channel), in IPC, PID, mount and UTS namespaces of its own
(not a network namespace: Bluetooth sockets exist only in the first),
with two socket pairs to 'run' and /dev/rfkill as its only open files.
It then confines itself on every thread: no new privileges, no
executable memory, no file but /sys (Landlock), none of the system calls
that administer the machine (seccomp). It has no TPM. The same on Arch
and Debian; nobody runs it by hand ('tpm2-kira phone gate' is the gate
on the unlocked system).

Its narrative goes to run's (the journal, or Debian's
/run/initramfs/tpm2-kira.log); what needs eyes, to run's stderr.
`,

	"ssh-child": `tpm2-kira-boot ssh-child

The code screen over SSH (docs/SSH.md). The network and the SSH
server of the boot image are set in /etc/tpm2-kira/control.conf
(TPM2_KIRA_NET_*, TPM2_KIRA_SSH_*; 'tpm2-kira control' sets them and
suggests the network from /etc/systemd/network or /etc/network/interfaces);
what aSSH does - the SSH CA and its slots, the port, the keys that may log
in - in ` + sshscreen.DefaultConf + ` (ASSH_*). Both are off until set; the
image build puts them in ('tpm2-kira help initramfs').

The SSH server is a library (github.com/tpm2-trust/assh/server) inside
'run', split in two processes. 'run' opens the port and starts this
binary again as 'ssh-child', the half that speaks SSH: as nobody, in
namespaces of its own, confined on every thread (no new privileges, no
executable memory, no file, none of the system calls that administer the
machine; assh's sandbox). It holds no host key
('run' has the TPM sign, over a socket pair between the two) and no
password; a login becomes a session of the code screen in 'run'. Nobody
runs 'ssh-child' by hand.

The host key is made in the TPM at every boot and certified by the SSH
CA, which 'tpm2-kira control' creates in the TPM and keeps in the EFI
variable ` + admin.DefaultSSHCA + `, and which signs only while the PCRs of one of its slots
hold values the signing key approved. control writes two slots into
assh.conf when it creates the CA: PCR 0, 2, 7 and the image's (11, or 8
and 9 with GRUB), and PCR 7 alone - each with PCR 15, the window, which run
extends. slot approve approves them after every image rebuild, and makes the
CA's slots assh.conf's first (ASSH_CA_SLOT_<N>=PCRs). Clients trust the CA once, in known_hosts:

  @cert-authority <the machine's names> <the contents of ` + admin.DefaultSSHCAPub + `>
`,

	"initramfs": `tpm2-kira initramfs plan [--buildroot DIR --format mkinitcpio|initramfs-tools] [--conf PATH] [--tpm PATH]

The boot plan: what the boot image carries, decided from what this
machine uses. The disk unlock is always in it - how a volume's key is
made, its LUKS2 header says at boot. Every other part is in only when
something uses it, and says why it is out otherwise:

  TOTP codes          a slot is sealed in the TPM
  Phone (Bluetooth)   a phone is enrolled, or TPM2_KIRA_ATTEST_BLUETOOTH=always;
                      needs the TPM, the signing key and the adapter
  Vault               a slot is enrolled with a vault; needs the network
  Network             TPM2_KIRA_NET in control.conf
  SSH server          TPM2_KIRA_SSH=on; needs the network, the TPM, the SSH
                      CA (its EFI variable), and a key that may log in

A machine without a TPM gets the disk unlock alone. Without --buildroot
the plan is shown. With it - what the initramfs hooks call - the image's
files of the parts that are in are written into DIR (the signing public
key, the adapter's module list and udev rule, the network's file, the
SSH CA with its approval, the keys that may log in, the drop-ins), the parts
are named in ` + imageplan.Dir + ` (a directory each, with a file named by
the digest of its settings), and the lines the hook adds by are printed:
say, warning, module, bt-module, bt-firmware, net-module, net-modules-all.
A part that cannot be had stays out; nothing stops the build.

'tpm2-kira control' compares the plan with the image the next boot starts:
a part in use and not in the image, or in it with other settings, makes it
rebuild the image when it is left. A part the image carries and nothing
uses is no reason to rebuild: the next build leaves it out.

  --no-busybox     initramfs-tools: the image has no busybox, so no network
  --kernel-log F   Extra kernel log naming the adapter's firmware (the
                   journal is read in any case)
`,

	"cap": `tpm2-kira-boot cap

Read-locks every slot's generation until the next boot: no code can be
computed in the running OS. The boot integration runs it when the initrd is
left; by hand only for a test.
`,

	"unlock-key": `tpm2-kira-boot unlock-key [--socket PATH] [--wait DUR] [VOLUME]

The Debian keyscript (/lib/cryptsetup/scripts/tpm2-kira runs it, VOLUME
from CRYPTTAB_NAME): the volume's key from the socket of 'run --unlock' to
stdout, as systemd-cryptsetup would ask it. Without the socket ('run'
failed), or without
a key to give (no tpm2-kira token on the volume, the phone salt or the
vault's part not released, Ctrl-C), it becomes cryptsetup's
own prompt, /lib/cryptsetup/askpass. On the last of cryptroot's tries the
keyscript asks at askpass directly.

  --socket PATH  (default ` + diskkey.DefaultUnlockSocket + `)
  --wait DUR     How long to wait for the socket (default 5s)
`,

	"attest": attestUsage,

	"phone salt": factorUsage,

	"vault": vaultUsage,

	"luks": `tpm2-kira luks status [<device>…] [--json]
tpm2-kira luks enrol  <device> --mode password+salt|password+phonesalt|tpm+vault [options]
tpm2-kira luks remove <device> --keyslot N
tpm2-kira luks route  [<device>…] [--cmdline FILE]… [--crypttab FILE] [--json]
tpm2-kira luks mark   <device> --keyslot N --mode password+salt|password+phonesalt|tpm+vault [options]
tpm2-kira luks derive --out PATH

tpm2-kira's LUKS keyslots. Every keyslot it adds is marked with a LUKS2
token in the header (no secret), whose type carries the mode, so a plain
luksDump tells them apart: tpm2-kira-salt is password+salt,
tpm2-kira-phonesalt is password+phonesalt, tpm2-kira-vault is tpm+vault
(docs/VAULT.md). status, removal and rotation
know the keyslots by it, and the boot reads the key's recipe from it; a
token of ours without a keyslot is named as a leftover, with the
'cryptsetup token remove' that takes it. A password+phonesalt or tpm+vault
keyslot is bound by "slot" to the slot whose enrolment releases its part (0 unless
--nvram names another): deleting that slot (control, the slot's line)
deletes the keyslot with it, and a keyslot outliving its slot is dirty.
A password+salt keyslot is bound to nothing - no TPM is in its key - and
survives every slot; the two coexist, the typed salt the fallback when
the phone is not there. The recovery passphrase stays in a keyslot of its
own, unmarked: cryptsetup's prompt is always the fallback
(docs/PLAN-LUKS.md).

  status    Every crypto_LUKS device (or the ones named): per keyslot whose
            it is - tpm2-kira, password+salt (slot 0); tpm2-kira,
            password+phonesalt (slot 0); or not tpm2-kira's
  enrol     The whole thing in one step: asks the password and the salt (or
            runs the phone salt's hand-over with the phone), derives the
            key, asks an existing passphrase of the device (the recovery
            one) to authorise, 'cryptsetup luksAddKey' (a device whose every
            keyslot is tpm2-kira's is refused), imports the token - which
            is all the boot needs: it reads the recipe from the header
            when the volume asks. Nothing else is configured.
              --nvram N               the slot the keyslot is bound to (default
                                      0; password+phonesalt: whose phone keeps the salt)
              --label STR             the key's label (default luks)
              --url --pin --token     tpm+vault: the vault, from 'tpm2-kira-vault
                                      token create'; --name the machine's name there
              --pepper                tpm+vault: an operator's pepper in the key, asked
                                      here; every boot waits for an approval with it
              --existing-key-file F   a passphrase file to authorise (scripts)
              --privkey --pubkey --adapter --timeout --adapter-wait  as phone salt enrol
  remove    'cryptsetup luksKillSlot' for a keyslot tpm2-kira marked, and
            its token. A remaining passphrase, asked, authorises it
            (--existing-key-file F for scripts). Never the last keyslot,
            never one that is not tpm2-kira's
  mark      The token for a keyslot made by hand (derive or phone salt enrol
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
  derive    The password+salt key by hand: asks a password and a salt and
            writes the derived key (Argon2id, 1 GiB, 16 passes; base64) to
            PATH on tmpfs, for 'cryptsetup luksAddKey <device> PATH' and
            'luks mark' afterwards - the password+salt mode without 'luks
            enrol'. Remove the file after use.

  tpm2-kira luks status
  tpm2-kira luks enrol /dev/sda2 --mode password+salt
  tpm2-kira luks enrol /dev/sda2 --mode password+phonesalt
  tpm2-kira luks enrol /dev/sda2 --mode tpm+vault --url https://vault:8443 --pin sha256:… --token …
  tpm2-kira luks remove /dev/sda2 --keyslot 1
  tpm2-kira luks route
  tpm2-kira luks mark /dev/sda2 --keyslot 1 --mode password+salt
  tpm2-kira luks derive --out /run/tpm2-kira/luks.key
`,

	"yubikey": `tpm2-kira yubikey list

The YubiKeys plugged in and the keys in their PIV slots, and which of them
tpm2-kira can use as the signing key. Read-only; no PIN. With the signing
key on a YubiKey, slot add and slot approve need the token and its PIN (see
'help slot'); reveal, run and info never do.
`,

	"pcrtips": `tpm2-kira pcrtips

What each PCR measures and which to seal to: 0,2,7 by default; 8 and 9 on
Debian with GRUB; 11 with a unified kernel image (docs/SEALING.md).
`,
}
