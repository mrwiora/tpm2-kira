# SSH in the boot image: the code screen over the network

> Arch (mkinitcpio, systemd in the initrd) and Debian (initramfs-tools).
> Off until turned on. Experimental. The superseded designs (tinysshd, an
> unencrypted host key, a host key sealed to the TPM, mkinitcpio-systemd-extras'
> hooks) are in HISTORY.md. The SSH server and the TPM-held host keys are
> [aSSH](../assh/README.md) (`github.com/tpm2-trust/assh`), a project of
> its own that tpm2-kira uses as a library, from the git submodule `assh/`.

The boot image can bring up a network of its own, and `tpm2-kira run` -
the process that holds the boot at the code screen - then also runs an SSH
server. The SSH protocol runs in a separate process without privileges, and
the host key is made in the TPM at every boot and certified by a
certificate authority that never leaves the TPM either.
Whoever logs in sees the codes, confirms them, and types the disk's
password in the session; when tpm2-kira has no key to give, cryptsetup's
own prompt is asked there too. The console says where to log in, and
Enter at the console continues there instead: a person at the machine is
never held by a remote session.

```bash
sudo tpm2-kira control      # step 2, "Network and SSH at boot": DHCP or static, proposed
                            # from /etc/systemd/network or /etc/network/interfaces;
                            # SSH only when you say yes, the SSH CA created in the TPM;
                            # the image is rebuilt when you quit
# once, on each client: trust the CA (control prints the line)
echo "@cert-authority host.example,192.0.2.10 $(cat /etc/tpm2-kira/ssh_ca.pub)" >> ~/.ssh/known_hosts
ssh root@<address shown on the console>
```

Contents: [1 Configuration](#1-configuration) ·
[2 The image build](#2-the-image-build) ·
[3 Privilege separation](#3-privilege-separation) ·
[4 The host key and the SSH CA](#4-the-host-key-and-the-ssh-ca) · [5 At boot](#5-at-boot) ·
[6 cryptsetup's own prompt](#6-cryptsetups-own-prompt) ·
[7 Using it](#7-using-it) · [8 Commands](#8-commands) ·
[9 The code](#9-the-code) · [10 Tests](#10-tests) ·
[11 Known limits](#11-known-limits)

## 1. Configuration

Two files, both written by `tpm2-kira control` (step 2, the submenu
"Network and SSH at boot"): `/etc/tpm2-kira/control.conf` holds what is
tpm2-kira's - the image's network, whether the SSH server runs, how long
the boot waits; `/etc/tpm2-kira/assh.conf`, beside it, what is aSSH's - the
SSH CA and its slots, the port, the keys that may log in (aSSH's own
format, `ASSH_*`, read with its `config` package).

`control.conf`:

| Key | Values |
|---|---|
| `TPM2_KIRA_NET` | `off` (default), `dhcp`, `static` |
| `TPM2_KIRA_NET_MATCH` | a MAC address (recommended) or an interface name; empty: every wired interface (DHCP only) |
| `TPM2_KIRA_NET_ADDRESS` | static: addresses with prefix, space-separated |
| `TPM2_KIRA_NET_GATEWAY`, `TPM2_KIRA_NET_DNS` | IP addresses, space-separated |
| `TPM2_KIRA_NET_DHCP_ID` | the identity the image asks the DHCP server with: `auto` (default) the running system's, read at every image build (§2.1); `mac`; or a client identifier in hex (`ff:56:50:…`) |
| `TPM2_KIRA_SSH` | `off` (default), `on` (needs a network) |
| `TPM2_KIRA_SSH_HOLD` | seconds the boot waits for a confirmation; `0` (default): until one comes |

`assh.conf` (what control writes; aSSH's README lists every key, and
tpm2-kira refuses those it has no use for - the authority is its signing
key, the window closes the CA, a login is a session of the code screen):

| Key | Values |
|---|---|
| `ASSH_CA` | `efi:KIRAasshCA` (default): the SSH CA's EFI variable (its public key in `/etc/tpm2-kira/ssh_ca.pub`), created in the TPM by control (§4) |
| `ASSH_CA_TYPE` | `p256` (default) or `rsa2048`: what control asked when it created the CA |
| `ASSH_CA_SLOT_<N>` | a slot's PCRs, `0,2,7,11,15`; control writes two, worked out for this machine (§4). An edit takes effect at the next reseal or control, which make the CA's slots these and approve them |
| `ASSH_CA_WINDOW` | `15` (default): the PCR every slot reads and run extends |
| `ASSH_CA_REF` | `tpm2-kira ssh ca` (default): what the signing key's approvals are bound to |
| `ASSH_LISTEN` | `:22` (default): the address the server listens on |
| `ASSH_AUTHORIZED_KEYS` | `/etc/tpm2-kira/authorized_keys` (default), tpm2-kira's own file - control copies root's keys there when asked, edit it for others; any key type OpenSSH has. A line with options in front of the key (`from=`, `command=`) is left out: the options are not honoured. Their sum is part of the SSH part's digest in the boot plan, so control sees a difference without unpacking the image |
| `ASSH_KEY_ID`, `ASSH_PRINCIPALS`, `ASSH_HOSTKEY_TYPE` | the host certificate's name (`tpm2-kira boot`), its principals (`*`), the host key's type (`p256`) |

The window, the type, the bank and the ref are the CA's for good: a
different value in assh.conf is an error that says to create the CA again
(control offers it). So is a CA made for another signing key - after
`setup` made a new one: control offers to create the CA again, as reseal
could not approve it.

**Off by default, on Arch and Debian alike.** Both keys default to `off`;
`run` starts the server only when the image passes `--ssh`; `control`
never runs the step on its own, and its question "Start the SSH server
with the code screen?" is preselected No.

**The step in `control`** asks the settings one by one: the network
(off, DHCP, static), the interface (MAC or name, with this machine's
interfaces listed), for a static address the addresses, gateway and DNS,
then whether to start the SSH server, its port, the hold, and - the first
time - the SSH CA's key type (P-256 recommended, or RSA-2048): it is
created in the TPM, approved with the signing key, and control prints the
`known_hosts` line that makes clients trust it. The first time,
it proposes the network from the running system's configuration:

- systemd-networkd: the first `.network` file in `/etc/systemd/network`
  (then `/run`, `/usr/lib`) whose `[Match]` names a wired interface;
- ifupdown: `/etc/network/interfaces` and what it `source`s (three levels
  deep): the first `iface NAME inet dhcp|static` (or `inet6 static`) of a
  wired interface, with `address`, `netmask` (turned into a prefix),
  `gateway`, `dns-nameservers`;
- otherwise DHCP on the first wired interface.

The interface is matched by MAC, which the proposal fills in. Then it
writes control.conf and offers the rebuild (`mkinitcpio -P`,
`update-initramfs -u`). The step is blocked on systems that build the
image with neither.

**The network is the image's alone.** `/etc/systemd/network` and
`/etc/network/interfaces` belong to the running system; control reads them
only to propose. In the image interfaces keep their kernel names (`eth0`
on Arch), not the predictable names of the running system - hence the
MAC. The network has its own setting apart from SSH because the vault
uses it too ([REMOTE-UNLOCK.md](REMOTE-UNLOCK.md)): a machine may have a
network in the image and no SSH server.

## 2. The image build

`control.conf` itself never goes into the image. The hook calls `tpm2-kira
initramfs plan --buildroot DIR [--format mkinitcpio|initramfs-tools]`, the
boot plan (`tpm2-kira help initramfs`): the network is a part of it when
`TPM2_KIRA_NET` is set and its settings work, the SSH server when
`TPM2_KIRA_SSH=on`, the network is in, the SSH CA exists (§4), and a key
may log in - each part on its own, so a vault keeps its network when SSH
cannot be had. It turns the settings into files of the image, and prints
what the hook has to add (modules - `efivarfs` for the SSH server -,
warnings); the CA is not one of them: it stays in its EFI variable, which
`run` reads at boot. The image names the parts with the digest of their settings,
so `control` tells an image built with another port or other login keys
(the SSH part's digest names the image's assh.conf and keys, the
network's the DHCP identity):

| | Arch (`sd-tpm2-kira`) | Debian (`hooks/tpm2-kira`) |
|---|---|---|
| network | `/etc/systemd/network/10-tpm2-kira.network`; with DHCP the running system's identity (§2.1); systemd-networkd enabled with its user | `/etc/tpm2-kira/remote.conf` (`TPM2_KIRA_NET`, `_MATCH`, `_ADDRESS`, `_GATEWAY`, `_DNS`, `_CLIENTID`, shell-quoted), read by `init-premount/tpm2-kira` |
| run's flags | `/etc/systemd/system/tpm2-kira.service.d/remote.conf`: `TPM2_KIRA_REMOTE=--ssh --ssh-hold=S`, and no `TimeoutStartSec` when the hold has no limit | `TPM2_KIRA_REMOTE=…` in the same `remote.conf` |
| aSSH's settings | `/etc/tpm2-kira/assh.conf`, the running system's, read by `run --ssh` | the same |
| SSH CA | not in the image: the EFI variable `KIRAasshCA`, read by `run` (efivarfs, mounted by systemd) | the same; `run` mounts efivarfs, the hook adds its module |
| login keys | where assh.conf says, `/etc/tpm2-kira/authorized_keys` (their sum is in the SSH part's digest, `/etc/tpm2-kira/plan/ssh/<digest>`) | the same |
| DHCP | systemd-networkd | busybox' `udhcpc` with the identifier (`-x 0x3d:…`, its events in `/etc/tpm2-kira/udhcpc.script`); without one klibc's `ipconfig` (`configure_networking`, as for an NFS root or dropbear-initramfs), which sends none |
| static | systemd-networkd | busybox `ip` |
| driver | the matched interface's module (every network driver when none matches on the build machine) | the same; `auto_add_modules net` for every driver |
| needs | - | busybox in the image (`BUSYBOX`, default `auto`); without it the hook asks for a plan without network (`--no-busybox`), which says so |

### 2.1 The address at boot

A DHCP server hands out addresses by the client identifier it is asked
with. The image has no machine-id, from which systemd-networkd makes its
DUID, and no dhcpcd DUID file: asking as itself it would be another client
and get another address than the running system - the code screen would
be where nobody looks for it. So it asks as the running system does on the
matched interface, read at every image build (`TPM2_KIRA_NET_DHCP_ID=auto`)
from the running system's DHCP client:

| the running system's client | its identity | the image asks with |
|---|---|---|
| systemd-networkd | `networkctl status --json`: the IAID and the DUID (RFC 4361) | networkd: `ClientIdentifier=duid`, `IAID=`, `DUIDType=`, `DUIDRawData=`; Debian: `udhcpc -x 0x3d:…` |
| NetworkManager (its own client) | `CLIENTID=` of its lease file | the same |
| dhcpcd (Debian 13) | `dhcpcd.conf` (`duid`, `clientid`, `iaid`) and `/var/lib/dhcpcd/duid`; the IAID the MAC's last four bytes | the same |
| none of them (ISC dhclient, by default without an identifier) | unknown: the build warns that the address may differ | networkd: the MAC; Debian: `ipconfig`, none |

The build says which: `Network: in - dhcp, asking as the running system's,
systemd-networkd on enp1s0 (ff:56:50:…)`. `TPM2_KIRA_NET_DHCP_ID=mac` or an
identifier in hex sets it instead. A network for every wired interface (no
`TPM2_KIRA_NET_MATCH`) has no one identity to take.

Nothing else goes in: the SSH server is tpm2-kira itself, and no shell, SSH
daemon or password agent is added. The build prints each part with why
it is in or out, `SSH server: in - port 22, host keys certified by the SSH
CA SHA256:…`. If a setting cannot work - SSH without a network, no CA,
nobody who may log in - the SSH
server stays out and says why (the network keeps its part): the image
still boots, with the code screen at the console.

## 3. Privilege separation

```
tpm2-kira run                              (root: TPM, disk key, code screen)
  │  has the TPM make this boot's host key, the SSH CA certify it; opens :PORT
  │  starts, handing over the listening socket and a control socket:
  ▼
tpm2-kira remote serve                     (uid 65534; own net/IPC/PID/mount/UTS namespaces;
  │                                         no new privileges; Landlock: no file access)
  │  speaks SSH (golang.org/x/crypto/ssh), checks the login keys
  │  ── control socket ──▶ run:  "sign this key exchange"  ◀── signature
  │  per login: a socket pair; one end goes to run (SCM_RIGHTS) as a session
  ▼
the session in run: the code screen, Enter, the password prompt
```

`run` must not parse what arrives from the network before a login: it
holds the TPM, the disk's key and the code screen. So the SSH protocol
runs in `tpm2-kira remote serve` - the same binary started again by `run`
(one binary, AGENTS.md) - which gives up everything it does not need
before it reads a byte:

- **nobody** (uid/gid 65534, no supplementary groups, so no capabilities):
  the TPM device and everything in `/etc/tpm2-kira` and `/run/tpm2-kira`
  are out of reach.
- **Namespaces of its own** for network, IPC, PID, mount and UTS. It has
  no network but the listening socket it was handed: it cannot connect
  anywhere. A kernel without one of them starts it without namespaces,
  and says so in the log.
- **No new privileges** (`PR_SET_NO_NEW_PRIVS`), then **Landlock**: a
  ruleset that handles every file access right and allows none (and, on
  newer kernels, no TCP bind or connect, no signals or abstract sockets
  outside it). Without Landlock the log says so.
- It refuses to run as root.

It holds **no host key**: the key exchange is signed by `run`, asked over
the control socket. It holds **no password**: a login becomes a session of
the code screen, one end of a socket pair handed to `run` with
SCM_RIGHTS (this is aSSH's `server` package; `run` hands it the host key as
a signer and takes the sessions), and `remote serve` only relays bytes between that and the SSH
channel. Only a terminal session is served: commands, subsystems,
forwardings and agent requests are refused. At most 8 connections may be
in the middle of a login (30 s each), and 8 sessions at once.

A compromise of the SSH code gets what a login gets: the code screen and
its prompt. It can ask `run` to sign with the host key while the server
runs, as a compromised OpenSSH privilege-separated child can ask its
monitor; it cannot read the key - which is in the TPM - the TPM or the
disk key.

The log shows what it runs with, for example `ssh: remote serve (pid 412)
runs with uid 65534, no new privileges, namespaces of its own, Landlock
ABI 6: no file access` (seen on both test VMs).

## 4. The host key and the SSH CA

The boot image is unencrypted: a host key stored in it lets anyone who
can read `/boot` impersonate the machine. So no key is stored anywhere,
and no secret either: the keys are in the TPM.

- **The SSH CA** is a certificate authority created inside the TPM by
  control (ECDSA P-256, or RSA-2048), never exported. Its file, kept in
  the EFI variable `KIRAasshCA` (aSSH's `efi:` CA, about 1.2 KB), holds
  only the TPM's wrapped copy, which loads in this TPM alone, and the
  approvals. Its use needs no password; its policy is `PolicyAuthorize`:
  it signs only while the PCRs of one of its slots hold values the
  **signing key** approved. The CA and the storage key it
  is made under are noDA: a dictionary attack lockout of the TPM (wrong
  PINs of another TPM object) does not stop it.
- **Its slots are assh.conf's** (`ASSH_CA_SLOT_<N>`), scanned in order;
  the first whose approval the PCRs meet lets the CA certify. control
  writes two when it creates the CA:

  | Slot | PCRs | Confidence |
  |---|---|---|
  | 0 | 0 (firmware), 2 (option ROMs), 7 (Secure Boot state and keys), the image - 11 with a unified kernel image, 8 and 9 with GRUB -, 15 (the window) | higher: what `seal` binds its slot 0 to |
  | 1 | 7, 15 | lower: an image not approved yet, a new option ROM or a firmware update still certify |

  Which of 11 or 8 and 9 is decided from the event log when control
  creates the CA, as `seal` decides. A slot changed, added or taken away
  in assh.conf is the CA's at the next reseal or control: a slot is a PCR
  selection the signing key approves states of, not a key, so the CA stays
  and so does its `known_hosts` line; a changed slot's approvals go, and
  the new selection is approved.
- **Why the CA lives in an EFI variable.** An approval of PCR 11 (or 9)
  carried inside the image would change the very measurement it approves.
  In the variable it is outside: the image is built, its values are
  predicted, approved, and written to the variable. Nothing in the
  variable is secret, and the TPM checks every approval in it; writing it
  takes root, who can delete the CA, never make it sign. It is the CA's
  only copy: firmware that wipes its variables loses the CA, as a TPM
  clear does - control then creates a new one, and the clients need its
  new line.
- **The window is PCR 15.** Both slots read it, and nothing in the boot
  image measures it before the code screen, so the next boot meets it
  empty. `run` extends it (`tpm2-kira: ssh ca closed`) right after the
  CA certified this boot's key - also when the key is temporary - so
  the CA certifies nothing more until the next reboot: not in the running
  system, on Arch or Debian, with or without `systemd-pcrosseparator`.
- **The approved values** are those of tpm2-kira's measure point: the code
  screen holds the boot ahead of `systemd-pcrosseparator`, which extends
  PCR 0-7 in the running system. They are replayed from the firmware
  event log (`measurepoint.go`), PCR 11 computed from the unified kernel
  image (`ukipredict.go`), PCR 8 and 9 predicted from grub.cfg and the
  files GRUB loads (`grub_predict.go`) - as `seal` does -; the window is
  empty. **`reseal` approves them** in both slots, with the signing key,
  whenever a slot has no approval of the next boot: the initramfs hooks
  run it after every image rebuild, so a kernel update needs nothing by
  hand. control approves them when it creates the CA and at quit; the CA
  and the clients' trust in it stay the same. A reseal that is skipped
  (the YubiKey not plugged in) leaves slot 1, which reads no image.
- **At every boot** `run` has the TPM make a new host key (the CA's type)
  under the TPM's **NULL hierarchy**, whose seed changes at every reboot,
  and the CA certify it (an OpenSSH host certificate) - when the SSH
  server starts, before the separator; then the window closes. The host key's authorization value
  is in `run`'s memory alone (the process is not dumpable); the key signs
  every key exchange of this boot, after the separator too, so a dropped
  session can come back; at the next reboot it loads nowhere.
- **Clients trust the CA, once**: `@cert-authority <the machine's names and
  addresses> <ssh_ca.pub>` in `known_hosts`. The certificate is valid
  for any host name (principal `*`); the pattern in `known_hosts` chooses
  the hosts. A new key at every boot asks the clients nothing.
- **When the CA does not certify** (a Secure Boot update, so that no slot
  is met; another TPM; no CA in the variable): `run` serves aSSH's
  **temporary key** - made in the TPM under the NULL hierarchy like the
  certified one, gone at the next reboot, but not certified. The console
  shows its fingerprint and, for each slot, which PCR changed, and `ssh` warns of an
  unknown host key. Quit `tpm2-kira control` once after that boot, or run
  `tpm2-kira reseal`: it approves the new values. Without a TPM there is no SSH
  server.

No `systemd-creds` and no TPM library go into the image: aSSH does the TPM
work in Go (go-tpm), compiled into tpm2-kira.

The running system's own sshd can use the same idea with a CA of its own
(`assh agent`, bound to the state after the unlock and closed by a PCR
extended once it started): see aSSH's README. tpm2-kira does not set that
up.

## 5. At boot

### 5.1 Arch (systemd in the initrd)

```
tpm2-kira.service (holds READY)
  ├── the TPM makes this boot's host key, the SSH CA certifies it (slot 0 or 1),
  │   PCR 15 is extended (the window closes), opens :PORT, starts 'remote serve'
  ├── console: "ssh root@<address>", the SSH CA's fingerprint, sessions connected,
  │            "Enter here: continue at this console"
  └── sessions: the code screen; Enter confirms, q leaves
```

The network comes up in parallel with the code screen: networkd is not
ordered after the hold.

- **Confirmed in a session.** The boot is released (READY, the separator
  runs). The password prompt (tpm2-kira's: password+salt or
  password+remotesalt) opens in that session. The server keeps running
  until switch-root, so a dropped session can log in again for the
  prompt. If tpm2-kira has no key to give, cryptsetup's own prompt is
  asked in the session too (§6).
- **Enter at the console.** The boot is released, every session is told
  and closed, `remote serve` ends and the port with it, and the prompt is
  the console's. No remote confirmation can hold a person at the machine
  (AGENTS.md: no enforced mode).
- **Released by the phone, by the vault's key, or by the hold's end.** The
  newest session takes the prompt; with no session, the server stops and
  the console asks.
- **Switch-root.** systemd stops the service; `run` stops the server
  first, wherever it is.

### 5.2 Debian (initramfs-tools)

```
init-premount/tpm2-kira
  ├── tpm2-kira run --ssh ...              (background, as on Arch)
  └── the network, in the background: waits up to 180 s for the interface (MAC,
      name, or the first wired one), then udhcpc with the client identifier
      or ipconfig without one (DHCP), or ip (static);
      log /run/initramfs/tpm2-kira.log, device in /run/tpm2-kira/net-device
local-top/cryptroot
  └── keyscript=/lib/cryptsetup/scripts/tpm2-kira: 'tpm2-kira unlock-key' waits on
      run's socket - the hold is there, until the code is confirmed
init-bottom/tpm2-kira
  └── SIGTERM to run (sessions told, 'remote serve' ends; KILL after a second),
      'killall ipconfig', the interface's addresses and routes flushed, the link
      set down, /run/net-<dev>.conf removed
```

The interface is taken down before the real root takes over: ifupdown or
NetworkManager configure it again, and an address left from the image
would stay beside theirs.

## 6. cryptsetup's own prompt

When tpm2-kira has no key to give (no token on the volume, Ctrl-C at its
prompt, a wrong answer, a vault that refused), cryptsetup asks for itself.
`run` asks the same question in the session that has the prompt, beside
the console. The first answer counts; a question answered at the console
is withdrawn from the session ("Answered at the console."), and a session
that leaves in the middle answers nothing - the question stays for the
console and is asked again in the next session.

| | Arch | Debian |
|---|---|---|
| who asks | systemd-cryptsetup, through systemd's password agents | the keyscript's last try: `/lib/cryptsetup/askpass` |
| the question | a file `/run/systemd/ask-password/ask.*` | an askpass process holding `/lib/cryptsetup/passfifo` open (found through `/proc/*/exe` and its fds); its prompt is its argument |
| the answer | a datagram `+password` to the socket the file names | written into the FIFO, as `cryptroot-unlock` does |
| gone | the file is removed (or its time is up) | the process is gone (its start time changed) |

In the session it reads: `cryptsetup asks: Please unlock disk vda3_crypt
(the console asks it too; the first answer counts)`, then `Passphrase:`.

## 7. Using it

- **Where to log in.** The console shows `ssh root@<address>` with the
  SSH CA's fingerprint, and updates it when an address comes up or a
  session comes or goes. DHCP may give the image another address than the
  running system (§11); a reservation by MAC or a static address makes it
  predictable.
- **known_hosts.** One line per client trusts the CA:
  `@cert-authority host.example,192.0.2.10 ecdsa-sha2-nistp256 AAAA…`
  (`tpm2-kira control` prints it; the key is `/etc/tpm2-kira/ssh_ca.pub`).
  A client without it sees an unknown host key at every boot. The running
  system keeps its own OpenSSH host key; a plain `known_hosts` entry for
  it does not cover the image (a certificate is checked against the CA
  line only).
- **The log.** Arch: `journalctl -b -u tpm2-kira.service`. Debian:
  `/run/initramfs/tpm2-kira.log` (it stays after the boot), with the
  network's lines.
- **After the boot.** Nothing of it is left: the server ends at
  switch-root (Arch) or at init-bottom (Debian), the image's address is
  removed (Debian), no tpm2-kira process remains.

## 8. Commands

```
tpm2-kira control                       step 2, "Network and SSH at boot"
tpm2-kira initramfs plan --buildroot DIR [--format mkinitcpio|initramfs-tools]
                           [--conf PATH] [--tpm PATH]
                                        what the hooks call (§2): a part that cannot be had stays out, and says why
tpm2-kira remote serve                  the SSH protocol, started by 'run --ssh' alone (§3)
tpm2-kira run --ssh [--ssh-hold S] [--ssh-conf PATH]
                                        set by the image (§2): be the SSH server too, as the
                                        image's assh.conf says
```

## 9. The code

| File | What |
|---|---|
| `cmd/remote_config.go` | the settings, their check, the networkd file, the proposal from networkd and ifupdown |
| `cmd/remote_assh.go` | assh.conf: tpm2-kira's defaults, the keys it refuses |
| `cmd/remote_dhcpid.go` | the image's DHCP identity: the running system's, read from its DHCP client |
| `cmd/control_remote.go` | control's step |
| `cmd/bootplan.go` | the boot plan: whether the network and the SSH server go in, and their files for both formats |
| `cmd/remote_initramfs.go` | the files' contents: `remote.conf`, the drop-in, the image's assh.conf, the login keys, udhcpc's script |
| `cmd/remote_hostkey.go` | the SSH CA in its EFI variable: its two slots and window, approved at the measure point; this boot's host key, certified or temporary; the window closed |
| `cmd/reseal.go` | `reseal` approves the SSH CA after the slots |
| `cmd/remote_ssh.go` | the server in `run`: sessions, the code screen, prompts, the console hint, release and stop |
| `assh/server` | `remote serve`: the SSH protocol, the sandbox; `run`'s side of it: starting it without privileges, signing, taking sessions |
| `assh/hostkey` | the CA in the TPM, its slots and approvals, the per-boot host key and its certificate, the temporary key |
| `assh/config` | assh.conf: its keys, writing it, making a CA's slots the file's |
| `cmd/remote_agent.go` | cryptsetup's own prompt in the session (§6) |
| `initramfs/mkinitcpio/install/sd-tpm2-kira` | the Arch hook's part |
| `initramfs/initramfs-tools/hooks/tpm2-kira`, `scripts/init-premount/tpm2-kira`, `scripts/init-bottom/tpm2-kira` | the Debian hook and scripts |

## 10. Tests

- **Unit** (`go test ./...`): the settings and their lines
  (`TestRemoteConfigLines`, `TestSetRemoteConfig`), the networkd file, the
  proposal from networkd and from ifupdown (`TestSuggestNetwork…`), the
  image's files for both formats (`TestWriteImageMkinitcpio`,
  `TestWriteImageInitramfsTools`), the server: a session confirms and answers,
  leaves the prompt, what is refused, Enter at the console stops it, a
  release elsewhere, the temporary key's console hint (with a key in software: no TPM in the unit tests), the console hint, `remote serve`
  alone (`cmd/remote_ssh_test.go`); cryptsetup's question through
  ask-password and through askpass' FIFO (`cmd/remote_agent_test.go`); the
  hooks add network and SSH on Arch and Debian (`hook_test.go`).
- **swtpm** (`-tags integration`): the CA approved in both slots at the
  code screen, certifying there through slot 0, nothing more once the
  window closed, through slot 1 after a reboot with a firmware update and
  a new option ROM, approved again by `reseal` and refused with another
  key (`TestSSHCAApprovedForTheCodeScreen`; a file in place of the EFI
  variable, which aSSH tests); the whole
  chain with `run --ssh` - SSH to the unprivileged `remote serve`, the
  session handed to `run`, the code screen, the key socket
  (`TestRemoteSSHConfirmsAndUnlocks`, `TestRemoteSSHEnterAtConsoleStops`).
- **On the test VMs** (2026-10-10): Arch and Debian each booted with the
  image's network and SSH; the sandbox line in the log; the strict host
  key check against the system's entry passed; the code confirmed in the
  session, the password prompt there, cryptsetup's own prompt answered in
  the session (on Debian through the FIFO, including the question asked
  again in a second session after the first left); after the boot no
  address of the image and no process left.

Not run on a VM yet: a static address on Debian, the temporary key made
in the TPM (the software key before it ran on Arch), and the SSH CA
at all (the VM runs above were with the sealed key that came before it):
its EFI variable written by reseal and read at the code screen, PCR 11
and PCR 8/9 approved from the prediction.
aSSH's own tests log in with OpenSSH's client (10.6) through a
`@cert-authority` line against a software TPM.

## 11. Known limits

- **Slot 1 binds the CA to the Secure Boot keys, not to the image.** Any
  image signed with the same key that gives a root
  shell before the window closes (an initramfs with an emergency shell, an
  older UKI, an image without tpm2-kira's SSH server, which never closes
  it) can have the CA certify a key of its own for that boot - not take
  the CA away. Keep such images unsigned. Without Secure Boot, PCR 7 says
  little: any OS booted on the machine reaches the same values. The CA
  never leaves this TPM either way; a certificate made so is good for the
  machine's names until the clients drop the CA line.
- **PCR 15 is extended in every boot with the SSH server**, before
  cryptsetup. Whatever the running system binds to PCR 15 (systemd's
  machine-id and file system measurements, a volume enrolled with
  `systemd-cryptenroll --tpm2-pcrs=15`) sees that extension; turning the
  SSH server on or off changes the value. Something that measured PCR 15
  before the code screen (a volume unlocked earlier with
  `tpm2-measure-pcr=`) meets no slot: the key is temporary.
- **The approvals are the signing key's.** Whoever holds it can approve
  another state; keep it on the YubiKey.
- **An approval is never revoked.** reseal and control keep only the
  approvals of the next boot in the variable, but root can write back a
  copy from before an update, which lets the CA sign in the old state,
  should the machine boot it again (an older signed kernel). aSSH's authority in the
  TPM has a counter that revokes old approvals; the signing key, a key
  elsewhere, has none.
- **The temporary key cannot be checked from afar.** Its fingerprint is
  on the console only; whoever logs in remotely after a firmware update
  has to accept an unknown key for that boot - never with
  `StrictHostKeyChecking=accept-new`, which takes anyone's without asking.
- **DHCP may give the image another address than the running system**,
  because the client identifiers differ (on the Debian test VM klibc's
  `ipconfig` got .102 or .104, dhclient .196).
- **Debian needs busybox in the image** for any network.
