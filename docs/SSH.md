# SSH in the boot image: the code screen over the network

> Arch (mkinitcpio, systemd in the initrd) and Debian (initramfs-tools).
> Off until turned on. Experimental. The superseded designs (tinysshd, an
> unencrypted host key, mkinitcpio-systemd-extras' hooks) are in
> HISTORY.md.

The boot image can bring up a network of its own, and `tpm2-kira run` -
the process that holds the boot at the code screen - then also runs an SSH
server. The SSH protocol runs in a separate process without privileges.
Whoever logs in sees the codes, confirms them, and types the disk's
password in the session; when tpm2-kira has no key to give, cryptsetup's
own prompt is asked there too. The console says where to log in, and
Enter at the console continues there instead: a person at the machine is
never held by a remote session.

```bash
sudo tpm2-kira control      # "Network and SSH at boot": DHCP or static, proposed
                            # from /etc/systemd/network or /etc/network/interfaces;
                            # SSH only when you say yes; rebuilds the image
ssh root@<address shown on the console>
```

Contents: [1 Configuration](#1-configuration) ·
[2 The image build](#2-the-image-build) ·
[3 Privilege separation](#3-privilege-separation) ·
[4 The host key](#4-the-host-key) · [5 At boot](#5-at-boot) ·
[6 cryptsetup's own prompt](#6-cryptsetups-own-prompt) ·
[7 Using it](#7-using-it) · [8 Commands](#8-commands) ·
[9 The code](#9-the-code) · [10 Tests](#10-tests) ·
[11 Known limits](#11-known-limits)

## 1. Configuration

All of it is in `/etc/tpm2-kira/control.conf`, written by `tpm2-kira
control` (the step "Network and SSH at boot"):

| Key | Values |
|---|---|
| `TPM2_KIRA_NET` | `off` (default), `dhcp`, `static` |
| `TPM2_KIRA_NET_MATCH` | a MAC address (recommended) or an interface name; empty: every wired interface (DHCP only) |
| `TPM2_KIRA_NET_ADDRESS` | static: addresses with prefix, space-separated |
| `TPM2_KIRA_NET_GATEWAY`, `TPM2_KIRA_NET_DNS` | IP addresses, space-separated |
| `TPM2_KIRA_SSH` | `off` (default), `on` (needs a network) |
| `TPM2_KIRA_SSH_PORT` | 22 |
| `TPM2_KIRA_SSH_HOLD` | seconds the boot waits for a confirmation; `0` (default): until one comes |
| `TPM2_KIRA_SSH_AUTHORIZED_KEYS` | `/root/.ssh/authorized_keys`; any key type OpenSSH has. A line with options in front of the key (`from=`, `command=`) is left out: the options are not honoured |
| `TPM2_KIRA_SSH_HOSTKEY` | `/etc/ssh/ssh_host_ed25519_key` (the system's OpenSSH key), or an ed25519 key of the image's own (control creates `/etc/tpm2-kira/ssh_host_ed25519_key`). Sealed to the TPM, §4 |

**Off by default, on Arch and Debian alike.** Both keys default to `off`;
`run` starts the server only when the image passes `--ssh`; `control`
never runs the step on its own, and its question "Start the SSH server
with the code screen?" is preselected No.

**The step in `control`** asks the settings one by one: the network
(off, DHCP, static), the interface (MAC or name, with this machine's
interfaces listed), for a static address the addresses, gateway and DNS,
then whether to start the SSH server, its port, the hold, and the host
key (the system's OpenSSH key or one of the image's own). The first time,
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
remote initramfs --buildroot DIR [--format mkinitcpio|initramfs-tools]`,
which turns the settings into files of the image, seals the host key, and
prints what the hook has to add (modules, warnings):

| | Arch (`sd-tpm2-kira`) | Debian (`hooks/tpm2-kira`) |
|---|---|---|
| network | `/etc/systemd/network/10-tpm2-kira.network`; with DHCP `ClientIdentifier=mac` (the image has no machine-id for a stable DUID); systemd-networkd enabled with its user | `/etc/tpm2-kira/remote.conf` (`TPM2_KIRA_NET`, `_MATCH`, `_ADDRESS`, `_GATEWAY`, `_DNS`, shell-quoted), read by `init-premount/tpm2-kira` |
| run's flags | `/etc/systemd/system/tpm2-kira.service.d/remote.conf`: `TPM2_KIRA_REMOTE=--ssh=PORT --ssh-hold=S --ssh-hostkey=…`, and no `TimeoutStartSec` when the hold has no limit | `TPM2_KIRA_REMOTE=…` in the same `remote.conf` |
| host key | `/etc/tpm2-kira/ssh/ed25519.sealed` (§4) | the same |
| login keys | `/root/.ssh/authorized_keys` | the same |
| DHCP | systemd-networkd | initramfs-tools' klibc `ipconfig` (`configure_networking`, as for an NFS root or dropbear-initramfs) |
| static | systemd-networkd | busybox `ip` |
| driver | the matched interface's module (every network driver when none matches on the build machine) | the same; `auto_add_modules net` for every driver |
| needs | - | busybox in the image (`BUSYBOX`, default `auto`); without it the hook adds no network and says so |

Nothing else goes in: the SSH server is tpm2-kira itself, and no shell, SSH
daemon or password agent is added. The hook prints what it did:
`network at boot: dhcp via virtio_net`, `SSH at boot on port 22`, `SSH host
key SHA256:… sealed to PCR 0+7`. If a setting cannot work - SSH without a
network, no host key, a key that cannot be sealed, nobody who may log in -
the build goes on without network and SSH and says why: the image still
boots, with the code screen at the console.

## 3. Privilege separation

```
tpm2-kira run                              (root: TPM, disk key, code screen, host key)
  │  opens :PORT, unseals the host key, keeps it in memory
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
SCM_RIGHTS, and `remote serve` only relays bytes between that and the SSH
channel. Only a terminal session is served: commands, subsystems,
forwardings and agent requests are refused. At most 8 connections may be
in the middle of a login (30 s each), and 8 sessions at once.

A compromise of the SSH code gets what a login gets: the code screen and
its prompt. It can ask `run` to sign with the host key while the server
runs, as a compromised OpenSSH privilege-separated child can ask its
monitor; it cannot read the key, the TPM or the disk key.

The log shows what it runs with, for example `ssh: remote serve (pid 412)
runs with uid 65534, no new privileges, namespaces of its own, Landlock
ABI 6: no file access` (seen on both test VMs).

## 4. The host key

The boot image is unencrypted: a host key stored in it lets anyone who
can read `/boot` impersonate the machine. So the image holds the key only
sealed to the TPM, bound to **PCR 0** (firmware) and **PCR 7** (Secure
Boot state and keys):

- The image build reads the key - by default the running system's
  OpenSSH host key, so the image answers with the same key as the system
  and clients need no second `known_hosts` entry - and seals its 32-byte
  seed to the TPM as a keyed-hash object whose only authorization is a
  PCR policy (no password).
- The values sealed are those of tpm2-kira's measure point: the code
  screen holds the boot ahead of `systemd-pcrosseparator`, which extends
  PCR 0-7 in the running system. They are replayed from the firmware
  event log (`measurepoint.go`), not read from the registers. The build
  leaves SSH out (and says why) when the event log does not describe PCR
  0 and 7.
- `run` unseals the key once, when the SSH server starts - before the
  separator - through a salted, encrypted session, and keeps it in its
  own memory. It is written nowhere.
- The key is sealed afresh at every image build, so a kernel update does
  not touch it. After a firmware or Secure Boot update it no longer
  unseals: `run` serves a **throwaway key**, the console shows its
  fingerprint and which PCR changed, and `ssh` warns of a changed host
  key. Unlock once, rebuild the image, and the sealed key is back.

No `systemd-creds` and no TPM library go into the image: tpm2-kira seals
and unseals with its own TPM code.

## 5. At boot

### 5.1 Arch (systemd in the initrd)

```
tpm2-kira.service (holds READY)
  ├── unseals the host key (PCR 0+7), opens :PORT, starts 'remote serve'
  ├── console: "ssh root@<address>", the host key's fingerprint, sessions connected,
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
  ├── tpm2-kira run --ssh=PORT ...          (background, as on Arch)
  └── the network, in the background: waits up to 180 s for the interface (MAC,
      name, or the first wired one), then ipconfig (DHCP) or ip (static);
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
  host key's fingerprint, and updates it when an address comes up or a
  session comes or goes. DHCP may give the image another address than the
  running system (§11); a reservation by MAC or a static address makes it
  predictable.
- **known_hosts.** With the default key nothing changes for clients: the
  image presents the system's own OpenSSH host key. A strict check against
  the system's entry passes (`ssh -o HostKeyAlias=<system address>`).
- **The log.** Arch: `journalctl -b -u tpm2-kira.service`. Debian:
  `/run/initramfs/tpm2-kira.log` (it stays after the boot), with the
  network's lines.
- **After the boot.** Nothing of it is left: the server ends at
  switch-root (Arch) or at init-bottom (Debian), the image's address is
  removed (Debian), no tpm2-kira process remains.

## 8. Commands

```
tpm2-kira control                       the step "Network and SSH at boot"
tpm2-kira remote initramfs --buildroot DIR [--format mkinitcpio|initramfs-tools]
                           [--conf PATH] [--tpm PATH]
                                        what the hooks call (§2); exit 2: nothing to add, and why
tpm2-kira remote serve                  the SSH protocol, started by 'run --ssh' alone (§3)
tpm2-kira run --ssh=PORT [--ssh-hold S] [--ssh-hostkey PATH] [--ssh-authorized-keys PATH]
                                        set by the image (§2): be the SSH server too
```

## 9. The code

| File | What |
|---|---|
| `cmd/remote_config.go` | the settings, their check, the networkd file, the proposal from networkd and ifupdown |
| `cmd/control_remote.go` | control's step |
| `cmd/remote_initramfs.go` | `remote initramfs`: the image's files for both formats, `remote.conf` |
| `cmd/remote_hostkey.go` | sealing the host key to PCR 0+7 at the measure point, unsealing at boot, the throwaway key |
| `cmd/remote_ssh.go` | the server in `run`: sessions, the code screen, prompts, the console hint, release and stop |
| `cmd/remote_serve.go` | `remote serve`: the SSH protocol, the sandbox |
| `cmd/remote_privsep.go` | `run`'s side of it: starting it without privileges, signing, taking sessions |
| `cmd/remote_agent.go` | cryptsetup's own prompt in the session (§6) |
| `initramfs/mkinitcpio/install/sd-tpm2-kira` | the Arch hook's part |
| `initramfs/initramfs-tools/hooks/tpm2-kira`, `scripts/init-premount/tpm2-kira`, `scripts/init-bottom/tpm2-kira` | the Debian hook and scripts |

## 10. Tests

- **Unit** (`go test ./...`): the settings and their lines
  (`TestRemoteConfigLines`, `TestSetRemoteConfig`), the networkd file, the
  proposal from networkd and from ifupdown (`TestSuggestNetwork…`), the
  image's files for both formats (`TestRemoteInitramfs`,
  `TestRemoteInitramfsTools`), the server: a session confirms and answers,
  leaves the prompt, what is refused, Enter at the console stops it, a
  release elsewhere, the throwaway key, the console hint, `remote serve`
  alone (`cmd/remote_ssh_test.go`); cryptsetup's question through
  ask-password and through askpass' FIFO (`cmd/remote_agent_test.go`); the
  hooks add network and SSH on Arch and Debian (`hook_test.go`).
- **swtpm** (`-tags integration`): the host key sealed to PCR 0 and 7, not
  unsealing after a PCR moved (`TestHostKeySealedToPCR0And7`); the whole
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

Not run on a VM yet: a static address on Debian, the throwaway key on
Debian (the Go code is the same as on Arch, where it was).

## 11. Known limits

- **PCR 0 and 7 bind the host key to the firmware and the Secure Boot
  keys, not to the image.** Any image signed with the same key that gives
  a root shell before the separator (an initramfs with an emergency
  shell, an older UKI) can unseal it - and with the default, that is the
  system's own OpenSSH host key. Keep such images unsigned, or use a key
  of the image's own (`TPM2_KIRA_SSH_HOSTKEY=/etc/tpm2-kira/ssh_host_ed25519_key`).
  Without Secure Boot, PCR 7 says little: any OS booted on the machine
  reaches the same values.
- **On Debian with GRUB nothing extends PCR 0-7 after the image**: the
  sealed host key unseals in the running system too, and with Secure Boot
  off in any OS booted on the machine. With the default key that gives
  nothing away that root does not have already; a key of the image's own
  is kept out of a readable `/boot` and off other machines, not away from
  this one.
- **The throwaway key cannot be checked from afar.** Its fingerprint is
  on the console only; whoever logs in remotely after a firmware update
  has to accept an unknown key for that boot.
- **DHCP may give the image another address than the running system**,
  because the client identifiers differ (on the Debian test VM klibc's
  `ipconfig` got .102 or .104, dhclient .196).
- **Debian needs busybox in the image** for any network.
