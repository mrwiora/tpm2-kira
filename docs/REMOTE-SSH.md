# The code screen over SSH

Arch (mkinitcpio) and Debian (initramfs-tools). The boot image brings up
a network of its own, and
`tpm2-kira run`, the process that holds the boot at the code screen, also
runs an SSH server, with the SSH protocol in a separate, unprivileged
process. Whoever logs in sees the codes, confirms them, and types the
disk's password there. The console says where to log in, and Enter at the
console continues there instead. Network and SSH are both off until set
in `control.conf` (by hand or with `tpm2-kira control`, whose SSH question
defaults to No).

## Configuration

All of it is in `/etc/tpm2-kira/control.conf`, written by `tpm2-kira
control` (the "Network and SSH at boot" step):

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
| `TPM2_KIRA_SSH_HOSTKEY` | `/etc/ssh/ssh_host_ed25519_key` (the system's OpenSSH key), or an ed25519 key of the image's own (control creates `/etc/tpm2-kira/ssh_host_ed25519_key`). Sealed to the TPM, see below |

The network is configured for the image alone and does not depend on
`/etc/systemd/network` or `/etc/network/interfaces`, which belong to the
running system. control reads them only to suggest DHCP or the static
address, plus the MAC of the interface they name. Match by MAC: in the image,
interfaces keep their kernel names (`eth0`), not the predictable names of
the running system. The network has its own setting, apart from SSH,
because more will use it later: an outgoing request for the remote salt
(PLAN-REMOTEUNLOCKING.md) reuses the same systemd-networkd setup.

`control.conf` itself never goes into the image. When the image is
built, `tpm2-kira remote initramfs --buildroot DIR` (called by the hook)
turns the settings into files of the image. On Arch:

- `/etc/systemd/network/10-tpm2-kira.network`. With DHCP it sets
  `ClientIdentifier=mac`, because the image has no machine-id to derive
  a stable DUID from.
- `/etc/tpm2-kira/ssh/ed25519.sealed`: the host key, sealed to this TPM
  (see "The host key").
- `/root/.ssh/authorized_keys`.
- `/etc/systemd/system/tpm2-kira.service.d/remote.conf`, which sets
  `TPM2_KIRA_REMOTE` for the unit's `ExecStart` (`--ssh=PORT
  --ssh-hold=S ...`) and lifts `TimeoutStartSec` when the hold has no
  limit.

On Debian (`--format initramfs-tools`) the network and the flags for
`run` go into one file instead, `/etc/tpm2-kira/remote.conf`, read by
`scripts/init-premount/tpm2-kira`; the sealed key and the authorized keys
are the same files.

The mkinitcpio hook adds systemd-networkd (enabled, with its user), the
initramfs-tools hook nothing but the driver: DHCP is initramfs-tools' own
klibc `ipconfig` (as for an NFS root or dropbear-initramfs), a static
address busybox' `ip`, which also takes the network down at the end -
without busybox in the image the hook adds no network. Both add the driver
module of the matched interface (every network driver when none matches
on the build machine). Nothing else: the SSH server is tpm2-kira itself,
and no shell, SSH daemon or password agent goes into the image. If a
setting cannot work (SSH without a network, no host key, a key that
cannot be sealed, nobody who may log in), the build goes on without
network and SSH and says why: the image still boots, with the code screen
at the console.

## Privilege separation

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
runs in `tpm2-kira remote serve`, the same binary started again by `run`,
which gives up everything it does not need before it reads a byte:

- **nobody** (uid/gid 65534, no supplementary groups, so no capabilities):
  the TPM device and everything in `/etc/tpm2-kira` and `/run/tpm2-kira`
  are out of reach.
- **Namespaces of its own** for network, IPC, PID, mount and UTS. It has
  no network but the listening socket it was handed: it cannot connect
  anywhere. A kernel without one of them starts it without namespaces,
  and says so in the journal.
- **No new privileges** (`PR_SET_NO_NEW_PRIVS`), then **Landlock**: a
  ruleset that handles every file access right and allows none (and, on
  newer kernels, no TCP bind or connect, no signals or abstract sockets
  outside it). Without Landlock the journal says so.
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

The journal shows what it runs with, for example `ssh: remote serve (pid
412) runs with uid 65534, no new privileges, namespaces of its own,
Landlock ABI 6: no file access`.

## The host key

The boot image is unencrypted: a host key stored in it lets anyone who
can read `/boot` impersonate the machine. So the image holds the key only
sealed to the TPM, bound to **PCR 0** (firmware) and **PCR 7** (Secure
Boot state and keys):

- The image build reads the key - by default the running system's
  OpenSSH host key, so the image answers with the same key as the system
  and the clients need no second `known_hosts` entry - and seals its
  32-byte seed to the TPM as a keyed-hash object whose only authorization
  is a PCR policy (no password).
- The values sealed are those of tpm2-kira's measure point: the code
  screen holds the boot ahead of `systemd-pcrosseparator`, which extends
  PCR 0-7 in the running system. They are replayed from the firmware
  event log (measurepoint.go), not read from the registers. The build
  fails (no SSH in the image, the hook says why) when the event log does
  not describe PCR 0 and 7.
- `run` unseals the key once, when the SSH server starts - before the
  separator - through a salted, encrypted session, and keeps it in its
  own memory. It is written nowhere.
- The key is sealed afresh at every image build, so a kernel update does
  not touch it. After a firmware or Secure Boot update it no longer
  unseals: `run` serves a throwaway key, the console shows its
  fingerprint and which PCR changed, and `ssh` warns of a changed host
  key. Unlock once, rebuild the image, and the sealed key is back.

No `systemd-creds` and no TPM library goes into the image: tpm2-kira
seals and unseals with its own TPM code. Unlike mkinitcpio-systemd-extras'
`sd-tinyssh` (which unseals with `systemd-creds` after the separator),
the values are taken before it.

## At boot

```
tpm2-kira.service (holds READY)
  ├── unseals the host key (PCR 0+7), opens :PORT, starts 'remote serve'
  ├── console: "ssh root@<address>", the host key's fingerprint, sessions connected,
  │            "Enter here: continue at this console"
  └── sessions: the code screen; Enter confirms, q leaves
```

- **Confirmed in a session.** The boot is released (READY, the separator
  runs). The password prompt (tpm2-kira's: password+salt, or
  password+remotesalt) opens in that session. The server keeps running
  until switch-root, so a dropped session can log in again for the
  prompt. If tpm2-kira has no key to give (no token on the volume,
  Ctrl-C, a wrong answer), cryptsetup's own prompt follows: `run` is the
  session's password agent (systemd's ask-password protocol) and asks it
  there too, beside the console's agent. The first answer counts; a
  question answered at the console is withdrawn from the session, and a
  session that leaves in the middle answers nothing.
- **Enter at the console.** The boot is released, every session is told
  and closed, `remote serve` ends and the port with it, and the prompt is
  the console's. No remote confirmation can hold a person at the machine
  (AGENTS.md: no enforced mode).
- **Released by the phone, or the hold's end.** The newest session takes
  the prompt. With no session connected, the server stops and the
  console asks.
- **Switch-root.** systemd stops the service; `run` stops the server
  first, wherever it is.

The network comes up in parallel with the code screen: networkd is not
ordered after the hold.

### On Debian

```
init-premount/tpm2-kira
  ├── tpm2-kira run --ssh=PORT ...          (background, as on Arch)
  └── the network, in the background: waits for the interface (MAC, name, or the
      first wired one), then ipconfig (DHCP) or ip (static)
local-top/cryptroot
  └── keyscript=/lib/cryptsetup/scripts/tpm2-kira: 'tpm2-kira unlock-key' waits on
      run's socket - the hold is there, until the code is confirmed
init-bottom/tpm2-kira
  └── SIGTERM to run (sessions told, 'remote serve' ends), then the interface's
      addresses and routes flushed and the link set down
```

Without systemd there is no ask-password: cryptsetup's own prompt is
`/lib/cryptsetup/askpass` (the keyscript's last try, or Ctrl-C at
tpm2-kira's prompt). askpass reads the console and the FIFO
`/lib/cryptsetup/passfifo` at once; `run` finds the askpass process that
holds the FIFO open, asks its prompt in the session and writes the answer
into the FIFO, as `cryptroot-unlock` does. The question is gone when that
process is.

The interface is taken down before the real root takes over: ifupdown or
NetworkManager configure it again, and an address left from the image
would stay beside theirs.

## Known limits

- **PCR 0 and 7 bind the host key to the firmware and the Secure Boot
  keys, not to the image.** Any image signed with the same key that gives
  a root shell before the separator (an initramfs with an emergency
  shell, an older UKI) can unseal it - and with the default, that is the
  system's own OpenSSH host key. Keep such images unsigned, or use a key
  of the image's own (`TPM2_KIRA_SSH_HOSTKEY=/etc/tpm2-kira/ssh_host_ed25519_key`).
  Without Secure Boot, PCR 7 says little: any OS booted on the machine
  reaches the same values.
- **The throwaway key cannot be checked from afar.** Its fingerprint is
  on the console only; whoever logs in remotely after a firmware update
  has to accept an unknown key for that boot.
- **DHCP may give the image another address than the running system**,
  because the client identifiers differ (on the Debian test VM: klibc's
  `ipconfig` got another lease than dhclient). The console shows the
  address; a reservation by MAC or a static address makes it predictable.
- **On Debian with GRUB nothing extends PCR 0-7 after the image**, and
  with Secure Boot off PCR 7 says little: the sealed host key unseals in
  the running system too, and in any OS booted on the machine. With the
  default, the system's own OpenSSH key, that gives nothing away that root
  does not have already; a key of the image's own is kept out of a
  readable `/boot` and off other machines, not away from this one.
- **Debian needs busybox in the image** (initramfs-tools' `BUSYBOX`,
  default `auto`): its `ip` sets a static address and takes the network
  down at the end. Without it the hook adds no network and says so.
