# The code screen over SSH

Arch / mkinitcpio. The boot image brings up a network of its own and
`tpm2-kira run`, the process that holds the boot at the code screen, is
also its SSH server. Whoever logs in sees the codes, confirms them, and
types the disk's password there. The console says where to log in, and
Enter at the console continues there instead.

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
| `TPM2_KIRA_SSH_AUTHORIZED_KEYS` | `/root/.ssh/authorized_keys`; only its `ssh-ed25519` lines are used (tinysshd takes no other kind) |
| `TPM2_KIRA_SSH_HOSTKEY` | `/etc/ssh/ssh_host_ed25519_key` (the system's OpenSSH key), or a tinysshd key directory (`tinysshd-makekey DIR`; control offers `/etc/tinyssh/sshkeydir`). Sealed to the TPM, see below |

The network is configured for the image alone and does not depend on
`/etc/systemd/network`, which belongs to the running system. control
reads that directory only to suggest DHCP or the static address, plus
the MAC of the interface the file names. Match by MAC: in the image,
interfaces keep their kernel names (`eth0`), not the predictable names of
the running system. The network has its own setting, apart from SSH,
because more will use it later: an outgoing request for the remote salt
(PLAN-REMOTEUNLOCKING.md) reuses the same systemd-networkd setup.

`control.conf` itself never goes into the image. When the image is
built, `tpm2-kira remote initramfs --buildroot DIR` (called by the hook)
turns the settings into files of the image:

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

The hook adds systemd-networkd (enabled, with its user), the driver
module of the matched interface (every network driver when none matches
on the build machine), tinysshd, a shell for tinysshd's command (busybox
when the image has none) and `systemd-tty-ask-password-agent`. If a
setting cannot work (SSH without a network, no host key, no ed25519
key), the build goes on without network and SSH and says why: the image
still boots, with the code screen at the console.

## The host key

The boot image is unencrypted: a host key stored in it lets anyone who
can read `/boot` impersonate the machine. So the image holds the key only
sealed to the TPM, bound to **PCR 0** (firmware) and **PCR 7** (Secure
Boot state and keys):

- The image build reads the key - by default the running system's
  OpenSSH host key, converted to tinysshd's format, so the image answers
  with the same key as the system and the clients need no second
  `known_hosts` entry - and seals its secret to the TPM as a keyed-hash
  object whose only authorization is a PCR policy (no password).
- The values sealed are those of tpm2-kira's measure point: the code
  screen holds the boot ahead of `systemd-pcrosseparator`, which extends
  PCR 0-7 in the running system. They are replayed from the firmware
  event log (measurepoint.go), not read from the registers. The build
  fails (no SSH in the image, the hook says why) when the event log does
  not describe PCR 0 and 7.
- `run` unseals the key once, when the SSH server starts - before the
  separator - through a salted, encrypted session, into
  `/tmp/tpm2-kira-ssh` in the initramfs's memory (not `/run`, which is
  carried into the booted system). It is removed when the server stops,
  and the initramfs is freed at switch-root.
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
  ├── unseals the host key (PCR 0+7) into /tmp/tpm2-kira-ssh
  ├── listens on :PORT ── per connection ── tinysshd -e 'tpm2-kira remote session --socket S'
  │                                                  └── connects to S (/run/tpm2-kira/remote.sock)
  ├── console: "ssh root@<address>", the host key's fingerprint, sessions connected,
  │            "Enter here: continue at this console"
  └── sessions: the code screen; Enter confirms, q leaves
```

- **Confirmed in a session.** The boot is released (READY, the separator
  runs). The password prompt (tpm2-kira's: password+salt, or
  password+remotesalt) opens in that session. The server keeps running
  until switch-root, so a dropped session can log in again for the
  prompt. If tpm2-kira has no key to give (no token on the volume,
  Ctrl-C, a wrong answer), cryptsetup's own prompt follows. The session
  answers it through `systemd-tty-ask-password-agent` as soon as systemd
  has a question pending.
- **Enter at the console.** The boot is released, every session is told
  and closed, the port is closed, and the prompt is the console's. No
  remote confirmation can hold a person at the machine (AGENTS.md: no
  enforced mode).
- **Released by the phone, or the hold's end.** The newest session takes
  the prompt. With no session connected, the server stops and the
  console asks.

The network comes up in parallel with the code screen: networkd is not
ordered after the hold. tinysshd runs in a session of its own, because
`run` gives up the console when the boot is released, and as the
console's session leader that sends SIGHUP to its whole session.

## Known limits

- **PCR 0 and 7 bind the host key to the firmware and the Secure Boot
  keys, not to the image.** Any image signed with the same key that gives
  a root shell before the separator (an initramfs with an emergency
  shell, an older UKI) can unseal it - and with the default, that is the
  system's own OpenSSH host key. Keep such images unsigned, or use a key
  of the image's own (`TPM2_KIRA_SSH_HOSTKEY=/etc/tinyssh/sshkeydir`).
  Without Secure Boot, PCR 7 says little: any OS booted on the machine
  reaches the same values.
- **DHCP may give the image another address than the running system**,
  because the client identifiers differ. The console shows the address;
  a reservation by MAC or a static address makes it predictable.
- **A session dropped while cryptsetup's own prompt is open in it** can
  submit an empty answer through the agent. That costs one of
  cryptsetup's tries.
- Debian / initramfs-tools: not yet.
