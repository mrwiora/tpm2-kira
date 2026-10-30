# The local test machines

`tools/localvm.py` runs the two test machines (Arch, Debian) on this host,
with qemu directly: no libvirt and no root. `tools/vmtest.py` and
`tools/serialtest.py` run against them. This file describes what the
machines need, how a libvirt export was turned into them once, and what
went wrong along the way.

## What the host needs

- `qemu-system-x86_64`, `qemu-img`, `qemu-io`, with KVM (`/dev/kvm`
  readable by the user)
- `swtpm` and `swtpm_setup` (its local CA is created in `~/.config` on the
  first `init`)
- OVMF at `/usr/share/edk2/x64/OVMF_CODE.4m.fd` and `OVMF_VARS.4m.fd`, the
  build without Secure Boot (Arch: `edk2-ovmf`)
- `e2fsprogs` (`debugfs`, `e2fsck`) and `mtools`, to edit a boot partition
  offline (the first boot only, below)
- Docker, for the vault of `vmtest.py`
- Disk: each machine is a qcow2 overlay on its export, and the overlay
  grows with every snapshot. Plan for about 20 GB beside the exports.

## The layout

```
.local/vms/                     outside git (the workspace's .local/)
  localvm.conf                  from tools/localvm.conf.example: exports, MACs, ports
  vmtest-local.conf             tools/vmtest.py's config for these machines (below)
  <machine>/
    disk.qcow2                  overlay on the export; snapshots are internal ones
    vars.fd                     the OVMF variables: the EFI variables the tests write
    tpm/                        swtpm's state, with EK and platform certificates
    serial.log                  everything the serial console printed (appended)
    serial.sock, qmp.sock       the console's input, qemu's control
    snap-<tag>/                 a snapshot's vars.fd and tpm/
.local/vm-pw                    the user's password, which is also the LUKS passphrase
```

A snapshot covers three things, because the tests change all three: the
disk (`qemu-img snapshot`), the EFI variables (`vars.fd`: the slot records
`KIRAslotN`, the SSH CA's variable) and the TPM (`tpm/`: NV indexes,
persistent keys). If you revert only the disk, the next run starts with a
TPM and EFI variables the disk knows nothing about. The machine must be
stopped for `snapshot`; `revert` kills it first.

The emulated TPMs that libvirt keeps in `/var/lib/libvirt/swtpm/` are not
used here. Each machine gets its own state in `<machine>/tpm/`, so nothing
needs to be deleted there.

Snapshots in use:

| Tag | State |
|---|---|
| `export` | the disk as exported, fresh OVMF variables, a fresh TPM; nothing changed in the guest |
| `fresh` | the serial console enabled (below), no tpm2-kira installed: what every test starts from |

## The machine as qemu sees it

These are the points that matter, and why. The full command line is in
`Machine.start`.

- **q35, KVM, OVMF in pflash.** The code is read-only, and the variables
  are the machine's own copy of `OVMF_VARS.4m.fd`. The exports came with
  Secure Boot off, so the build without Secure Boot fits. With a Secure
  Boot variables template, a UKI that is not enrolled would not boot.
- **TPM:** `tpm-crb` on swtpm through a unix socket. `swtpm_setup
  --create-ek-cert --create-platform-cert` provisions it the way libvirt
  does: the phone and vault steps of `vmtest.py` read the EK certificate.
  swtpm is started with `--terminate` and ends with qemu.
- **The NIC sits behind a `pcie-root-port` on bus 1.** That is where
  libvirt places it, and the guests' network configuration names
  `enp1s0`. A NIC on the root bus becomes `enp0s2`, and the guest then
  has no network.
- **The MAC comes from the export's XML.** DHCP leases and the
  configuration in the guests may depend on it.
- **User networking with host forwards:** `127.0.0.1:<ssh_port>` goes to
  the guest's port 22, and `127.0.0.1:<boot_port>` to port 2222 (tpm2-kira's
  boot SSH server). The guests reach the host at `10.0.2.2`, which makes
  the vault's url `https://10.0.2.2`. Docker publishes the vault on the
  host's port, and that port is reachable through 10.0.2.2.
- **The serial console** is a chardev socket with `logfile=serial.log,
  logappend=on`. `send` writes to the socket; `log`, `expect` and `unlock`
  read the log. Read positions are byte offsets into `serial.log`, so
  never rewrite the file while qemu runs. `sed -i` replaces the file, qemu
  keeps writing to the old inode, and from then on the log shows nothing.
  Truncate it with `: > serial.log`, and only while the machine is
  stopped.
- **QMP** for `system_powerdown` (stop) and `quit` (kill).

## From a libvirt export to the snapshot `fresh`

The export was a qcow2 and a libvirt XML per machine (no OVMF variables,
no swtpm state). Secure Boot was off, and the root was on LUKS. The guests
printed nothing on the serial port, so the first boot needed each one's
boot loader to be told about it.

1. **Config.** Copy `tools/localvm.conf.example` to
   `.local/vms/localvm.conf`. Set `export` to the qcow2, `mac` to the
   XML's `<mac address>`, and choose ports (in use: arch 10022/12222,
   debian 20022/22222). Set `password_file` to `.local/vm-pw`.
2. **Files and the snapshot `export`:**
   ```
   tools/localvm.py init arch
   tools/localvm.py snapshot arch export
   ```
3. **Arch (systemd-boot, UKI).** The UKI carries its command line
   (`/etc/kernel/cmdline`). systemd-boot's menu works on the serial console
   through the EFI console, so the first boot can be edited there:
   ```
   tools/localvm.py start arch --no-unlock
   # press a key repeatedly until the menu shows ("Reboot Into Firmware")
   tools/localvm.py send arch ' '
   tools/localvm.py send arch 'e'
   tools/localvm.py send arch 'console=tty1 console=ttyS0,115200 '
   tools/localvm.py send arch '\r'
   tools/localvm.py start arch          # waits for the passphrase prompt, types it, waits for ssh
   ```
   The editor's cursor is at the start of the line, so the text is
   **inserted in front of** the existing options and must end with a
   space. Without the space it merges with the first option
   (`rd.luks.name=...`), and the disk is not found. Then make the change
   permanent in the guest and rebuild the UKI:
   ```
   sed -i 's/$/ console=tty1 console=ttyS0,115200/' /etc/kernel/cmdline
   mkinitcpio -P
   ```
   `console=ttyS0` comes last because the last console is the one systemd's
   password agent and tpm2-kira's boot screen use.
4. **Debian (GRUB, separate /boot).** GRUB draws its menu graphically
   only. Nothing appears on the serial port, so you cannot edit it there.
   The first boot's `grub.cfg` was therefore edited offline, on the
   unencrypted `/boot` partition inside the overlay:
   ```
   # the partition's start and length in sectors: from the partition table
   # (e.g. fdisk -l on the first MBs, taken out with qemu-img dd)
   qemu-img dd -f qcow2 -O raw if=disk.qcow2 of=boot.raw bs=512 skip=<start> count=<start+length>
   ```
   `qemu-img dd`'s `count` counts from the start of the disk, not from
   `skip`, so it is the end sector. Use a scratch directory, not the
   repository, for `boot.raw`.
   ```
   debugfs -R 'cat /grub/grub.cfg' boot.raw > grub.cfg
   sed 's#^\(\s*linux\s.* ro \)\(.*\)$#\1\2 console=tty0 console=ttyS0,115200#' grub.cfg > grub.cfg.new
   debugfs -w -R 'rm /grub/grub.cfg' boot.raw
   debugfs -w -f - boot.raw <<EOF
   write grub.cfg.new /grub/grub.cfg
   sif /grub/grub.cfg uid 0
   sif /grub/grub.cfg gid 0
   sif /grub/grub.cfg mode 0100444
   EOF
   e2fsck -fn boot.raw
   qemu-io -f qcow2 -c "write -s boot.raw <start*512> <length*512>" disk.qcow2
   tools/localvm.py start debian
   ```
   Do this with the machine stopped. Then, in the guest, make it
   permanent:
   ```
   sed -i 's/^GRUB_CMDLINE_LINUX=""$/GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200"/' /etc/default/grub
   update-grub
   ```
   The initrd's prompt is then cryptsetup's askpass ("Please unlock disk
   ..."). `PASSPHRASE_PROMPT` matches both distributions' prompts.
5. **Commands in the guest** go through the guest's own sshd. Use
   `tools/localvm.py ssh <m> 'cmd'`, which answers the password prompt in a
   pty. Use the serial console only when there is no network yet. Avoid
   typing through `send` where possible: shell quoting through the console
   breaks easily (a `sed` with nested quotes did not survive it on
   Debian), and the console echoes whatever is typed, so typed secrets end
   up in `serial.log`.
6. **Clean up and take the snapshot.** In the guest, run `history -c;
   history -w`. Check `serial.log` for anything secret: a password typed
   at a shell prompt, or `sudo`'s prompt answered at the console. Redact it
   only with the machine stopped (see "The serial console" above). Then
   run:
   ```
   tools/localvm.py stop arch
   tools/localvm.py snapshot arch fresh
   ```
7. **Check:** `tools/localvm.py reset arch` should end in "ssh answers".

## Running the tests

Run `reset` before every run: `vmtest.py` calls it as the `reset` command
of its config, and `serialtest.py` calls it before every case. It reverts
to `fresh`, cold-boots the machine, types the passphrase at the serial
console, and waits for an SSH banner.

```
# .local/vms/vmtest-local.conf (outside git):
#   [arch]   host = 127.0.0.1, ssh_port = 10022, boot_port = 12222, user = ...,
#            reset = tools/localvm.py reset arch
#   [debian] the same with 20022 / 22222
#   [vault]  src = ../tpm2-kira-vault, url = https://10.0.2.2, port = 443
tools/vmtest.py --config ../.local/vms/vmtest-local.conf --target both
tools/serialtest.py --target both                 # every case: totp, hashpwd2, tpmsalt, lostrecord
tools/serialtest.py --target arch --case totp
tools/localvm.py status                           # running or not, snapshots
tools/localvm.py stop arch; tools/localvm.py stop debian
```

`vmtest.py` builds HEAD's packages into `build/packages` (unless you
pass `--no-build`). `serialtest.py` takes them from there, or builds them
with `--build`. It writes its reports and each case's console transcript to
`.local/runs/serialtest-<time>/<machine>/<case>/`.

## Points that cost time

- **A machine is "up" when an SSH banner answers**, not when the
  forwarded port accepts a connection. qemu's user network accepts on the
  host side even while the guest is still booting.
- **known_hosts** for the boot SSH server: the `@cert-authority` line must
  name `[127.0.0.1]:<port>`, because the port is not 22. `vmtest.py`
  writes it that way.
- **The passphrase prompt** carries a suffix on Arch ("(press TAB for no
  echo)"), so the pattern matches up to the end of the line, not up to a
  fixed text.
- **The serial console and tpm2-kira's boot screen share one tty.** If
  the volume is not routed to tpm2-kira's key (`luks route`), Debian's
  askpass and the code screen both read the console. `serialtest.py`
  applies the route first.
- **Arch's `HOOKS`:** after installing the package, the initrd needs
  `sd-tpm2-kira` in `/etc/mkinitcpio.conf`'s `HOOKS`, as control would
  put it. `serialtest.py` does this before rebuilding.
- **A fallback to the system's prompt** (a wrong password, or no salt):
  on Debian, tpm2-kira asks again first, and Ctrl-C hands over to
  askpass.
- **Do not build in the workspace with `go.work`** while another session
  changes `../assh`. Build the packages the way the release build does
  (`GOWORK=off`).
