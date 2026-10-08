# PLAN — the test host: machines in a defined state, their consoles, and the phone in an emulator

> **Status:** planning (2026-10-08). Nothing of this exists yet except
> `tools/acceptance.py`, which runs against two hand-installed VMs and
> needs a person at the console. This plan replaces those VMs with
> machines a script installs, gives every machine a serial console the
> tests read and type on, and adds the phone: Marify in the Android
> emulator, reached over a virtual Bluetooth link.
> **A larger rework**, done in the milestones of §9, each usable on its
> own. The BLE link (§7) rests on netsim's HCI port, which the emulator
> documents (§7.2); the questions left are in §10.

## 1. What the host is for

One physical machine, QEMU/KVM, nothing else on it, that holds every
test machine tpm2-kira is tried on:

- the **Linux machines**, one per distribution and boot path (§3), each
  with its own software TPM, Secure Boot, an encrypted disk, a serial
  console and - when a test asks - a virtual Bluetooth adapter;
- the **phone**: the Android emulator with Marify and the emulator's
  virtual radio (§7);
- the **harness** (`tools/acceptance.py` grown into §8) that installs the
  package of a commit on a machine, boots it, reads the console, types
  what the person typed until now, talks to the phone through `adb`, and
  reports.

Three things this gives that the hand-installed VMs cannot:

1. **A defined state.** Every machine is installed by a script from the
   distribution's own installer, its image frozen, and every run starts
   from that image (§4). A defect found is a defect of tpm2-kira or of
   the installation script, never of a VM somebody once fixed by hand
   (AGENTS.md: a test machine's own defect is reported, not repaired).
2. **The boot itself under test.** With the console on a socket the
   harness sees the code screen, compares the codes with what the TOTP
   secret says (§6), types the password and the salt at tpm2-kira's
   prompt, and knows whether the disk opened - today a person does that
   and answers yes or no.
3. **The phone without a phone.** The attestation, the remote salt and
   the gate at boot run against Marify in the emulator (§7); the real
   phone and the T450s stay the last check before a release, not the
   only one.

## 2. The host

| | |
|---|---|
| Hardware | x86-64 with VT-x/AMD-V, 32 GiB RAM (each machine 2-4 GiB, the emulator 4 GiB, Argon2id at 1 GiB inside a machine), 200 GiB SSD, no need for a GPU or Bluetooth hardware |
| OS | Arch Linux (the same Go, QEMU, swtpm, OVMF and Android SDK as the workstation; Debian works too, with the versions below) |
| Packages | `qemu-full` (or `qemu-system-x86`, `qemu-img`), `edk2-ovmf` (Secure Boot variables), `swtpm`, `socat`, `oath-toolkit` (`oathtool`), `python3`, `go` (or go.dev's into `/usr/local/go`, README), `openssh`, `git`, a JDK 17 for `sdkmanager`; the Android SDK itself is fetched by the script (§7.2), not from the distribution. `archinstall` is not needed on the host, the Arch ISO runs it (§4) |
| Users | `tester`, member of `kvm`, runs everything; no root for the tests themselves. The emulator is QEMU too and needs `/dev/kvm` as well; both share it |
| Network | one libvirt-free `qemu-bridge-helper` bridge or user-mode networking with port forwards; every machine has a fixed address the harness knows (`testhost.conf`, §4) |
| Layout | `/srv/testhost/`: `images/` (base images and their swtpm state), `runs/` (overlays, consoles and logs of one run each), `iso/` (the installers), `android/` (the SDK, the AVD, the APK under test), `conf/testhost.conf` |

No libvirt: QEMU is started by the harness with the exact command line
(§4.3), so the machine is the same on every run and the serial console,
the TPM socket and the HCI port are where the harness expects them.

### 2.1 `tools/testhost/host-setup.sh`

The host, too, is set up by a script, run once as `tester` (the few
root steps are `sudo` lines in it), idempotent, with every version in
`conf/testhost.conf`:

1. **Packages** of the table above (`pacman -S --needed …`), the `kvm`
   group, `/dev/kvm` readable by `tester`; the layout under
   `/srv/testhost/`, owned by `tester`.
2. **The installers**: the Arch ISO and the Debian netinst ISO into
   `iso/`, with their signatures checked (`sq`/`gpg` against the
   distributions' keys), the versions pinned.
3. **OVMF**: a copy of `OVMF_VARS.4m.fd` as the template a machine's
   variables start from (§4.2), `OVMF_CODE.secboot.4m.fd` referenced in
   place.
4. **The Android SDK**, into `android/sdk/`:
   ```
   wget https://dl.google.com/android/repository/commandlinetools-linux-<pinned>_latest.zip
   unzip … -d android/sdk/cmdline-tools && mv … cmdline-tools/latest
   yes | sdkmanager --licenses
   sdkmanager "platform-tools" "emulator" "system-images;android-34;google_apis;x86_64"
   ```
   This is the **netsim install**: `emulator` brings `netsimd`, the
   `netsim` CLI and `netsim-cli` into `android/sdk/emulator/`; there is
   no package of their own. The script checks for them and for the HCI
   option: `android/sdk/emulator/netsimd --help | grep -- --hci-port`
   (the emulator passes `-netsim-args` through to this binary, §7.1).
   `ANDROID_HOME`, `ANDROID_USER_HOME=/srv/testhost/android/home`
   (the AVDs and netsim's artifacts) and the `PATH` go into
   `conf/env.sh`, sourced by every other script.
5. **Standalone rootcanal**, for `transport/ble`'s tests without Android
   (§7.2): a virtual environment, so nothing of it touches the host's
   Python:
   ```
   python -m venv /srv/testhost/rootcanal
   /srv/testhost/rootcanal/bin/pip install rootcanal==<pinned>
   ```
   Started as `/srv/testhost/rootcanal/bin/python -m rootcanal
   --hci_port 6412 --test_port 6411` (ports of its own, next to the
   emulator's 6402, so both can run); the script checks it answers on
   the HCI port (a connection, an `HCI_Reset`, the Command Complete) and
   stops it. The Bazel build from google/rootcanal is the way when the
   wheel does not fit the host; the plan does not need it.
6. **The hci bridge** (§7.1) built static from `tools/hcibridge` with the
   host's Go, into `/srv/testhost/bin/`, from where the initramfs hooks
   of a test machine take it (`TPM2_KIRA_TEST_HCI=1`); `oathtool`
   checked against a known secret and time (§6).
7. **The check at the end**: `qemu-system-x86_64 --version`, `swtpm
   --version`, `go version`, `emulator -version`, `netsimd` present,
   rootcanal answering, `/dev/kvm` writable, the free space - printed as
   one table, and the script exits non-zero when a line is missing. The
   same check is `host-setup.sh --check`, run by the harness before
   every run.

## 3. The machines

| name | distribution | boot | initramfs | disk | tests |
|---|---|---|---|---|---|
| `arch-uki` | Arch Linux | systemd-boot, **UKI**, Secure Boot with sbctl's keys enrolled | mkinitcpio (systemd hooks) | LUKS2 on the root partition | the seal to PCR 11, `sd-tpm2-kira`, the systemd unlock socket |
| `debian-grub` | Debian 13 | **GRUB**, Secure Boot with shim | initramfs-tools | LUKS2 | the seal to PCRs 8 and 9, the `init-premount` script, cryptsetup's askpass |
| `arch-sha1` (later) | Arch Linux | as `arch-uki` with swtpm started with the SHA-1 bank only (`--tpm2 --pcr-banks sha1`) | | | the `--sha1` path of an old TPM (T450s) |

Every machine: 2 vCPU, 4 GiB, q35, OVMF with its own writable variables
file (Secure Boot enabled, keys enrolled by the installation script),
`tpm-tis` on a swtpm socket with the machine's own state directory,
virtio disk, virtio-net with a fixed address, **serial console**
(`console=ttyS0,115200 console=tty0` on the kernel command line, the
same text on both), a **virtio-serial port `hci`** (§7) and the QEMU
monitor on a socket. User `tester` with sudo, the harness's ssh key, the
LUKS passphrase and the user's password in `testhost.conf` - test
secrets, the same on every machine, never anything else.

## 4. Installed by a script, run from a frozen image

### 4.1 The installation

`tools/testhost/install.sh <machine>` builds a machine from the
distribution's installer, unattended, and leaves a base image that is
never booted again:

- **Arch**: the official ISO booted with the serial console; `archinstall`
  with a configuration file (`tools/testhost/arch-uki.json`: LUKS2,
  systemd-boot, UKI, the user, `sbctl` and `mkinitcpio` hooks, `openssh`),
  then a post-install script over the console: `sbctl create-keys`,
  `sbctl enroll-keys -m`, the kernel command line with the console, the
  ssh key, the fixed address. The ISO's `archinstall` is driven over the
  serial console by the same expect-style code the harness uses (§5).
- **Debian**: the netinst ISO with a **preseed** file
  (`tools/testhost/debian-grub.cfg`: guided LUKS, GRUB, the user, ssh;
  `late_command` for the console, the key, the address), passed on the
  kernel command line of a direct-kernel boot (`-kernel`/`-initrd` from
  the ISO, `auto=true priority=critical url=...` served from the host).
- Both end with the machine shut down, `tpm2-kira` **not** installed, no
  slot sealed: the package and the sealing are the test's job, on a fresh
  copy, so every run also tests the install hooks.

The script is the definition of the machine. A change to a machine is a
change to the script and a rebuild of the image; nothing is fixed in
place by hand (the Arch VM's empty `/etc/resolv.conf` of 2026-10-08 is
the example: a defect of the installation, so it goes into the script).

### 4.2 The frozen state

A machine's state is **two things together**: the disk image and the
swtpm state (the EK, the NV indices, the PCR history of a boot are in
`tpm2-00.permall`). The base of a machine is therefore a directory:

```
images/arch-uki/
  disk.qcow2        the installed system, never booted again
  OVMF_VARS.fd      the variables with Secure Boot keys enrolled
  swtpm/            the TPM's state after the installation
  machine.conf      the QEMU command line's variables (address, ports, MAC)
```

A run copies `OVMF_VARS.fd` and `swtpm/` into `runs/<run>/<machine>/`
and gives QEMU a **qcow2 overlay** with `disk.qcow2` as backing file.
Nothing a test does reaches the base; a run that is wanted again is its
directory, kept.

### 4.3 Running a machine

`tools/testhost/run.sh <machine> <run>` starts swtpm, then QEMU with the
one command line (abridged):

```
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m 4G -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
  -drive if=pflash,format=raw,file=runs/R/arch-uki/OVMF_VARS.fd \
  -drive if=virtio,format=qcow2,file=runs/R/arch-uki/disk.qcow2 \
  -chardev socket,id=tpm,path=runs/R/arch-uki/swtpm/sock -tpmdev emulator,id=tpm0,chardev=tpm -device tpm-tis,tpmdev=tpm0 \
  -netdev user,id=n,hostfwd=tcp:127.0.0.1:2201-:22 -device virtio-net-pci,netdev=n,mac=52:54:00:aa:00:01 \
  -chardev socket,id=con,path=runs/R/arch-uki/console.sock,server=on,wait=off -serial chardev:con \
  -chardev socket,id=hci,host=127.0.0.1,port=6402,server=off,reconnect=1 -device virtio-serial -device virtserialport,chardev=hci,name=hci \
  -monitor unix:runs/R/arch-uki/monitor.sock,server=on,wait=off -display none
```

The console, the monitor and the TPM are sockets in the run's directory;
the HCI chardev is connected only when a test wants the phone (§7),
else omitted. The harness talks to the machine over three channels:
**ssh** (what `tools/acceptance.py` does today), the **console** (§5)
and the **monitor** (`system_reset`, `quit`, a screenshot of the VGA
console for the record).

## 5. The console the harness reads and types on

The console socket carries what the person sees today. The harness
(`tools/testhost/console.py`, the expect-style loop that
`tools/acceptance.py` already uses for ssh's password prompt, with the
same rule: wait for a state, never for a time) reads it line by line,
strips the colours, writes the whole of it to `runs/R/<machine>/console.log`,
and acts on the lines that matter:

| line on the console | the harness |
|---|---|
| `[ KIRA ] Time UTC hh:mm:ss` and the slots' codes below it | records the time and the codes, compares them (§6) |
| `[ KIRA ] Password for disk <name>:` | types the password from `testhost.conf` |
| `[ KIRA ] Salt for disk <name>:` | types the salt (the `password+salt` mode) |
| `Slot #N attested by <phone>` | the phone's verdict reached the machine (§7) |
| `Please enter passphrase for disk` (cryptsetup's own prompt) | **failure** when a tpm2-kira mode was set: the derived key did not open the disk; the passphrase is typed so the boot can finish and the journal be read |
| a login prompt | the boot is complete: the ssh checks of today follow |
| `PCR mismatch`, `SKIPPED`, a panic, a rescue shell | failure, with the console as evidence |
| nothing for N seconds while a prompt is expected | failure: the boot hangs (the one timeout, and it names what it waited for) |

The same loop drives the installers (§4.1) and the reboot of today's
`acceptance.py`: "wait for ssh" becomes "see the login prompt".

Plymouth is not installed on the machines; systemd's password agent
asks on the serial console as it does on the VGA one.

## 6. The codes, verified without a person

`seal` prints the TOTP secret as an `otpauth://` URI
(`cmd/totp_utils.go`), for the authenticator. On a test machine the
harness **is** the authenticator: it keeps the URI of every slot from the
seal's output, and at the code screen computes the code for the time
the screen shows (`[ KIRA ] Time UTC`) with `oathtool --totp -b <secret>
--now "<time>"` - the same step as a person with the phone, so a
difference is a defect in the TPM's computation, in the sealing, or in
the clock.

What this checks on every boot, both slots:

- the code of slot 0 is the one the secret gives (the policy was
  satisfied: the boot state is the sealed one);
- the fallback slot shows its code too;
- after an unapproved change (a kernel update not resealed, simulated by
  extending a PCR or editing the command line) slot 0 shows the mismatch
  and the fallback still shows;
- after the hooks' reseal, the next boot shows codes again (the
  generation moved: `status` after boot).

The real authenticator on a phone then only confirms what is confirmed
here, on the real hardware.

## 7. The phone: Marify in the Android emulator, over a virtual radio

### 7.1 The link

QEMU has no Bluetooth emulation (removed in 6.0) and no emulated USB
Bluetooth controller; the Android emulator uses no host Bluetooth
hardware. The link is therefore made of what each side has:

```
Marify ─ the emulator's virtual controller ─ netsimd / rootcanal (the virtual air)
                                                       │ H4 over TCP, the HCI port
                                 host: QEMU -chardev socket,port=6402 ┘
                                 guest: /dev/virtio-ports/hci ─ hci bridge ─ /dev/vhci ─ hci0 ─ the gate
```

- **The emulator's radio.** Emulator 33.1.4 and later with an API 33/34
  Google APIs x86_64 image emulates Bluetooth through **netsim**
  (`netsimd`, built on rootcanal): a virtual controller per emulated
  device and a shared air in which LE advertising, scanning and
  connections work. netsim **ships with the emulator package** - there is
  nothing to install besides the SDK's `emulator` - and the emulator
  starts it (`-packet-streamer-endpoint default`; the emulator talks to
  it over gRPC). rootcanal's **HCI port** is kept: every new TCP
  connection on it spawns a new virtual controller in the air, speaking
  H4 (the Bluetooth UART transport) over TCP; the emulator sets the port
  with `-netsim-args="--hci-port 6402"` (rootcanal's default, 6402, is
  what the plan uses; several emulators need several ports). The same
  channel is what Bumble uses to put an external BLE host into the
  emulator's air, so it is a supported way in, not a side door.
- **The machine's adapter.** The kernel's `hci_vhci`: a process that
  opens `/dev/vhci` is a controller `hci0`, with the process at the HCI
  level. tpm2-kira's gate works on an HCI user channel with legacy LE
  advertising and its own ATT (`transport/ble/host.go`, `att.go`), so a
  vhci adapter is a USB dongle to it.
- **The bridge** (`tools/hcibridge`, ~150 lines of Go, static): copies H4
  packets between `/dev/virtio-ports/hci` and `/dev/vhci`, re-framed -
  `/dev/vhci` takes exactly one packet per `write()`, and a stream
  (`socat`, `cat`) cannot keep the boundaries. In the initramfs with the
  `hci_vhci` module and a unit `Before=tpm2-kira-attest.service`, added
  by the hooks only when `TPM2_KIRA_TEST_HCI=1` is in the build's
  environment - never on a machine that is not a test machine.
- **control.conf** on the machine: `TPM2_KIRA_ATTEST_ADAPTER=0`.

QEMU carries the TCP side (`-chardev socket,host=127.0.0.1,port=6402`),
so the initramfs needs no network.

### 7.2 The Android machine, installed by a script like the others

The phone is a machine of the host like `arch-uki`: the Android
emulator (itself QEMU on KVM), set up by `tools/testhost/android-setup.sh`
once, frozen, and started from that state for every run. The script:

1. **The SDK**, into `android/sdk/`: the command-line tools zip from
   developer.android.com, then `sdkmanager "platform-tools" "emulator"
   "system-images;android-34;google_apis;x86_64"`, licences accepted.
   `netsimd` and the `netsim` CLI arrive with `emulator`
   (`android/sdk/emulator/`); nothing else provides them. The versions
   are pinned in `testhost.conf` (`emulator` 36.x, the image's revision)
   so a rebuild gives the same machine.
2. **The AVD** `marify`: `avdmanager create avd -n marify -k
   "system-images;android-34;google_apis;x86_64" -d pixel_6a`, then
   `config.ini`: `hw.ramSize=4096`, `disk.dataPartition.size=4G`,
   `hw.keyboard=yes`, `hw.gpu.mode=swiftshader_indirect` (no display).
3. **The first boot and its state**: `emulator -avd marify -no-window
   -no-audio -packet-streamer-endpoint default -netsim-args="--hci-port
   6402"`, `adb wait-for-device` and the boot completed
   (`sys.boot_completed`), then over `adb`: Bluetooth on
   (`svc bluetooth enable`), a device credential (`locksettings set-pin`,
   the one Marify asks for at every signature), the animations off,
   Marify's **debug APK** installed with its permissions granted
   (`pm grant … BLUETOOTH_SCAN/CONNECT`, location for the scan), the
   instrumentation APK with it. Then a **snapshot** (`adb emu avd
   snapshot save base`) - the emulator's own frozen state, as the
   qcow2 overlay is for the Linux machines: a run starts with
   `-snapshot base -no-snapshot-save` and leaves nothing behind.
4. **The APK under test** is the one built for the commit
   (`android/scripts/build-core.sh` and Gradle on the host, or the APK the
   workstation built); a run installs it over the snapshot's one first.

The harness drives the app with its instrumented tests
(`android/app/src/androidTest` holds a session test against a machine
already: `SwtpmMachineSessionTest` for the demo machine; a
`RealMachineSessionTest` connects to the advertised machine, binds,
checks a boot, keeps the remote salt, returns it) and, where a test needs
the screens, UI Automator through `adb`. `netsim` (the CLI) lists the
devices in the air - the phone, and the Linux machine once its bridge
connected - and `--pcap` in the netsim arguments records every packet of
a run next to the console log.

**Standalone rootcanal** (`pip install rootcanal`, or Bazel from
google/rootcanal) is the same controller without Android: two machines,
or a machine and a Go test, on one rootcanal give tpm2-kira's own BLE
transport a controller-level integration test in CI, without the
emulator. The emulator is for Marify; rootcanal alone is for
`transport/ble`.

Two consequences of the emulator for tpm2-kira's checks:

- the emulator's keystore is software: the phone's key attestation does
  not chain to Google's roots, so the machine enrols with
  `attest enrol --verify-phone off` on the test host (the `require`
  policy is a test of its own: it must refuse this phone);
- swtpm's EK has no vendor certificate: `--verify-tpm off`, and the
  phone's "unverified TPM" card is what the test expects.

### 7.3 What the BLE tests cover

| test | machine | phone |
|---|---|---|
| enrol | `attest enrol` over the console/ssh | scans, sees the machine, binds (the six digits compared by the harness: both sides print them) |
| gate at boot | the code screen advertises; the harness waits for `Slot #0 attested by` | the app is asked, checks, the code equals the slot's second code |
| changed state | a resealed kernel update | the orange card with the green check; approve |
| remote salt | `remote-salt enrol`, mode `password+remotesalt` | keeps the salt; the next boot: `attest and return the salt`, the disk opens with password + released salt, `release_ack` |
| rejection | | the red cross; the machine shows the rejection and falls back to the passphrase |
| stop while connecting | | the machine is told, the console says so |

Each is one `androidTest` method on the phone side and one harness
scenario on the machine side, synchronised through `adb` (the harness
starts the instrumentation and reads its result).

## 8. The harness: `tools/acceptance.py` grown

Today's script keeps its shape (build on the target, install, checks,
reboot, checks, report) and gains:

- a `--machine <name>` that takes the machine from `testhost.conf`:
  start the run (§4.2, §4.3), ssh and console from there; `--host` with
  credentials stays for a real machine (the T450s);
- the console channel (§5) in place of "wait for ssh" and in place of
  every question to the person: the person's answers become checks, the
  questions remain only for `--host` machines;
- the codes compared (§6);
- `--phone` for the BLE scenarios (§7), which start the emulator and
  the bridge chardev;
- scenarios as named sets of steps (`seal`, `luks-salt`, `luks-remote`,
  `kernel-update`, `ble-enrol`, ...), each a function, run in order,
  each writing its own log; `--scenario` picks;
- a run directory under `runs/` holding everything: console, journal,
  the packages built, the report;
- the machines run in parallel where they do not share the emulator.

The rule stays: wait for states, never for times; nothing twice.

## 9. Milestones

1. **The host and the installed machines** (§2.1, §4): `host-setup.sh`
   (the SDK with netsim and the standalone rootcanal included),
   `install.sh` for `arch-uki` and `debian-grub`, `run.sh`; the two base
   images; today's `acceptance.py` runs against them unchanged through
   the port forwards. *Result: a defined state and a rebuild in minutes.*
2. **The console** (§5, §6): `console.py`, the reboot through the console,
   the password and the salt typed, the codes computed and compared; the
   questions to the person gone for `--machine` runs. *Result: the boot
   path tested without a person.*
3. **Scenarios** (§8): `kernel-update` (the hooks' reseal), `luks-salt`,
   `pcr-mismatch`, the YubiKey PIN from control.conf with the token
   emulator is a unit test and stays one.
4. **The phone** (§7): `android-setup.sh` and the frozen AVD, the bridge
   and the hook knob, the first connection seen in `netsim`'s device
   list (§10.1), `RealMachineSessionTest`, the six BLE scenarios.
   *Result: the whole protocol under test on every commit.*
5. **`arch-sha1`** and whatever machine the next platform observation
   needs (`docs/PLATFORM-OBSERVATIONS.md`).

Milestones 1-3 do not depend on 4; 4 is the one with a first contact to make.

## 10. Open questions

1. **netsim's HCI port, in practice.** The emulator documents
   `--hci-port` and rootcanal's H4-over-TCP channel; what is left to see
   on the host is the first connection from the bridge: the new
   controller appearing in `netsim` 's device list, and Marify's scan
   finding the machine's advertisement. Two things known to bite: a
   controller attached while Android's Bluetooth is up can be refused
   (Bumble's note - Bluetooth off, attach, on, in the setup), and the
   emulator must be started with the port before the machine's QEMU
   connects (`reconnect=1` on the chardev covers the order).
2. **Secure Boot on Debian under OVMF**: shim with Microsoft's keys from
   `OVMF_VARS.secboot` (the firmware's enrolled defaults) or the
   machine's own keys like Arch; the former is what a Debian user has.
3. **The time**: the codes depend on the machine's clock; the machines
   take the host's through kvm-clock, and the harness computes with the
   time the screen prints, so drift is not a failure - but a wrong clock
   on a real machine would be, and `status` could say it.
4. **One emulator, several machines**: netsim is one air; two machines
   advertising at once are two machines in the app's list, which the
   tests can use or must avoid. Start with one machine at a time.
