#!/usr/bin/env python3
"""The hibernate steps of tools/vmtest.py's scenarios: the SSH CA's close (PCR 15) across a resume
from hibernation, on the machines of tools/localvm.py. vmtest.py --only NAME runs them alone.

A resume from hibernation starts the TPM afresh, which sets PCR 15 back to zero and so opens the
SSH CA and every slot (their policies read PCR 15), and the resumed system runs no code screen. The
boot image closes it right before the resume (tpm2-kira-boot close: Arch's drop-in on
systemd-hibernate-resume.service, Debian's local-top script). This checks that on both
distributions:

  prepare    tpm2-tools and aSSH's command (the probe) in the guest, a swap file on the encrypted
             root (Arch) or the encrypted swap volume (Debian) as the resume device: in the setup,
             before control, so that control's image is the one resumed
  hibernate  the proof's: V1 the image carries the close before the resume; a normal boot certifies
             and leaves the CA closed (PCR 15 not zero). V5 suspend to RAM: tested where the guest
             offers S3 ("deep"). On Arch, between them, the resume: one hibernation, of the typed boot, kept
             as a snapshot: every resume starts from it. The guest under a new qemu since that
             boot, so no clock to catch up (tools/LOCALVM.md), and a cold start's memory map at the
             resume as at the boot. V2 the resume through the code screen over SSH: the session is
             the old one (boot_id), the CA closed, the CA certifies nothing (aSSH's agent as the
             probe); the TPM's restartCount is reported. A kernel that refuses the image for its
             memory map (tools/LOCALVM.md) makes it "not tested", at once. V7 the next boot,
             whatever it is for: certified again
  debian-resume  --all, Debian: that hibernation and resume; its kernel refuses the image in most runs
  silent-tpm the proof's: a TPM the firmware has, silent (the steps of docs/SSH.md, "The close",
             step 6): the kernel's driver kept from starting: one hard reboot, then the passphrase
             and the late closer. Arch at the resume's boot, from the hibernated state, the words
             at systemd-boot's menu; Debian in a boot of its own: GRUB's command line is part of
             what is hibernated
  V6         --all: control: no hibernation risk with encrypted swap; red with a swap file on an
             unencrypted file system (Debian's /boot)
  V3         --all, Arch: the resume with tpm2-kira's unit masked (rd.systemd.mask, the passphrase
             at systemd's own prompt): the close alone closes the CA
  no-tpm     --all: V4 step 5, a boot without a TPM from the hibernated state (localvm's tpm=False:
             no device, no TPM2 table, nothing measured): no reboot, the passphrase's recipe, the
             resume may go on
  V4-reverted  --all, Debian: the resume with the TPM back
  V9-long    --all, Debian: after silent-tpm, a close that holds clears the count
  V8         --all: the way out of a close that keeps rebooting (step 7, which no VM can make: a
             TPM that answers and refuses): its mechanics, without a TPM: Arch, the word
             tpm2-kira.noclose with Secure Boot off, from the setup; Debian, GRUB's break=bottom
             and the plan's TPM part removed

Each step that wants a running system gets one when the step before it left none.
"""

import importlib.util
import os
import re
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# A boot's first word on the serial console, the firmware's: the kernel's are
# kept from it by the command line's quiet.
RESTART = re.compile(r"BdsDxe: loading")
# What rules a prompt on the console out, whatever the wait has left.
RULED_OUT = re.compile(r"Freezing execution|Failed to isolate|emergency mode|Kernel panic|\(initramfs\) ?$|^\S+ login: ", re.M)
# The kernel's TPM driver kept from starting. The second word is the test's and not what it tests:
# without a TPM device the running system's units wait 90 s for /dev/tpm0, systemd's own bound.
SILENT_WORDS = "initcall_blacklist=crb_acpi_driver_init systemd.default_device_timeout_sec=15"
MEMMAP = "dmesg | sed -n 's/^\\[[^]]*\\] //; /BIOS-e820\\|reserve setup_data\\|Hibernate inconsistent/p'"


def load(name):
    """One module per process: tools/vmtest.py runs this file's steps in its own run."""
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, "tools", name + ".py"))
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


vmtest = load("vmtest")
localvm = load("localvm")
HIBERNATED = vmtest.HIBERNATED
Fail = (vmtest.Fail, localvm.Fail)
CONF = "/etc/tpm2-kira/assh.conf"
PROBE = "/root/assh"


def build_probe(run_dir):
    """aSSH's command of the pin, as releases build it: the probe of the CA."""
    probe = os.path.join(run_dir, "assh")
    p = subprocess.run(["go", "build", "-o", probe, "./cmd/assh"], cwd=os.path.join(REPO, "assh"),
                       env=dict(os.environ, GOWORK="off", CGO_ENABLED="0"), capture_output=True, text=True)
    if p.returncode != 0:
        raise vmtest.Fail("aSSH's command does not build:\n" + p.stdout + p.stderr)
    return probe


class Hib:
    def __init__(self, lv, m, probe):
        self.lv, self.m, self.probe = lv, m, probe
        self.distro = m.distro
        self.before = None  # the state hibernated, once a hibernation was kept

    def run(self, cmd, save=None):
        return self.m.run(cmd, save=save)

    def check(self, name, ok, detail=""):
        return self.m.check(name, ok, detail)

    # ── the guest ────────────────────────────────────────────────────────

    def prepare(self):
        """What this test adds to the setup: before control, whose image is resumed."""
        m = self.m
        m.head("hibernation: tools and swap")
        # Nothing that wakes a hook: btrfs-progs alone would build the image, which control does.
        install = ("pacman -S --noconfirm --needed tpm2-tools" if self.distro == "arch" else
                   "rm -f /var/lib/man-db/auto-update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tpm2-tools")
        rc, out = self.run(install + " 2>&1", save="tpm2-tools.log")
        self.check("setup: tpm2-tools in the guest (the probe of PCR 15 and the TPM's clock)", rc == 0, out[-300:])
        m.t.copy_to(self.probe, "/tmp/assh")
        rc, out = self.run(f"install -m 0755 /tmp/assh {PROBE} && {PROBE} help >/dev/null 2>&1; echo rc=$?")
        self.check("setup: aSSH's command in the guest (the probe of the CA)", "rc=0" in out, out[-200:])
        if self.distro == "arch":
            # A swap file on the encrypted root; systemd records it in
            # HibernateLocation, which its initrd resumes from.
            rc, out = self.run("set -e; touch /swapfile; chmod 600 /swapfile; "
                               "if [ \"$(findmnt -no FSTYPE /)\" = btrfs ]; then chattr +C /swapfile; fi; "
                               "fallocate -l 6G /swapfile; mkswap /swapfile; "
                               "swapon /swapfile; cat /proc/swaps", save="swap.log")
        else:
            # The encrypted swap volume, as the resume device of the image.
            rc, out = self.run("set -e; dev=$(awk 'NR==2{print $1}' /proc/swaps); "
                               "uuid=$(blkid -s UUID -o value \"$dev\"); "
                               "printf 'RESUME=UUID=%s\\n' \"$uuid\" > /etc/initramfs-tools/conf.d/resume; "
                               "cat /etc/initramfs-tools/conf.d/resume /proc/swaps", save="swap.log")
        self.check("setup: the resume device (an encrypted swap)", rc == 0, out[-400:])
        # This test probes port 22 again and again across a resume, which keeps
        # sshd's state: its penalties would close the connection for minutes.
        rc, out = self.run("echo 'PerSourcePenalties no' > /etc/ssh/sshd_config.d/00-hibernatetest.conf; "
                           "systemctl reload sshd 2>/dev/null || systemctl reload ssh; sshd -T 2>/dev/null | grep -i persourcepenalties", save="sshd-penalties.log")
        self.check("setup: sshd without per-source penalties (this test's probes)", rc == 0, out[-300:])

    def state(self, tag):
        """boot_id, PCR 15, the TPM's clock counts, the CA as aSSH shows
        it."""
        rc, out = self.run(
            "echo BOOT=$(cat /proc/sys/kernel/random/boot_id); "
            "echo PCR15=$(tpm2_pcrread sha256:15 2>&1 | awk '/15 *:/{print $2}'); "
            "tpm2_readclock 2>&1; "
            f"{PROBE} ca show --config {CONF} 2>&1 | tail -4", save=f"state-{tag}.log")
        boot = re.search(r"BOOT=(\S+)", out)
        restart = re.search(r"restart_count:\s*(\d+)", out)
        reset = re.search(r"reset_count:\s*(\d+)", out)
        return {"boot": boot.group(1) if boot else None,
                "locked": bool(re.search(r"PCR15=0x(?!0{64}\b)[0-9A-F]{64}", out)),
                "restart": int(restart.group(1)) if restart else None,
                "reset": int(reset.group(1)) if reset else None,
                "signs": "it signs." in out,
                "out": out}

    def agent_probe(self, tag):
        """aSSH's agent asks the CA for a certificate: the attempt a root
        process would make."""
        # It serves until it is stopped: asked, it has said how the CA answered
        # once it names its socket.
        rc, out = self.run(f"f=$(mktemp); timeout 60 {PROBE} agent --config {CONF} --dir /run/assh-probe --uid 0 >$f 2>&1 & p=$!; "
                           "while kill -0 $p 2>/dev/null && ! grep -q 'assh: agent at' $f; do sleep 0.2; done; "
                           "kill $p 2>/dev/null; wait $p 2>/dev/null; cat $f; rm -f $f; true",
                           save=f"agent-{tag}.log")
        return out

    def image_has_close(self):
        m = self.m
        m.head("V1: the close before the resume, in the image")
        if self.distro == "debian":
            listing = "unmkinitramfs /boot/initrd.img-$(uname -r) x >/dev/null && cd x && { [ -d main ] && cd main; true; }"
            show = ("cat scripts/local-top/tpm2-kira-close; echo ORDER:; cat scripts/local-top/ORDER; "
                    "ls scripts/local-premount/")
        else:
            listing = ("uki=$(sed -n 's/^default_uki=\"\\(.*\\)\"/\\1/p' /etc/mkinitcpio.d/*.preset | head -1); "
                       "objcopy -O binary --only-section=.initrd \"$uki\" initrd && lsinitcpio -x initrd >/dev/null")
            show = ("cat etc/systemd/system/systemd-hibernate-resume.service.d/tpm2-kira-close.conf; "
                    "ls usr/lib/systemd/system/systemd-hibernate-resume.service usr/lib/systemd/system-generators/ | grep -i hibernate")
        rc, out = self.run(f"set -e; d=$(mktemp -d); cd $d; {listing}; {show}; cd /; rm -rf $d", save="image-close.log")
        if self.distro == "debian":
            order = out.split("ORDER:", 1)[-1]
            crypt, close = order.find("cryptroot"), order.find("tpm2-kira-close")
            self.check("V1: the image's local-top script closes before the resume (after cryptroot)",
                       "tpm2-kira-boot close" in out and 0 <= crypt < close, out[-600:])
            self.check("V1: the image resumes in local-premount", "resume" in out.split("ORDER:", 1)[-1], out[-300:])
        else:
            self.check("V1: the image's drop-in closes before the resume (ExecStartPre), after the code screen",
                       "ExecStartPre=/usr/bin/tpm2-kira-boot close" in out and "After=tpm2-kira.service" in out, out[-600:])
            self.check("V1: the image resumes with systemd-hibernate-resume", "systemd-hibernate-resume" in out, out[-300:])
        st = self.state("v1")
        self.check("V1: after a normal boot the CA is closed (PCR 15 extended)", st["locked"] and not st["signs"], st["out"][-600:])

    def running(self):
        """A step wants a running system: the one there, or a boot from the setup."""
        if self.lv.pid() and self.run("true")[0] == 0:
            return
        self.m.head("back to the setup, for a running system")
        self.m.setup_snapshot.restore()
        self.lv.start(unlock=False)
        self.m.typed_boot_unchecked()

    def control_status(self, tag):
        s = self.m.session("sudo ACCESSIBLE=1 tpm2-kira control", f"control-{tag}")
        try:
            text, _ = s.expect(r"Enter a number between 1 and \d+: ?$", 300)
            return text
        finally:
            s.close()

    def swap_risk(self):
        m = self.m
        m.head("V6: hibernation to unencrypted swap in control")
        if self.distro == "arch":
            self.run("swapon /swapfile 2>/dev/null; true")  # not in fstab: on again after a reboot
        text = self.control_status("swap-encrypted")
        self.check("V6: control shows no hibernation risk with the swap encrypted", "Hibernation" not in text,
                   "\n".join(l for l in text.split("\n") if "Hibernation" in l))
        if self.distro != "debian":
            return
        rc, out = self.run("set -e; fallocate -l 64M /boot/plainswap; chmod 600 /boot/plainswap; mkswap /boot/plainswap >/dev/null; "
                           "swapon /boot/plainswap; cat /proc/swaps")
        if not self.check("V6: a swap file on /boot (unencrypted)", rc == 0, out[-300:]):
            return
        try:
            text = self.control_status("swap-plain")
            line = "\n".join(l for l in text.split("\n") if "Hibernation" in l)
            self.check("V6: control shows the hibernation risk of the unencrypted swap", "/boot/plainswap" in line and "risk:" in line, line or text[-800:])
        finally:
            self.run("swapoff /boot/plainswap; rm -f /boot/plainswap")

    # ── hibernation ──────────────────────────────────────────────────────

    def hibernate(self, tag):
        """Hibernates the guest and waits for qemu to end (S4 powers off)."""
        if self.distro == "arch":
            self.run("swapon /swapfile 2>/dev/null; true")  # not in fstab: on again after a reboot
        before = self.state(f"{tag}-before")
        _, self.memmap = self.run(MEMMAP, save=f"{tag}-memmap-before.log")
        self.m.when_returned("systemctl hibernate")
        deadline = time.time() + 600
        while self.lv.pid() and time.time() < deadline:
            time.sleep(0.5)
        if self.lv.pid():
            raise vmtest.Fail(f"{tag}: the guest did not hibernate (qemu still runs)")
        self.m.lap(f"{tag}: writing the image, the power-off")
        self.check(f"{tag}: the guest hibernated (powered off)", True)
        return before

    def resume_over_ssh(self, tag):
        """The resume's boot: the code screen over SSH, unlocked there."""
        m = self.m
        self.lv.start(unlock=False)
        if not self.check(f"{tag}: the boot SSH server answers", m.wait_port(vmtest.SSH_PORT, True, 300)):
            raise vmtest.Fail("no boot SSH server on the resume's boot")
        m.lap(f"{tag}: firmware to the boot SSH server")
        s = m.boot_session(tag)
        try:
            s.expect(r"Does the code match your authenticator\?.*$", 60)
            self.check(f"{tag}: the host key is certified at the resume's code screen (strict known_hosts)", True)
            s.send("\r")
            s.expect(r"Password for disk \S+: ?$", 120); s.send(vmtest.TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(vmtest.TEST_SALT + "\r")
            m.lap(f"{tag}: the prompts")
            # The kernel takes the image once the keyslot is open, and the initrd's
            # SSH server goes with it: where the time between goes is told by this.
            m.wait_port(vmtest.SSH_PORT, False, 300)
            m.lap(f"{tag}: salt typed to the image taken (Argon2id, the keyslot)")
            # A resume never leaves the initrd: the server goes with it, the
            # connection without a last word. The session is held until the
            # system is back, so that what was typed arrives whatever the boot does.
            back = m.wait_port(22, True, 300)
        finally:
            s.close()
        console = self.lv.serial_text(self.lv.mark)
        killed = [l for l in console.split("\n") if "Out of memory" in l]
        self.check(f"{tag}: nothing was killed for memory on the resume's boot (the console)", not killed, "\n".join(killed)[-400:])
        if not self.check(f"{tag}: the system is back (ssh)", back):
            raise vmtest.Fail("the system does not come back")
        m.lap(f"{tag}: the image taken to ssh (the resume)")

    def wait_login(self, tag):
        """ssh itself works: a banner is not enough (setup turned sshd's
        per-source penalties off, which these probes would earn)."""
        self.m.wait_login(tag)

    def after_resume(self, tag, before):
        self.wait_login(tag)
        # What the resumed system did, by its own clock: the kernel's, the journal's.
        self.run("dmesg -T | tail -80; journalctl --no-pager -o short-precise -n 200; systemctl list-jobs --no-pager", save=f"{tag}-resumed-system.log")
        st = self.state(f"{tag}-after")
        if st["boot"] != before["boot"]:
            rc, out = self.run("journalctl -b -k -o cat --no-pager 2>&1 | grep -E 'PM: (Image|hibernation: (Image|Failed))'", save=f"{tag}-no-resume.log")
            if "Image mismatch" in out:
                # The kernel refused the image itself: the memory map it got
                # from the firmware differs from the hibernated boot's.
                _, now = self.run(MEMMAP, save=f"{tag}-memmap-after.log")
                was, is_ = set(self.memmap.splitlines()), set(now.splitlines())
                diff = sorted("- " + l for l in was - is_) + sorted("+ " + l for l in is_ - was)
                self.m.log.save(f"{tag}-memmap.diff", "\n".join(diff) + "\n")
                self.m.rep.issues.append(f"{tag}: not tested - the kernel refused the image: {out.strip().splitlines()[-1] if out.strip() else ''}; the memory map differs in {len(diff)} line(s) ({tag}-memmap.diff)")
                return st
        self.check(f"{tag}: the session resumed (boot_id {before['boot']} kept)", st["boot"] == before["boot"] and st["boot"], st["out"][:200])
        self.check(f"{tag}: the CA is closed after the resume (PCR 15 extended)", st["locked"], st["out"][-600:])
        self.check(f"{tag}: aSSH says the CA signs nothing", not st["signs"], st["out"][-400:])
        out = self.agent_probe(tag)
        self.check(f"{tag}: a certificate asked of the CA after the resume is refused (closed)",
                   "TEMPORARY" in out and "the CA is closed" in out and "through slot" not in out, out[-600:])
        rc, out = self.run("tpm2-kira reveal-plain --nvram 0 2>&1 | tail -2", save=f"{tag}-reveal.log")
        self.check(f"{tag}: slot 0's TOTP key refuses after the resume (closed)", "Closed until the next boot" in out, out.strip())
        self.m.rep.issues.append(f"{tag}: the TPM's restartCount {before['restart']} -> {st['restart']}, "
                                 f"resetCount {before['reset']} -> {st['reset']} (a resume from hibernation is a TPM "
                                 f"{'Restart' if st['restart'] and st['restart'] != before['restart'] else 'Reset'})")
        return st

    def resume_masked(self, tag):
        """Arch: the resume's boot with tpm2-kira's unit masked, edited at
        systemd-boot's menu; the passphrase at systemd's own prompt."""
        lv = self.lv
        lv.start(unlock=False)
        since = lv.mark
        deadline = time.time() + 120
        while time.time() < deadline and "Reboot Into Firmware" not in lv.serial_text(since):
            lv.send(" ")
            time.sleep(0.1)
        if "Reboot Into Firmware" not in lv.serial_text(since):
            raise vmtest.Fail(f"{tag}: systemd-boot's menu did not show")
        self.editor_open()
        lv.send("rd.systemd.mask=tpm2-kira.service rd.systemd.mask=tpm2-kira-unlock.socket ")
        lv.send("\r")
        lv.unlock(600)
        lv.wait_ssh(600)
        text = lv.serial_text(since)
        self.check(f"{tag}: no code screen ran on the resume's boot", "Does the code match" not in text, text[-600:])

    def console_unlock(self, tag, since):
        """The code screen at the console (the SSH server did not start),
        then tpm2-kira's password and salt prompts there."""
        lv = self.lv
        lv.expect(re.compile(r"Does the code match your authenticator\?"), 600, since)
        lv.send("\r")
        lv.expect(re.compile(r"Password for disk \S+: ?$", re.M), 300, since)
        lv.send(vmtest.TEST_PASSWORD + "\r")
        lv.expect(re.compile(r"Salt for disk \S+: ?$", re.M), 120, since)
        lv.send(vmtest.TEST_SALT + "\r")
        lv.wait_ssh(600)

    def restarted(self, since, after, timeout):
        """Waits for the second boot on the console after the text after:
        the machine restarted by itself. The console's text up to it, and
        whether it came."""
        lv, deadline = self.lv, time.time() + timeout
        first = re.compile(re.escape(after))
        while time.time() < deadline:
            text = lv.serial_text(since)
            m = first.search(text)
            if m:
                again = RESTART.search(text, m.end())
                if again:
                    return text[:again.start()], True
            elif RULED_OUT.search(text):
                return text, False
            if not lv.pid():
                return text, False
            time.sleep(0.5)
        return lv.serial_text(since), False

    def editor_open(self):
        """Opens systemd-boot's editor at its menu: it draws itself on the console."""
        lv, mark = self.lv, self.console_mark()
        lv.send("e")
        deadline = time.time() + 10
        while self.console_mark() == mark and time.time() < deadline:
            time.sleep(0.05)

    def menu_edit(self, words, tpm=True):
        """Arch: a start, and at systemd-boot's menu the command line edited: this
        machine has Secure Boot off. The menu comes for a key that is there the
        moment the loader looks: a boot that goes past it is started again. Gives
        where the console's text of that boot starts."""
        lv = self.lv
        for _ in range(4):
            lv.start(unlock=False, tpm=tpm)
            since = lv.mark
            deadline = time.time() + 40
            while time.time() < deadline and "Reboot Into Firmware" not in lv.serial_text(since):
                lv.send(" ")
                time.sleep(0.1)
            if "Reboot Into Firmware" in lv.serial_text(since):
                self.editor_open()
                lv.send(words + " ")
                lv.send("\r")
                return since
            lv.kill()
        raise vmtest.Fail("systemd-boot's menu did not show")

    def console_expect(self, rx, timeout, since, ruled_out=RULED_OUT):
        """Waits for rx on the console, and fails the moment the console rules it
        out: a failure, a shell, a login, this boot's restart."""
        lv, deadline = self.lv, time.time() + timeout
        while time.time() < deadline:
            text = lv.serial_text(since)
            m = rx.search(text)
            if m:
                return m
            bad = ruled_out.search(text) if ruled_out else None
            if bad:
                raise vmtest.Fail(f"waiting for /{rx.pattern}/, the console said {bad.group(0)!r}:\n" + text[-800:])
            first = RESTART.search(text)
            if first and RESTART.search(text, first.end()):
                raise vmtest.Fail(f"waiting for /{rx.pattern}/, the machine restarted:\n" + text[-800:])
            if not lv.pid():
                raise vmtest.Fail(f"waiting for /{rx.pattern}/, the machine stopped:\n" + text[-800:])
            time.sleep(0.5)
        raise vmtest.Fail(f"waited {timeout} s for /{rx.pattern}/ at the console:\n" + lv.serial_text(since)[-800:])

    def console_prompts(self, since):
        """tpm2-kira's prompts at the console: the recovery recipe needs no TPM."""
        lv = self.lv
        self.console_expect(re.compile(r"Password for disk \S+: ?$", re.M), 180, since)
        lv.send(vmtest.TEST_PASSWORD + "\r")
        self.console_expect(re.compile(r"Salt for disk \S+: ?$", re.M), 60, since)
        lv.send(vmtest.TEST_SALT + "\r")

    def console_mark(self):
        return os.path.getsize(self.lv.path("serial.log"))

    def no_tpm_at_all(self, before):
        """Step 5: no TPM device and no sign of one (localvm's tpm=False: QEMU
        gives no TPM2 table without the device, and the stub measures nothing):
        nothing to close, no reboot, and the resume goes on."""
        m, lv = self.m, self.lv
        lv.start(unlock=False, tpm=False)
        since = lv.mark
        self.console_prompts(since)
        lv.wait_ssh(240)
        text = lv.serial_text(since)
        m.log.save("V4-no-tpm-console.log", text)
        self.check("V4 step 5: no TPM at all: no reboot, no failed close", not RESTART.search(text, text.find("Password for disk")) and "the boot is not closed" not in text, text[-800:])
        rc, out = self.run("cat /proc/sys/kernel/random/boot_id", save="V4-no-tpm-boot.log")
        resumed = out.strip() == before["boot"]
        if not resumed:
            m.rep.issues.append("V4 step 5: the kernel did not resume (a boot of its own): the resume itself is not shown here")
        self.check("V4 step 5: the machine is up", rc == 0, out)

    def step_no_tpm(self):
        """Step 5: the resume's boot, from the one hibernated state, without a TPM."""
        m, lv = self.m, self.lv
        before = self.hibernated()
        m.head("V4: a boot without a TPM at all")
        try:
            self.no_tpm_at_all(before)
        except Fail as e:
            self.check("V4 step 5: the machine comes up without a TPM", False, str(e).split("\n")[0] + "\n" + lv.serial_text(lv.mark)[-800:])

    def step_v4_reverted(self):
        """Debian: the resume with the TPM back, the running system what comes after goes on from."""
        before = self.hibernated()
        self.m.head("V4: the resume with the TPM back")
        self.resume_over_ssh("V4-reverted")
        self.after_resume("V4-reverted", before)

    def silent_tpm(self):
        """Step 6: a TPM the firmware has does not answer. On Arch the resume's boot; on Debian a
        boot of its own, its command line is grub.cfg's, part of what is hibernated."""
        if self.distro == "arch":
            before = self.hibernated()
            self.m.head("V4: a silent TPM")
            self.silent_tpm_arch(before)
        else:
            self.running()
            self.m.head("V9: a TPM the firmware has does not answer")
            self.silent_tpm_debian()

    def after_silent(self, tag, before_boot):
        """The running system of a boot that went on without the TPM's answer."""
        rc, out = self.run("cat /proc/sys/kernel/random/boot_id; ls /dev/tpm* 2>&1; cat /run/tpm2-kira/close-state; ls /run/tpm2-kira/close-pending; "
                           "systemctl is-active tpm2-kira-late-close.service; ls /sys/firmware/efi/efivars | grep KIRAcloseReboot; "
                           "tpm2-kira status 2>&1 | grep -i 'did not answer'", save=f"{tag.replace(' ', '-')}-state.log")
        self.check(f"{tag}: a fresh boot, no resume", before_boot not in out, out[:200])
        self.check(f"{tag}: no device for the TPM", "/dev/tpm0" not in out, out)
        self.check(f"{tag}: the close left its state: pending", "pending" in out and "close-pending" in out, out)
        self.check(f"{tag}: the late closer runs", re.search(r"^active$", out, re.M) is not None, out)
        self.check(f"{tag}: the reboot is counted", "KIRAcloseReboot" in out, out)
        self.check(f"{tag}: status says it in red", "did not answer" in out, out)

    def one_wait(self, text, what, first, then, most):
        """The kernel's stamps on what the boot's steps said at the console: then came at most
        most seconds after first, so it did not wait again."""
        stamp = lambda word: next((float(x) for x in re.findall(r"\[\s*([\d.]+)\][^\n]*?" + word, text)), None)
        a, b = stamp(first), stamp(then)
        self.m.log.say(f"{what}: {first} at {a} s, {then} at {b} s")
        self.check(what, a is not None and b is not None and b - a <= most, f"{a}, {b}: " + text[-800:])

    def silent_tpm_arch(self, before):
        m, lv = self.m, self.lv
        words = SILENT_WORDS
        since = self.menu_edit(words)
        text, again = self.restarted(since, "rebooting once", 90)
        m.log.save("V4-silent-first-console.log", text)
        self.check("V4 step 6: one hard reboot, for a TPM the firmware measured into", "rebooting once" in text and again, text[-800:])
        self.check("V4 step 6: no shell on the way", "maintenance" not in text and "emergency mode" not in text.lower(), text[-800:])
        self.check("V4 step 6: the close comes first: no volume's unit and no prompt before its reboot", "Cryptography Setup" not in text[:text.find("rebooting once")] and "Password for disk" not in text, text[-800:])
        self.one_wait(text, "V4 step 6: one wait: run does not wait after machine-id", "the machine-id is not released", "did not appear; no code", 2)
        self.one_wait(text, "V4 step 6: one wait: the close ends the boot's 30 s, from machine-id's first wait", "the machine-id is not released", "rebooting once", 27)
        # The firmware of the second boot: it would not be edited, and have its
        # driver. The second boot is one edited.
        lv.kill()
        since = self.menu_edit(words)
        self.console_prompts(since)
        lv.wait_ssh(240)
        self.wait_login("V4 step 6")
        text = lv.serial_text(since)
        m.log.save("V4-silent-second-console.log", text)
        self.check("V4 step 6: the second time: no reboot, the passphrase", "the TPM does not answer" in text and not RESTART.search(text, text.find("Password for disk")), text[-800:])
        self.one_wait(text, "V4 step 6: the second time the close does not wait", "did not appear; no code", "the TPM does not answer", 3)
        self.after_silent("V4 step 6", before["boot"])
        rc, out = self.run(vmtest.Machine.VOLUME_ORDER, save="V4-silent-volume-order.log")
        m.check_volume_order("V4 step 6, the second time", out)

    def silent_tpm_debian(self):
        m, lv = self.m, self.lv
        words = SILENT_WORDS
        rc, out = self.run("cp /boot/grub/grub.cfg /boot/grub/grub.cfg.kira; sed -i 's#^\\(\\s*linux\\s.*\\)$#\\1 " + words + "#' /boot/grub/grub.cfg; grep -c initcall_blacklist /boot/grub/grub.cfg", save="silent-grub.log")
        self.check("V9 step 6: the driver kept from starting on GRUB's command line", rc == 0 and out.strip() != "0", out)
        rc, boot = self.run("cat /proc/sys/kernel/random/boot_id")
        m.when_returned("systemctl poweroff")
        if not lv.wait_stopped(300):
            raise vmtest.Fail("V9: the guest did not power off")
        lv.start(unlock=False)
        since = lv.mark
        self.console_prompts(since)
        text, again = self.restarted(since, "rebooting once", 150)
        m.log.save("V9-first-console.log", text)
        self.check("V9 step 6: one hard reboot, for a TPM the firmware measured into", again, text[-800:])
        self.check("V9 step 6: no shell on the way", "(initramfs)" not in text and "Rebooting automatically" not in text, text[-800:])
        self.console_prompts(self.console_mark())
        lv.wait_ssh(240)
        self.wait_login("V9")
        self.after_silent("V9 step 6", boot.strip())

    def silent_tpm_long(self):
        """Back to normal: the count goes with the first close that holds."""
        m = self.m
        m.head("V9: a close that holds clears the count")
        self.run("mv /boot/grub/grub.cfg.kira /boot/grub/grub.cfg")
        m.cycle(9)
        rc, out = self.run("ls /sys/firmware/efi/efivars | grep -c KIRAcloseReboot; cat /run/tpm2-kira/close-state; ls /run/tpm2-kira/close-pending 2>&1", save="V9-after.log")
        self.check("V9: a close that holds clears the count and the state", re.search(r"^0$", out, re.M) is not None and "closed" in out and "No such file" in out, out)

    def way_out(self):
        """A TPM that answers and refuses everything: docs/SSH.md's way out, taken
        as it says, here without a TPM. Arch: the word tpm2-kira.noclose, which the
        stub takes with Secure Boot off; Debian: GRUB's break=bottom - written into
        grub.cfg, as the menu's editor is on the graphical console here - and the
        plan's TPM part removed in the shell it gives."""
        m, lv = self.m, self.lv
        m.head("V8: the way out of a TPM that stays broken")
        if self.distro == "debian":
            self.running()
            rc, out = self.run("sed -i 's#^\\(\\s*linux\\s.*\\)$#\\1 break=bottom#' /boot/grub/grub.cfg; grep -c 'break=bottom' /boot/grub/grub.cfg", save="wayout-grub.log")
            self.check("V8: Debian - break=bottom on GRUB's command line", rc == 0 and out.strip() != "0", out)
            m.when_returned("systemctl poweroff")
            if not lv.wait_stopped(300):
                raise vmtest.Fail("V8: the guest did not power off")
            lv.start(unlock=False, tpm=False)
            since = lv.mark
            self.console_prompts(since)
            self.console_expect(re.compile(r"\(initramfs\) ?$", re.M), 120, since, ruled_out=None)
            mark = self.console_mark()
            lv.send("rm -r /etc/tpm2-kira/plan/tpm\r")
            self.console_expect(re.compile(r"\(initramfs\) ?$", re.M), 30, mark, ruled_out=None)
            lv.send("exit\r")
        else:
            # From the setup: no image in the swap, nothing of the steps before.
            lv.kill()
            m.setup_snapshot.restore()
            since = self.menu_edit("tpm2-kira.noclose", tpm=False)
            self.console_prompts(since)
        lv.wait_ssh(240)
        self.wait_login("V8")
        text = lv.serial_text(since)
        m.log.save("V8-console.log", text)
        self.check("V8: the machine is up with its passphrase's recipe, without the TPM", not RESTART.search(text, text.find("Password for disk")), text[-800:])
        if self.distro == "arch":
            rc, out = self.run("journalctl -b --no-pager -o cat | grep 'tpm2-kira.noclose'", save="wayout-skipped.log")
            self.check("V8: Arch - the close's unit was left out by the word", "ConditionKernelCommandLine" in out or "unmet condition" in out, out[-400:])
        rc, out = self.run("ls /dev/tpm* 2>&1; true", save="wayout-tpm.log")
        self.check("V8: no TPM in this boot", "/dev/tpm0" not in out, out)

    def mem_sleep(self):
        self.running()
        self.m.head("V5: suspend to RAM")
        rc, out = self.run("cat /sys/power/mem_sleep")
        if "deep" not in out:
            self.m.rep.issues.append(f"V5: not tested - the guest offers no suspend to RAM (S3): mem_sleep is '{out.strip()}'")
            return
        before = self.state("V5-before")
        self.m.when_returned("systemctl suspend")
        deadline = time.time() + 120
        while time.time() < deadline and self.lv.qmp({"execute": "query-status"}).get("return", {}).get("status") != "suspended":
            time.sleep(0.25)
        if not self.check("V5: the guest is suspended (qemu says so)", self.lv.qmp({"execute": "query-status"}).get("return", {}).get("status") == "suspended"):
            raise vmtest.Fail("V5: the guest did not suspend")
        self.lv.qmp({"execute": "system_wakeup"})
        self.m.wait_port(22, True, 120)
        self.wait_login("V5")
        st = self.state("V5-after")
        self.check("V5: after suspend to RAM the CA is still closed", st["locked"] and st["boot"] == before["boot"], st["out"][-400:])
        self.m.rep.issues.append(f"V5: restartCount {before['restart']} -> {st['restart']}")

    def hibernate_once(self):
        """The one hibernation of a run, of boot 1: the state every resume starts from."""
        self.running()
        self.m.head("hibernate: the state V3, V2 and V4 resume from")
        self.before = self.hibernate("V2")
        self.lv.snapshot(HIBERNATED)

    def hibernated(self):
        """Back to the hibernated state, made when no step made it yet. What it was before."""
        if self.before is None:
            self.hibernate_once()
        self.lv.revert(HIBERNATED)
        return self.before

    def scenario_hibernate(self):
        """V1, on Arch the hibernation and the resume (V2), suspend to RAM (V5), in the order that
        spares waits. Debian's kernel refuses the image in most runs: its resume is under --all."""
        self.image_has_close()
        if self.distro == "arch":
            self.scenario_resume()
        self.mem_sleep()

    def scenario_resume(self):
        self.hibernate_once()
        self.step_v2()

    def step_v2(self):
        """The resume. A kernel that refuses the image makes it "not tested", at once."""
        before = self.hibernated()
        self.m.head("V2: resume over SSH")
        self.resume_over_ssh("V2")
        self.after_resume("V2", before)
        self.m.resumed = True

    def step_v3(self):
        before = self.hibernated()
        self.m.head("V3: resume with tpm2-kira masked: the close alone")
        self.resume_masked("V3")
        self.after_resume("V3", before)
