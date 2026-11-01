#!/usr/bin/env python3
"""The hibernation test: the SSH CA's close (PCR 15) across a resume from
hibernation, on the machines of tools/localvm.py.

    tools/hibernatetest.py --target both          # or arch, or debian
    tools/hibernatetest.py --target arch --no-build

A resume from hibernation starts the TPM afresh, which sets PCR 15 back to
zero and so opens the SSH CA and every slot (their policies read PCR 15),
and the resumed system runs no code screen. The boot image closes it right before
the resume (tpm2-kira-boot close: Arch's drop-in on
systemd-hibernate-resume.service, Debian's local-top script). This test
checks that on both distributions, from the machines' snapshot "fresh":

  setup  tools/vmtest.py's steps up to the first reboot (the package of HEAD,
         slots, the recovery recipe, control with the SSH server and its CA,
         the image), tpm2-tools and aSSH's command (the probe) in the guest,
         a swap file on the encrypted root (Arch) or the encrypted swap
         volume (Debian) as the resume device
  V1     the image carries the close before the resume; a normal boot
         certifies and leaves the CA closed (PCR 15 not zero)
  V6     control: no hibernation risk with encrypted swap; red with a swap
         file on an unencrypted file system (Debian's /boot)
  V2     hibernate, resume through the code screen over SSH: the session is
         the old one (boot_id), the CA closed, the CA certifies nothing
         (aSSH's agent as the probe); the TPM's restartCount is reported
  V7     a normal reboot afterwards: certified again
  V3     Arch: hibernate, resume with tpm2-kira's unit masked
         (rd.systemd.mask, the passphrase at systemd's own prompt): the
         close alone closes the CA
  V5     suspend to RAM: tested where the guest offers S3 ("deep")
  V4     a boot without the TPM's answer, from one hibernated state (the steps
         of docs/SSH.md, "The close"): step 5, no TPM at all (localvm's
         tpm=False: no device, no TPM2 table, nothing measured): no reboot, the
         passphrase's recipe, the resume may go on. On Arch step 6, the TPM2
         table there and the kernel's driver kept from starting: one hard reboot,
         then the recipe and the late closer, no resume. Then the resume with
         the TPM back.
  V9     Debian's step 6, in a boot of its own: GRUB's command line is part of
         what is hibernated. Then a close that holds clears the count.
  V8     the way out of a close that keeps rebooting (step 7, which no VM can
         make: a TPM that answers and refuses): its mechanics, without a TPM:
         Arch, rd.systemd.mask=tpm2-kira-close.service with Secure Boot off;
         Debian, GRUB's break=bottom and the plan's TPM part removed.

V4, V9 and V8 run last. The report and every
transcript land in the run's directory (.local/runs/hibernatetest-<time>/).
"""

import argparse
import configparser
import datetime
import importlib.util
import os
import re
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL = os.path.join(os.path.dirname(REPO), ".local")


# A boot's first word on the serial console: the kernel's.
MEMMAP = "dmesg | sed -n 's/^\\[[^]]*\\] //; /BIOS-e820\\|reserve setup_data\\|Hibernate inconsistent/p'"
RESTART = re.compile(r"Linux version \d")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, "tools", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vmtest = load("vmtest")
localvm = load("localvm")
Fail = (vmtest.Fail, localvm.Fail)
CONF = "/etc/tpm2-kira/assh.conf"
PROBE = "/root/assh"


class Hib:
    def __init__(self, lv, m, probe):
        self.lv, self.m, self.probe = lv, m, probe
        self.distro = m.distro

    def run(self, cmd, save=None):
        return self.m.run(cmd, save=save)

    def check(self, name, ok, detail=""):
        return self.m.check(name, ok, detail)

    # ── the guest ────────────────────────────────────────────────────────

    def setup(self, package, reset):
        m = self.m
        m.reset(reset)
        m.preflight()
        m.install(package)
        m.seal()
        m.enrol()
        m.control()
        m.image()
        m.cycle(1)
        m.log.head("hibernation: tools and swap")
        install = ("pacman -S --noconfirm --needed tpm2-tools btrfs-progs" if self.distro == "arch" else
                   "DEBIAN_FRONTEND=noninteractive apt-get install -y tpm2-tools")
        rc, out = self.run(install + " 2>&1", save="tpm2-tools.log")
        self.check("setup: tpm2-tools in the guest (the probe of PCR 15 and the TPM's clock)", rc == 0, out[-300:])
        m.t.copy_to(self.probe, "/tmp/assh")
        rc, out = self.run(f"install -m 0755 /tmp/assh {PROBE} && {PROBE} help >/dev/null 2>&1; echo rc=$?")
        self.check("setup: aSSH's command in the guest (the probe of the CA)", "rc=0" in out, out[-200:])
        if self.distro == "arch":
            # A swap file on the encrypted root; systemd records it in
            # HibernateLocation, which its initrd resumes from.
            rc, out = self.run("set -e; fs=$(findmnt -no FSTYPE /); "
                               "if [ \"$fs\" = btrfs ]; then btrfs filesystem mkswapfile --size 6g /swapfile; "
                               "else fallocate -l 6G /swapfile; chmod 600 /swapfile; mkswap /swapfile; fi; "
                               "swapon /swapfile; cat /proc/swaps", save="swap.log")
        else:
            # The encrypted swap volume, as the resume device of the image.
            rc, out = self.run("set -e; dev=$(awk 'NR==2{print $1}' /proc/swaps); "
                               "uuid=$(blkid -s UUID -o value \"$dev\"); "
                               "printf 'RESUME=UUID=%s\\n' \"$uuid\" > /etc/initramfs-tools/conf.d/resume; "
                               "update-initramfs -u 2>&1 | tail -3; cat /etc/initramfs-tools/conf.d/resume /proc/swaps", save="swap.log")
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
        rc, out = self.run(f"timeout 20 {PROBE} agent --config {CONF} --dir /run/assh-probe --uid 0 2>&1; true",
                           save=f"agent-{tag}.log")
        return out

    def image_has_close(self):
        m = self.m
        m.log.head("V1: the close before the resume, in the image")
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

    def control_status(self, tag):
        s = self.m.session("sudo ACCESSIBLE=1 tpm2-kira control", f"control-{tag}")
        try:
            text, _ = s.expect(r"Enter a number between 1 and \d+: ?$", 300)
            return text
        finally:
            s.close()

    def swap_risk(self):
        m = self.m
        m.log.head("V6: hibernation to unencrypted swap in control")
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
        self.run("nohup sh -c 'sleep 2; systemctl hibernate' >/dev/null 2>&1 &")
        deadline = time.time() + 600
        while self.lv.pid() and time.time() < deadline:
            time.sleep(2)
        if self.lv.pid():
            raise vmtest.Fail(f"{tag}: the guest did not hibernate (qemu still runs)")
        self.check(f"{tag}: the guest hibernated (powered off)", True)
        return before

    def resume_over_ssh(self, tag):
        """The resume's boot: the code screen over SSH, unlocked there."""
        m = self.m
        self.lv.start(unlock=False)
        if not self.check(f"{tag}: the boot SSH server answers", m.wait_port(vmtest.SSH_PORT, True, 300)):
            raise vmtest.Fail("no boot SSH server on the resume's boot")
        s = m.boot_session(tag)
        try:
            s.expect(r"Does the code match your authenticator\?.*$", 60)
            self.check(f"{tag}: the host key is certified at the resume's code screen (strict known_hosts)", True)
            s.send("\r")
            s.expect(r"Password for disk \S+: ?$", 120); s.send(vmtest.TEST_PASSWORD + "\r")
            s.expect(r"Salt for disk \S+: ?$", 60); s.send(vmtest.TEST_SALT + "\r")
            # A resume never leaves the initrd: the server goes with it,
            # the connection without a last word.
            time.sleep(5)
        finally:
            s.close()
        if not self.check(f"{tag}: the system is back (ssh)", m.wait_port(22, True, 300)):
            raise vmtest.Fail("the system does not come back")

    def wait_login(self, tag):
        """ssh itself works: a banner is not enough. The resumed sshd keeps
        its penalties (PerSourcePenalties) for the probes of this boot and
        earlier ones and closes the connection until they run out (600 s
        at most); a login does not add to them."""
        deadline = time.time() + 660
        while time.time() < deadline:
            rc, _ = self.run("true")
            if rc == 0:
                return
            time.sleep(5)
        raise vmtest.Fail(f"{tag}: ssh does not let in")

    def after_resume(self, tag, before):
        self.wait_login(tag)
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
            time.sleep(0.5)
        if "Reboot Into Firmware" not in lv.serial_text(since):
            raise vmtest.Fail(f"{tag}: systemd-boot's menu did not show")
        lv.send("e")
        time.sleep(1)
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
            time.sleep(0.5)
        return lv.serial_text(since), False

    def menu_edit(self, since, words):
        """Arch: at systemd-boot's menu (the console's text from since), the
        command line edited: this machine has Secure Boot off."""
        lv = self.lv
        deadline = time.time() + 180
        while time.time() < deadline and "Reboot Into Firmware" not in lv.serial_text(since):
            lv.send(" ")
            time.sleep(0.5)
        if "Reboot Into Firmware" not in lv.serial_text(since):
            raise vmtest.Fail("systemd-boot's menu did not show")
        lv.send("e")
        time.sleep(1)
        lv.send(words + " ")
        lv.send("\r")

    def console_prompts(self, since):
        """tpm2-kira's prompts at the console: the recovery recipe needs no TPM."""
        lv = self.lv
        lv.expect(re.compile(r"Password for disk \S+: ?$", re.M), 600, since)
        lv.send(vmtest.TEST_PASSWORD + "\r")
        lv.expect(re.compile(r"Salt for disk \S+: ?$", re.M), 120, since)
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
        lv.wait_ssh(600)
        text = lv.serial_text(since)
        m.log.save("V4-no-tpm-console.log", text)
        self.check("V4 step 5: no TPM at all: no reboot, no failed close", not RESTART.search(text, text.find("Password for disk")) and "the boot is not closed" not in text, text[-800:])
        rc, out = self.run("cat /proc/sys/kernel/random/boot_id", save="V4-no-tpm-boot.log")
        resumed = out.strip() == before["boot"]
        if not resumed:
            m.rep.issues.append("V4 step 5: the kernel did not resume (a boot of its own): the resume itself is not shown here")
        self.check("V4 step 5: the machine is up", rc == 0, out)

    def failed_close(self):
        """What a boot does for a TPM it does not get. The resume's boot, from
        one hibernated state: step 5 (no TPM at all); on Arch step 6 (a TPM the
        firmware has, silent); then the resume with the TPM back. Debian's step
        6 comes after it, in a boot of its own: its command line is grub.cfg's,
        part of what is hibernated."""
        m, lv = self.m, self.lv
        m.log.head("V4: a boot without the TPM's answer")
        before = self.hibernate("V4")
        lv.snapshot("hibernated-v4")
        try:
            self.no_tpm_at_all(before)
        except Fail as e:
            self.check("V4 step 5: the machine comes up without a TPM", False, str(e).split("\n")[0] + "\n" + lv.serial_text(lv.mark)[-800:])
        lv.revert("hibernated-v4")
        if self.distro == "arch":
            try:
                self.silent_tpm_arch(before)
            except Fail as e:
                self.check("V4 step 6: one reboot, then the passphrase", False, str(e).split("\n")[0] + "\n" + lv.serial_text(lv.mark)[-800:])
            lv.revert("hibernated-v4")
        lv.drop_snapshot("hibernated-v4")
        self.resume_over_ssh("V4-reverted")
        self.after_resume("V4-reverted", before)
        if self.distro == "debian":
            m.log.head("V9: a TPM the firmware has does not answer")
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

    def silent_tpm_arch(self, before):
        m, lv = self.m, self.lv
        words = "initcall_blacklist=crb_acpi_driver_init"
        lv.start(unlock=False)
        since = lv.mark
        self.menu_edit(since, words)
        text, again = self.restarted(since, "rebooting once", 400)
        m.log.save("V4-silent-first-console.log", text)
        self.check("V4 step 6: one hard reboot, for a TPM the firmware measured into", "rebooting once" in text and again, text[-800:])
        self.check("V4 step 6: no shell on the way", "maintenance" not in text and "emergency mode" not in text.lower(), text[-800:])
        # restarted() saw the kernel of the second boot, which was not edited:
        # it has its driver, and closes. The reboot goes on to a boot edited.
        lv.kill()
        lv.start(unlock=False)
        since = lv.mark
        self.menu_edit(since, words)
        self.console_prompts(since)
        lv.wait_ssh(600)
        self.wait_login("V4 step 6")
        text = lv.serial_text(since)
        m.log.save("V4-silent-second-console.log", text)
        self.check("V4 step 6: the second time: no reboot, the passphrase", "the TPM does not answer" in text and not RESTART.search(text, text.find("Password for disk")), text[-800:])
        self.after_silent("V4 step 6", before["boot"])

    def silent_tpm_debian(self):
        m, lv = self.m, self.lv
        words = "initcall_blacklist=crb_acpi_driver_init"
        rc, out = self.run("cp /boot/grub/grub.cfg /boot/grub/grub.cfg.kira; sed -i 's#^\\(\\s*linux\\s.*\\)$#\\1 " + words + "#' /boot/grub/grub.cfg; grep -c " + words + " /boot/grub/grub.cfg", save="silent-grub.log")
        self.check("V9 step 6: the driver kept from starting on GRUB's command line", rc == 0 and out.strip() != "0", out)
        rc, boot = self.run("cat /proc/sys/kernel/random/boot_id")
        self.run("nohup sh -c 'sleep 2; systemctl poweroff' >/dev/null 2>&1 &")
        if not lv.wait_stopped(300):
            raise vmtest.Fail("V9: the guest did not power off")
        lv.start(unlock=False)
        since = lv.mark
        self.console_prompts(since)
        text, again = self.restarted(since, "rebooting once", 400)
        m.log.save("V9-first-console.log", text)
        self.check("V9 step 6: one hard reboot, for a TPM the firmware measured into", again, text[-800:])
        self.check("V9 step 6: no shell on the way", "(initramfs)" not in text and "Rebooting automatically" not in text, text[-800:])
        self.console_prompts(self.console_mark())
        lv.wait_ssh(600)
        self.wait_login("V9")
        self.after_silent("V9 step 6", boot.strip())
        # Back to normal: the count goes with the first close that holds.
        self.run("mv /boot/grub/grub.cfg.kira /boot/grub/grub.cfg")
        m.cycle(9)
        rc, out = self.run("ls /sys/firmware/efi/efivars | grep -c KIRAcloseReboot; cat /run/tpm2-kira/close-state; ls /run/tpm2-kira/close-pending 2>&1", save="V9-after.log")
        self.check("V9: a close that holds clears the count and the state", re.search(r"^0$", out, re.M) is not None and "closed" in out and "No such file" in out, out)

    def way_out(self):
        """A TPM that stays broken: docs/SSH.md's way out, taken as it says.
        The boot without the close comes up with the passphrase's recipe.
        Arch: the stub takes a passed command line (this machine has Secure
        Boot off); Debian: GRUB's break=bottom - written into grub.cfg, as
        the menu's editor is on the graphical console here - and the plan's
        TPM part removed in the shell it gives."""
        m, lv = self.m, self.lv
        m.log.head("V8: the way out of a TPM that stays broken")
        if self.distro == "debian":
            rc, out = self.run("sed -i 's#^\\(\\s*linux\\s.*\\)$#\\1 break=bottom#' /boot/grub/grub.cfg; grep -c 'break=bottom' /boot/grub/grub.cfg", save="wayout-grub.log")
            self.check("V8: Debian - break=bottom on GRUB's command line", rc == 0 and out.strip() != "0", out)
        self.run("nohup sh -c 'sleep 2; systemctl poweroff' >/dev/null 2>&1 &")
        if not lv.wait_stopped(300):
            raise vmtest.Fail("V8: the guest did not power off")
        lv.start(unlock=False, tpm=False)
        since = lv.mark
        if self.distro == "debian":
            lv.expect(re.compile(r"Password for disk \S+: ?$", re.M), 600, since)
            lv.send(vmtest.TEST_PASSWORD + "\r")
            lv.expect(re.compile(r"Salt for disk \S+: ?$", re.M), 120, since)
            lv.send(vmtest.TEST_SALT + "\r")
            lv.expect(re.compile(r"\(initramfs\) ?$", re.M), 300, since)
            lv.send("rm -r /etc/tpm2-kira/plan/tpm\r")
            time.sleep(1)
            lv.send("exit\r")
        else:
            deadline = time.time() + 120
            while time.time() < deadline and "Reboot Into Firmware" not in lv.serial_text(since):
                lv.send(" ")
                time.sleep(0.5)
            if "Reboot Into Firmware" not in lv.serial_text(since):
                raise vmtest.Fail("V8: systemd-boot's menu did not show")
            lv.send("e")
            time.sleep(1)
            lv.send("rd.systemd.mask=tpm2-kira-close.service ")
            lv.send("\r")
            lv.expect(re.compile(r"Password for disk \S+: ?$", re.M), 600, since)
            lv.send(vmtest.TEST_PASSWORD + "\r")
            lv.expect(re.compile(r"Salt for disk \S+: ?$", re.M), 120, since)
            lv.send(vmtest.TEST_SALT + "\r")
        lv.wait_ssh(600)
        self.wait_login("V8")
        text = lv.serial_text(since)
        m.log.save("V8-console.log", text)
        self.check("V8: the machine is up with its passphrase's recipe, without the TPM", not RESTART.search(text, text.find("Password for disk")), text[-800:])
        rc, out = self.run("ls /dev/tpm* 2>&1; true", save="wayout-tpm.log")
        self.check("V8: no TPM in this boot", "/dev/tpm0" not in out, out)

    def mem_sleep(self):
        rc, out = self.run("cat /sys/power/mem_sleep")
        if "deep" not in out:
            self.m.rep.issues.append(f"V5: not tested - the guest offers no suspend to RAM (S3): mem_sleep is '{out.strip()}'")
            return
        before = self.state("V5-before")
        self.run("nohup sh -c 'sleep 2; systemctl suspend' >/dev/null 2>&1 &")
        time.sleep(15)
        self.lv.qmp({"execute": "system_wakeup"})
        self.m.wait_port(22, True, 120)
        st = self.state("V5-after")
        self.check("V5: after suspend to RAM the CA is still closed", st["locked"] and st["boot"] == before["boot"], st["out"][-400:])
        self.m.rep.issues.append(f"V5: restartCount {before['restart']} -> {st['restart']}")

    def all(self, package, reset):
        m = self.m
        try:
            self.setup(package, reset)
            self.image_has_close()
            self.swap_risk()
            m.log.head("V2: hibernate, resume over SSH")
            before = self.hibernate("V2")
            self.resume_over_ssh("V2")
            self.after_resume("V2", before)
            m.log.head("V7: a normal reboot after the resume")
            m.cycle(2)
            if self.distro == "arch":
                m.log.head("V3: resume with tpm2-kira masked: the close alone")
                before = self.hibernate("V3")
                self.resume_masked("V3")
                self.after_resume("V3", before)
                m.cycle(3)
            self.mem_sleep()
            self.failed_close()
            self.way_out()
        except Fail as e:
            m.rep.issues.append("stopped: " + str(e).split("\n")[0])
        except Exception as e:
            m.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        return m.report()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["arch", "debian", "both"], required=True)
    p.add_argument("--packages", default=os.path.join(REPO, "build", "packages"))
    p.add_argument("--no-build", action="store_true", help="take HEAD's packages already in --packages")
    args = p.parse_args()
    vcfg = configparser.ConfigParser()
    vcfg.read(os.path.join(LOCAL, "vms", "vmtest-local.conf"))
    lcfg = configparser.ConfigParser()
    lcfg.read(os.path.join(LOCAL, "vms", "localvm.conf"))
    run_dir = os.path.join(LOCAL, "runs", "hibernatetest-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(run_dir, exist_ok=True)
    names = ["arch", "debian"] if args.target == "both" else [args.target]
    if not args.no_build:
        targets = ["arch" if n == "arch" else "deb" for n in names]
        with open(os.path.join(run_dir, "build-packages.log"), "w") as log:
            if subprocess.run([os.path.join(REPO, "packaging", "build-packages.sh")] + targets, cwd=REPO, stdout=log, stderr=subprocess.STDOUT).returncode != 0:
                print(f"the packages do not build: {run_dir}/build-packages.log", file=sys.stderr)
                return 1
    short, packages = vmtest.head_packages(args.packages)
    # The probe: aSSH's command of the pin, as releases build it.
    probe = os.path.join(run_dir, "assh")
    if subprocess.run(["go", "build", "-o", probe, "./cmd/assh"], cwd=os.path.join(REPO, "assh"),
                      env=dict(os.environ, GOWORK="off", CGO_ENABLED="0")).returncode != 0:
        print("aSSH's command does not build", file=sys.stderr)
        return 1
    defaults = dict(lcfg["defaults"]) if lcfg.has_section("defaults") else {}
    password = open(os.path.expanduser(defaults.get("password_file", os.path.join(LOCAL, "vm-pw")))).read().strip()
    defaults.setdefault("password_file", os.path.join(LOCAL, "vm-pw"))
    hs, results = [], {}
    for name in names:
        if not packages[name]:
            print(f"no {name} package of HEAD ({short})", file=sys.stderr)
            return 2
        lv = localvm.Machine(name, lcfg[name], defaults)
        sec = vcfg[name]
        m = vmtest.Machine(name, name, sec["host"], sec.get("user", "pix"), password, lv.passphrase, run_dir, 0,
                           int(sec["ssh_port"]), int(sec["boot_port"]))
        hs.append((Hib(lv, m, probe), sec.get("reset")))
    print(f"tpm2-kira {short}: hibernation test on {', '.join(names)}, logs: {run_dir}", flush=True)
    threads = [threading.Thread(target=lambda h=h, r=r: results.__setitem__(h.m.name, h.all(packages[h.m.name], r))) for h, r in hs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = True
    for h, _ in hs:
        passed, text = results[h.m.name]
        print(text)
        ok = ok and passed
    print("ALL PASS" if ok else "FAILED", "- logs:", run_dir)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
