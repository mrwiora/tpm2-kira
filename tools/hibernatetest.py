#!/usr/bin/env python3
"""The hibernation test: the SSH CA's window across a resume from
hibernation, on the machines of tools/localvm.py.

    tools/hibernatetest.py --target both          # or arch, or debian
    tools/hibernatetest.py --target arch --no-build

A resume from hibernation starts the TPM afresh, which opens the SSH CA's
window (its window index W, read-locked until the next TPM start), and the
resumed system runs no code screen. The boot image closes it right before
the resume (tpm2-kira-boot close: Arch's drop-in on
systemd-hibernate-resume.service, Debian's local-top script). This test
checks that on both distributions, from the machines' snapshot "fresh":

  setup  tools/vmtest.py's steps up to the first reboot (the package of HEAD,
         slots, the recovery recipe, control with the SSH server and its CA,
         the image), tpm2-tools and aSSH's command (the probe) in the guest,
         a swap file on the encrypted root (Arch) or the encrypted swap
         volume (Debian) as the resume device
  V1     the image carries the close before the resume; a normal boot
         certifies and leaves the window closed
  V6     control: no hibernation risk with encrypted swap; red with a swap
         file on an unencrypted file system (Debian's /boot)
  V2     hibernate, resume through the code screen over SSH: the session is
         the old one (boot_id), the window closed, the CA certifies nothing
         (aSSH's agent as the probe); the TPM's restartCount is reported
  V7     a normal reboot afterwards: certified again
  V3     Arch: hibernate, resume with tpm2-kira's unit masked
         (rd.systemd.mask, the passphrase at systemd's own prompt): the
         close alone closes the window
  V5     suspend to RAM: tested where the guest offers S3 ("deep")
  V4     the close fails (an index of another shape put at W's handle):
         no resume - a fresh boot, the file systems clean - and the next
         boot does not resume the stale image either

V4 breaks the SSH CA (W gone): it runs last. The report and every
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


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, "tools", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vmtest = load("vmtest")
localvm = load("localvm")
Fail = (vmtest.Fail, localvm.Fail)
W = "0x01802915"
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
        self.check("setup: tpm2-tools in the guest (the probe of W and the TPM's clock)", rc == 0, out[-300:])
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

    def state(self, tag):
        """boot_id, W's attributes, the TPM's clock counts, the CA as aSSH
        shows it."""
        rc, out = self.run(
            "echo BOOT=$(cat /proc/sys/kernel/random/boot_id); "
            f"tpm2_nvreadpublic {W} 2>&1 | grep -i attributes -A2; "
            "tpm2_readclock 2>&1; "
            f"{PROBE} ca show --config {CONF} 2>&1 | tail -4", save=f"state-{tag}.log")
        boot = re.search(r"BOOT=(\S+)", out)
        restart = re.search(r"restart_count:\s*(\d+)", out)
        reset = re.search(r"reset_count:\s*(\d+)", out)
        return {"boot": boot.group(1) if boot else None,
                "locked": "readlocked" in out,
                "restart": int(restart.group(1)) if restart else None,
                "reset": int(reset.group(1)) if reset else None,
                "signs": "the CA signs." in out,
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
            self.check("V1: the image's drop-in closes before the resume (ExecStartPre)",
                       "ExecStartPre=/usr/bin/tpm2-kira-boot close" in out, out[-600:])
            self.check("V1: the image resumes with systemd-hibernate-resume", "systemd-hibernate-resume" in out, out[-300:])
        st = self.state("v1")
        self.check("V1: after a normal boot the window is closed (W read-locked)", st["locked"] and not st["signs"], st["out"][-600:])

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

    def after_resume(self, tag, before):
        st = self.state(f"{tag}-after")
        if st["boot"] != before["boot"]:
            rc, out = self.run("journalctl -b -k -o cat --no-pager 2>&1 | grep -E 'PM: (Image|hibernation: (Image|Failed))'", save=f"{tag}-no-resume.log")
            if "Image mismatch" in out:
                # The kernel refused the image itself: the firmware's memory
                # map differed from the hibernated boot's (OVMF's on this VM).
                self.m.rep.issues.append(f"{tag}: not tested - the kernel refused the image: {out.strip().splitlines()[-1] if out.strip() else ''}")
                return st
        self.check(f"{tag}: the session resumed (boot_id {before['boot']} kept)", st["boot"] == before["boot"] and st["boot"], st["out"][:200])
        self.check(f"{tag}: the window is closed after the resume (W read-locked)", st["locked"], st["out"][-600:])
        self.check(f"{tag}: aSSH says the CA signs nothing", not st["signs"], st["out"][-400:])
        out = self.agent_probe(tag)
        self.check(f"{tag}: a certificate asked of the CA after the resume is refused (window closed)",
                   "TEMPORARY" in out and "window is closed" in out and "through slot" not in out, out[-600:])
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

    def failed_close(self):
        m = self.m
        m.log.head("V4: the close fails - no resume")
        rc, out = self.run(f"set -e; tpm2_nvundefine {W} -C o; "
                           f"tpm2_nvdefine {W} -C o -s 8 -a 'ownerread|ownerwrite|authread|authwrite|no_da'; "
                           f"tpm2_nvreadpublic {W}", save="v4-foreign.log")
        if not self.check("V4: an index of another shape at W's handle", rc == 0, out[-400:]):
            return
        before = self.hibernate("V4")
        self.lv.start(unlock=False)
        since = self.lv.mark
        self.console_unlock("V4", since)
        st = self.state("V4-after")
        self.check("V4: no resume - a fresh boot (boot_id new)", st["boot"] and st["boot"] != before["boot"], st["out"][:200])
        text = self.lv.serial_text(since)
        if self.distro == "debian":
            self.check("V4: the image said why it did not resume", "no resume from hibernation this boot" in text, text[-800:])
        else:
            rc, out = self.run("journalctl -b -o cat --no-pager -u systemd-hibernate-resume.service 2>&1", save="v4-resume-unit.log")
            self.check("V4: systemd-hibernate-resume failed at the close", "tpm2-kira-boot close" in out, out[-800:])
        rc, out = self.run("journalctl -b -k -o cat --no-pager 2>&1 | grep -v COMMAND= | grep -iE 'EXT4-fs (error|warning)|BTRFS (error|critical|warning)|I/O error|PM: (Image|hibernation: (resume|Failed))' ; "
                           "journalctl -b -o cat --no-pager 2>&1 | grep -v COMMAND= | grep -iE 'suspend data|swap signature' ; "
                           "swapon --show; true", save="v4-fs.log")
        self.check("V4: the file systems report no error after the fresh boot",
                   not re.search(r"EXT4-fs (error|warning)|BTRFS (error|critical|warning)|I/O error", out), out[-800:])
        self.check("V4: the kernel did not even try the image (the resume was stopped before it)",
                   "Image signature found" not in out, out[-800:])
        # The next boot: the stale image is not resumed either.
        boot = st["boot"]
        self.run("nohup sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &")
        m.wait_port(22, False, 180)
        since = os.path.getsize(self.lv.path("serial.log"))
        self.console_unlock("V4b", since)
        st2 = self.state("V4b")
        self.check("V4: the next boot is a fresh one too (the stale image never resumed)",
                   st2["boot"] and st2["boot"] not in (boot, before["boot"]), st2["out"][:200])

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
        self.check("V5: after suspend to RAM the window is still closed", st["locked"] and st["boot"] == before["boot"], st["out"][-400:])
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
