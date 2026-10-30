#!/usr/bin/env python3
"""The serial-console test: tpm2-kira's recipes at the console, without its
boot SSH server, on the machines of tools/localvm.py.

    tools/serialtest.py --target both            # or arch, or debian
    tools/serialtest.py --target arch --case hashpwd2

Every case starts from the machines' snapshot "fresh" (localvm.py reset:
the disk unlocked at the serial console), installs the package of HEAD
(build/packages, as tools/vmtest.py builds it; --build builds it), sets
the case up over the guest's sshd, rebuilds the boot image, and reboots;
the boot is then answered at the serial console alone, as a person at the
machine would:

  totp      slot add --totp, no keyslot of tpm2-kira's: the codes of slots
            0 and 1 at the console are the ones computed from the secrets;
            Enter; the passphrase opens the disk; cap locked the codes
  hashpwd2  luks enrol --password typed --salt typed (0x1100), no slot:
            no code screen; the password and the salt typed open the disk
  tpmsalt   slot add without --totp, luks enrol --salt tpm (0x1200): no
            code screen, the TPM opens the salt, the password alone opens
            the disk; cap locked the slot all the same. A second boot: a
            wrong password, then the system's own prompt and the LUKS
            passphrase (the fallback)
  lostrecord  the TPM salt's slot, its record (the EFI variable KIRAslot0)
            removed by hand: status names the slot incomplete and why; at
            boot the TPM opens no salt, the prompt says so, Ctrl-C gives
            the system's prompt and the LUKS passphrase opens the disk;
            slot delete takes what is left

The report and every serial transcript land in the run's directory
(.local/runs/serialtest-<time>/<machine>/<case>/).
"""

import argparse
import base64
import configparser
import json
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
CASES = ["totp", "hashpwd2", "tpmsalt", "lostrecord"]
WRONG = "not-the-password"
# The system's own prompt after tpm2-kira's key opened nothing: systemd's
# agent (Arch) or cryptsetup's askpass (Debian).
SYSTEM_PROMPT = r"(Please enter passphrase for disk \S+|Please unlock disk \S+):[^\n]*$"


class Case:
    def __init__(self, lv, name, user, password, run_dir, package):
        self.lv, self.name, self.package = lv, name, package
        self.m = vmtest.Machine(lv.name, lv.name, "127.0.0.1", user, password, lv.passphrase, run_dir, 0,
                                lv.ssh_port, lv.boot_port)
        self.dir = run_dir

    def check(self, name, ok, detail=""):
        return self.m.check(f"{self.name}: {name}", ok, detail)

    # ── the console ──────────────────────────────────────────────────────

    def reboot(self):
        """Reboots and returns the serial log's mark at that moment."""
        mark = os.path.getsize(self.lv.path("serial.log"))
        self.m.run("systemctl reboot >/dev/null 2>&1 &")
        self.m.wait_port(22, False, 120)
        return mark

    def expect(self, pattern, mark, timeout=300):
        """The serial output after mark up to pattern; the next mark is the
        output's end then (what came after the match stays to be seen)."""
        m = self.lv.expect(re.compile(pattern, re.M), timeout, mark)
        return m, self.lv.serial_text(mark)

    def save_console(self, mark, name):
        with open(os.path.join(self.m.dir, f"console-{name}.log"), "w") as f:
            f.write(self.lv.serial_text(mark))

    def up(self, what):
        return self.check(f"{what}: the system comes up (ssh)", self.m.wait_port(22, True, 420))

    def capped(self, what):
        """cap read-locked slot 0's generation index when the initrd was
        left: slot info says so, whatever the slot's methods."""
        rc, out = self.m.run("tpm2-kira slot info --nvram 0 2>&1", save=f"slot-info-{what}.log")
        return self.check(f"{what}: cap locked slot 0 when the initrd was left (its generation index read-locked)",
                          "read-locked until reboot" in out, out[-400:])

    # ── the setup ────────────────────────────────────────────────────────

    def prepare(self):
        self.lv.revert("fresh")
        self.lv.start(timeout=600)
        self.m.preflight()
        self.m.install(self.package)

    def rebuild(self, want):
        if self.lv.name == "arch":
            # What control's mkinitcpio step writes: sd-tpm2-kira into
            # HOOKS, before sd-encrypt (AdoptHook).
            rc, out = self.m.run("grep -q '^HOOKS=.*sd-tpm2-kira' /etc/mkinitcpio.conf || "
                                 "sed -i '/^HOOKS=/s/sd-encrypt/sd-tpm2-kira sd-encrypt/' /etc/mkinitcpio.conf; grep ^HOOKS= /etc/mkinitcpio.conf")
            self.check("HOOKS carry sd-tpm2-kira before sd-encrypt", "sd-tpm2-kira sd-encrypt" in out, out[-300:])
        out = self.m.rebuild()
        self.check("the image is rebuilt" + (f" ({want})" if want else ""), re.search(want, out) is not None if want else True, out[-800:])

    def route(self):
        """Routes the volume's key through tpm2-kira as a person does after
        luks enrol: the line 'luks route' says it should read, written into
        its file (control's WriteRouteFix, by hand)."""
        rc, out = self.m.run(f"tpm2-kira luks route --json {self.m.luks_dev} 2>/dev/null", save="route.json")
        try:
            findings = json.loads(out[out.index("["):]) if "[" in out else []
        except ValueError:
            findings = []
        fixed = 0
        for f in findings:
            if f.get("routed") or not f.get("kind") or not f.get("should"):
                continue
            rc, data = self.m.run(f"cat {f['file']}")
            lines, should = data.split("\n"), f["should"]
            if f["kind"] == "cmdline":
                lines = [should, ""]
            elif f["kind"] == "entry":
                lines = ["options " + should if l.split()[:1] == ["options"] else l for l in lines]
            else:
                lines = [should if len(l.split()) > 1 and not l.split()[0].startswith("#") and
                         (l.split()[1].lower() == "uuid=" + f["uuid"].lower() or l.split()[1] in (f.get("device"), "/dev/disk/by-uuid/" + f["uuid"]))
                         else l for l in lines]
            text = base64.b64encode("\n".join(lines).encode()).decode()
            rc, _ = self.m.run(f"echo {text} | base64 -d > {f['file']}")
            fixed += rc == 0
        rc, out = self.m.run(f"tpm2-kira luks route {self.m.luks_dev} 2>&1; echo rc=$?", save="route.log")
        return self.check("the volume's key is routed through tpm2-kira (luks route)", "rc=0" in out, out[-500:])

    def enrol(self, args, name, answers, want):
        s = self.m.session(f"sudo tpm2-kira luks enrol {self.m.luks_dev} {args}", name)
        try:
            for rx, text in answers:
                s.expect(rx, 900)
                s.send(text + "\n")
            s.expect(want, 300)
            s.wait_end(120)
            return self.check(f"luks enrol {args}", True)
        except Fail as e:
            return self.check(f"luks enrol {args}", False, str(e))
        finally:
            s.close()

    # ── the cases ────────────────────────────────────────────────────────

    def totp(self):
        rc, out = self.m.run("tpm2-kira setup --local 2>&1", save="setup.log")
        self.check("setup --local", "Setup Complete" in out, out[-400:])
        rc, out = self.m.run("tpm2-kira slot add --totp 2>&1", save="slot-add.log")
        secrets = re.findall(r"^Secret: ([A-Z2-7]+)", out, re.M)
        if not self.check("slot add --totp seals slots 0 and 1, each with its secret", len(secrets) == 2, out[-600:]):
            return
        self.rebuild(r"TOTP codes:\s+in")
        mark = self.reboot()
        try:
            m, text = self.expect(r"#0: (\d{6})[\s\S]*#1: (\d{6})", mark, 300)
        except Fail as e:
            self.check("the code screen at the serial console", False, str(e))
            return
        at = time.time()
        self.check("slot 0's code at the console is the authenticator's", vmtest.code_matches(secrets[0], m.group(1), at), m.group(0)[-200:])
        self.check("slot 1's code at the console is the authenticator's", vmtest.code_matches(secrets[1], m.group(2), at), m.group(0)[-200:])
        self.lv.send("\r")
        try:
            self.expect(r"(Passphrase for disk \S+|" + SYSTEM_PROMPT + r")", mark, 300)
            self.lv.send(self.lv.passphrase + "\r")
            self.check("after Enter, the passphrase is asked at the console", True)
        except Fail as e:
            self.check("after Enter, the passphrase is asked at the console", False, str(e))
        self.save_console(mark, "totp")
        if self.up("totp"):
            self.capped("totp")

    def hashpwd2(self):
        if not self.enrol("--password typed --salt typed", "luks-enrol-recovery",
                          [(r"^Password: ?$", vmtest.TEST_PASSWORD), (r"The same password again: ?$", vmtest.TEST_PASSWORD),
                           (r"Salt \(asked for at boot the same way\): ?$", vmtest.TEST_SALT), (r"to authorise: ?$", self.lv.passphrase)],
                          r"keyslot (\d+) added: tpm2-kira, 0x1100 "):
            return
        if not self.route():
            return
        self.rebuild(None)
        mark = self.reboot()
        try:
            _, text = self.expect(r"Password for disk \S+: ?$", mark, 300)
            self.check("no code screen (no slot)", not re.search(r"#\d+: \d{6}", text), text[-500:])
            self.lv.send(vmtest.TEST_PASSWORD + "\r")
            self.expect(r"Salt for disk \S+: ?$", mark, 120)
            self.lv.send(vmtest.TEST_SALT + "\r")
            self.check("the password and the salt are asked at the console", True)
        except Fail as e:
            self.check("the password and the salt are asked at the console", False, str(e))
        self.save_console(mark, "hashpwd2")
        if self.up("hashpwd2"):
            rc, out = self.m.run("journalctl -b -u tpm2-kira.service 2>/dev/null; cat /run/initramfs/tpm2-kira.log 2>/dev/null", save="boot-hashpwd2.log")
            self.check("the key provider answered the volume (0x1100)", re.search(r"answered|key (was )?made|0x1100", out) is not None, out[-500:])

    def tpmsalt(self):
        rc, out = self.m.run("tpm2-kira setup --local 2>&1", save="setup.log")
        self.check("setup --local", "Setup Complete" in out, out[-400:])
        rc, out = self.m.run("tpm2-kira slot add --nvram 0 2>&1", save="slot-add.log")
        self.check("slot add without --totp: no TOTP key, no secret shown", rc == 0 and "Secret:" not in out and "without a TOTP code" in out, out[-500:])
        if not self.enrol("--salt tpm", "luks-enrol-tpm-salt",
                          [(r"Password \(typed at the machine at every boot\): ?$", vmtest.TPM_SALT_PASSWORD),
                           (r"The same password again: ?$", vmtest.TPM_SALT_PASSWORD), (r"to authorise: ?$", self.lv.passphrase)],
                          r"keyslot (\d+) added: tpm2-kira, 0x1200 "):
            return
        if not self.route():
            return
        rc, out = self.m.run("tpm2-kira status 2>&1", save="status.log")
        self.check("status: slot 0's methods are the TPM salt alone", "methods: TPM salt" in out, out[-600:])
        self.rebuild(r"TPM salt:\s+in")
        mark = self.reboot()
        try:
            _, text = self.expect(r"Password for disk \S+: ?$", mark, 300)
            self.check("no code screen (no TOTP code, no phone)", not re.search(r"#\d+: \d{6}", text), text[-500:])
            self.check("the TPM opened the salt before the prompt", "the salt this TPM opened" in text, text[-500:])
            self.lv.send(vmtest.TPM_SALT_PASSWORD + "\r")
        except Fail as e:
            self.check("the password is asked at the console", False, str(e))
        self.save_console(mark, "tpmsalt")
        if not self.up("tpmsalt"):
            return
        self.capped("tpmsalt")

        # The fallback: a wrong password; tpm2-kira's prompt again (Debian's
        # cryptsetup tries the keyscript again) or the system's own (Arch's
        # systemd-cryptsetup); there Ctrl-C, then the system's prompt.
        mark = self.reboot()
        try:
            self.expect(r"Password for disk \S+: ?$", mark, 300)
            mark2 = os.path.getsize(self.lv.path("serial.log"))
            self.lv.send(WRONG + "\r")
            m, _ = self.expect(r"(Password for disk \S+: ?$|" + SYSTEM_PROMPT + ")", mark2, 300)
            if m.group(0).startswith("Password for disk"):
                self.check("fallback: after a wrong password tpm2-kira asks again", True)
                self.lv.send("\x03")
            self.expect(SYSTEM_PROMPT, mark2, 300)
            self.lv.send(self.lv.passphrase + "\r")
            self.check("fallback: after a wrong password the system's prompt takes the LUKS passphrase", True)
        except Fail as e:
            self.check("fallback: after a wrong password the system's prompt takes the LUKS passphrase", False, str(e))
        self.save_console(mark, "fallback")
        self.up("fallback")

    def lostrecord(self):
        rc, out = self.m.run("tpm2-kira setup --local 2>&1", save="setup.log")
        self.check("setup --local", "Setup Complete" in out, out[-400:])
        rc, out = self.m.run("tpm2-kira slot add --nvram 0 2>&1", save="slot-add.log")
        if not self.enrol("--salt tpm", "luks-enrol-tpm-salt",
                          [(r"Password \(typed at the machine at every boot\): ?$", vmtest.TPM_SALT_PASSWORD),
                           (r"The same password again: ?$", vmtest.TPM_SALT_PASSWORD), (r"to authorise: ?$", self.lv.passphrase)],
                          r"keyslot (\d+) added: tpm2-kira, 0x1200 "):
            return
        if not self.route():
            return
        self.rebuild(r"TPM salt:\s+in")
        var = "/sys/firmware/efi/efivars/KIRAslot0-67f474ef-94a1-4412-88df-d62349d430a9"
        rc, out = self.m.run(f"chattr -i {var}; rm {var} && echo removed")
        self.check("the record removed by hand (the EFI variable KIRAslot0)", "removed" in out, out[-300:])
        rc, out = self.m.run("tpm2-kira status 2>&1", save="status-lost.log")
        self.check("status: slot 0 is incomplete, its record gone", "slot 0 is incomplete" in out and "KIRAslot0) is gone" in out, out[-800:])
        mark = self.reboot()
        try:
            _, text = self.expect(r"Password for disk \S+: ?$", mark, 300)
            self.check("the TPM opened no salt, and the prompt says so", "no salt that this TPM opened" in text, text[-600:])
            self.lv.send("\x03")
            self.expect(SYSTEM_PROMPT, mark, 300)
            self.lv.send(self.lv.passphrase + "\r")
            self.check("Ctrl-C: the system's prompt takes the LUKS passphrase", True)
        except Fail as e:
            self.check("Ctrl-C: the system's prompt takes the LUKS passphrase", False, str(e))
        self.save_console(mark, "lostrecord")
        if not self.up("lostrecord"):
            return
        rc, out = self.m.run("tpm2-kira slot delete --nvram 0 2>&1", save="slot-delete.log")
        rc, out = self.m.run("tpm2-kira status 2>&1", save="status-after-delete.log")
        # slot delete takes what is in the TPM; the LUKS keyslot bound to the
        # slot stays (the header is control's and luks remove's), and is
        # what is left of the slot now.
        note = next((l for l in out.splitlines() if "slot 0 is incomplete" in l), "")
        self.check("slot delete takes the slot's indices; the keyslot bound to it is what is left",
                   re.search(r"slot 0 is incomplete - keyslot \d+ of \S+ left", note) is not None and "luks remove" in note and "generation" not in note and "slot delete" not in note, out[-800:])

    def run(self):
        try:
            self.prepare()
            getattr(self, self.name)()
        except Fail as e:
            self.m.rep.issues.append(f"stopped: {e}"[:1500])
        except Exception as e:
            self.m.rep.issues.append(f"the test failed: {type(e).__name__}: {e}")
        return self.m.report()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["arch", "debian", "both"], required=True)
    p.add_argument("--case", choices=CASES, action="append", help="default: every case")
    p.add_argument("--config", default=os.path.join(LOCAL, "vms", "localvm.conf"))
    p.add_argument("--packages", default=os.path.join(REPO, "build", "packages"))
    p.add_argument("--build", action="store_true", help="build HEAD's packages first")
    a = p.parse_args()
    cfg = configparser.ConfigParser()
    if not cfg.read(a.config):
        print(f"no {a.config}", file=sys.stderr)
        return 2
    defaults = cfg["defaults"]
    password = open(os.path.expanduser(defaults["password_file"])).read().strip()
    names = ["arch", "debian"] if a.target == "both" else [a.target]
    if a.build:
        targets = ["arch" if n == "arch" else "deb" for n in names]
        if subprocess.run([os.path.join(REPO, "packaging", "build-packages.sh")] + targets, cwd=REPO).returncode != 0:
            return 1
    short, packages = vmtest.head_packages(a.packages)
    run_dir = os.path.join(LOCAL, "runs", "serialtest-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    results = {}

    def machine(name):
        lv = localvm.Machine(name, cfg[name], defaults)
        if not packages[name]:
            results[name] = [(False, f"no {name} package of HEAD ({short}) in {a.packages} (--build)")]
            return
        out = []
        for case in a.case or CASES:
            ok, text = Case(lv, case, cfg[name].get("user", "pix"), password, os.path.join(run_dir, name, case), packages[name]).run()
            print(text, flush=True)
            out.append((ok, f"{name} {case}: {'PASS' if ok else 'FAIL'}"))
        results[name] = out

    threads = [threading.Thread(target=machine, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"tpm2-kira {short}, serial-console test, {run_dir}")
    allok = True
    for name in names:
        for ok, line in results.get(name, []):
            print("  " + line)
            allok = allok and ok
    print("RESULT: PASS" if allok else "RESULT: FAIL")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
