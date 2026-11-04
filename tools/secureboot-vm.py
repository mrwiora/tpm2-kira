#!/usr/bin/env python3
"""A test machine with Secure Boot really on: real keys in its firmware, in a snapshot of its own.

    tools/secureboot-vm.py arch     # or debian, or both

From the machine's snapshot fresh, which it never writes, and to the snapshot secureboot, which it
makes again each time. The machine runs the build of OVMF with Secure Boot (secure_boot = yes,
tools/LOCALVM.md) and is in Setup Mode until here. Keys go in as an owner's would, from the guest:

  Arch    sbctl, which the machine has: create-keys, enroll-keys --microsoft, the loader and the
          UKI signed. sbctl's post hook signs a rebuilt UKI, and only what is signed boots.
  Debian  no sbctl here, so go-uefi-slim's internal/vmcheck writes what sbctl writes (its tests
          check that): PK, KEK and db with Microsoft's, nothing signed: shim is Microsoft's, GRUB
          and the kernel Debian's. Its kernel locks itself down (integrity): no hibernation.

Enrolling PK ends Setup Mode for good, so this is for a test machine alone. The machine stops at
the end. tools/vmtest.py runs the same steps in its scenario secure-boot.
"""

import argparse
import configparser
import importlib.util
import os
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAPSHOT = "secureboot"
GO_UEFI_SLIM = os.path.join(os.path.dirname(REPO), "go-uefi-slim")
VAR = "/sys/firmware/efi/efivars/{}-8be4df61-93ca-11d2-aa0d-00e098032b8c"


class Fail(Exception):
    pass


def build_vmcheck(directory):
    """go-uefi-slim's checkout, built static for a guest. Test tooling: it goes into no package."""
    path = os.path.join(directory, "vmcheck")
    env = dict(os.environ, CGO_ENABLED="0", GOWORK="off")
    p = subprocess.run(["go", "build", "-o", path, "./internal/vmcheck"], cwd=GO_UEFI_SLIM, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise Fail("vmcheck does not build:\n" + p.stdout + p.stderr)
    return path


def run(target, cmd):
    rc, out = target.run(cmd, root=True)
    if rc != 0:
        raise Fail(f"{cmd}: exit {rc}\n{out[-600:]}")
    return out


def enrol(target, distro, vmcheck):
    """Keys into the firmware of the running machine, in Setup Mode; what boots, signed."""
    if distro == "arch":
        run(target, "sbctl create-keys && sbctl enroll-keys --microsoft --yes-this-might-brick-my-machine")
        for f in ("/boot/EFI/BOOT/BOOTX64.EFI", "/boot/EFI/systemd/systemd-bootx64.efi", "/boot/EFI/Linux/arch-linux.efi"):
            run(target, f"sbctl sign -s {f}")
    else:
        target.copy_to(vmcheck, "/tmp/vmcheck")
        run(target, "chmod 755 /tmp/vmcheck && /tmp/vmcheck enrol /var/lib/sbctl && rm /tmp/vmcheck")
    rc, out = target.run(f"od -An -tx1 {VAR.format('SetupMode')} | awk '{{print $NF}}'", root=True)
    if out.strip() != "00":
        raise Fail(f"still in Setup Mode after the enrolment: {out.strip()}")


def power_off(target, lv):
    target.run("nohup sh -c 'while kill -0 $1 2>/dev/null; do sleep 0.1; done; systemctl poweroff' _ $$ >/dev/null 2>&1 &", root=True)
    if not lv.wait_stopped(180):
        raise Fail(f"{lv.name}: the guest did not power off")


def make(lv, target, distro, vmcheck):
    """From fresh to the snapshot, the machine stopped."""
    lv.revert("fresh")
    lv.start()
    enrol(target, distro, vmcheck)
    power_off(target, lv)
    lv.snapshot(SNAPSHOT)


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, "tools", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("machine", choices=["arch", "debian", "both"])
    ap.add_argument("--config", help="tools/localvm.py's config")
    args = ap.parse_args()
    localvm, acceptance = load("localvm"), load("acceptance")
    cfg = configparser.ConfigParser()
    path = args.config or localvm.DEFAULT_CONFIG
    if not cfg.read(path):
        print(f"no {path}: copy tools/localvm.conf.example", file=sys.stderr)
        return 2
    defaults = cfg["defaults"] if cfg.has_section("defaults") else {}
    with tempfile.TemporaryDirectory() as scratch:
        vmcheck = build_vmcheck(scratch)
        for name in (["arch", "debian"] if args.machine == "both" else [args.machine]):
            lv = localvm.Machine(name, cfg[name], defaults)
            if not lv.secure_boot:
                print(f"{name}: secure_boot = yes in its section: the firmware without it has no Secure Boot", file=sys.stderr)
                return 2
            start = time.monotonic()
            target = acceptance.Target("127.0.0.1", lv.user, lv.ssh_port, lv.passphrase, None, acceptance.Log(os.path.join(scratch, name)))
            make(lv, target, name, vmcheck)
            print(f"{name}: the snapshot {SNAPSHOT}, in {time.monotonic() - start:.0f} s; stopped")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as e:
        print(f"secureboot-vm: {e}", file=sys.stderr)
        sys.exit(1)
