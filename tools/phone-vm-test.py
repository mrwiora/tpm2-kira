#!/usr/bin/env python3
"""The phone and the machine on one simulated Bluetooth: Marify on the Android emulator, its real
BLE code, against a local test VM with the real tpm2-kira package, with nobody at the keyboard.

    tools/phone-vm-test.py --target arch            # one machine
    tools/phone-vm-test.py --target both --fast-kdf # both, one after the other; no final proof

What it does:

  1. builds Marify's debug app and its instrumented tests (marify/android) with the core of
     marify/core.properties, as scripts/build-core.sh builds it
  2. starts an emulator of its own (the AVD marify-vmtest, made when missing) from wiped data, its
     Bluetooth medium (netsimd) with a raw HCI socket (-netsim-args --hci-port); installs the APKs
     with their Bluetooth permissions
  3. runs tools/vmtest.py --only setup,phone --phone SERIAL on each target in turn, with
     LOCALVM_BT set: every start of the VM (tools/localvm.py) connects its ttyS1 to that socket,
     and the scenario phone makes it an adapter (btattach) in the system and in the boot image
  4. stops the emulator and the VM; the VM's snapshots fresh and export are not touched

The scenario phone (tools/vmtest.py, docs/TESTING.md): the enrolment with the SAS compared on
both sides, a phone salt handed over with a keyboard (0x1302), two boots the phone attests in the
initrd, the code on the boot's screen the phone's, the pepper typed through the layout the phone
shows. Logs: the run directory (default .local/runs/phone-vm-<time>), one per target.

Needs: the machines of tools/localvm.py and its vmtest config (.local/vms/vmtest-local.conf),
the Android SDK with an emulator and the system image of marify's scripts/test-emulator.sh, KVM,
and no other netsimd running (an emulator of another test shares its medium and its settings).
"""

import argparse
import datetime
import os
import socket
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE = os.path.dirname(REPO)
LOCAL = os.path.join(WORKSPACE, ".local")
MARIFY = os.path.join(WORKSPACE, "marify", "android")
VM_CONFIG = os.path.join(LOCAL, "vms", "vmtest-local.conf")
SDK = os.environ.get("ANDROID_HOME", os.path.expanduser("~/Android/Sdk"))
ADB = os.path.join(SDK, "platform-tools", "adb")
EMULATOR = os.path.join(SDK, "emulator", "emulator")
AVDMANAGER = os.path.join(SDK, "cmdline-tools", "latest", "bin", "avdmanager")
AVD = "marify-vmtest"
IMAGE = "system-images;android-36;google_apis;x86_64"
# Java for avdmanager and Gradle, as marify's scripts/test-emulator.sh takes it.
os.environ.setdefault("JAVA_HOME", "/usr/lib/jvm/java-25-openjdk")
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")
APP_ID = "io.wiora.marify.debug"
PERMISSIONS = ("android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT")


class Fail(Exception):
    pass


def say(text):
    print(text, flush=True)


def run(cmd, log, cwd=None, env=None, timeout=None):
    with open(log, "a") as f:
        f.write("\n$ " + " ".join(cmd) + "\n")
        f.flush()
        return subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT, timeout=timeout).returncode


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def netsim_hci_port():
    """The HCI port of the running netsimd, from its ini file, or None."""
    ini = f"/run/user/{os.getuid()}/netsim.ini"
    try:
        for line in open(ini):
            if line.startswith("hci.port="):
                return int(line.split("=", 1)[1])
    except (OSError, ValueError):
        pass
    return None


def netsimd_running():
    return subprocess.run(["pgrep", "-x", "netsimd"], capture_output=True).returncode == 0


class Emulator:
    def __init__(self, port, hci_port, run_dir):
        self.port, self.hci_port, self.run_dir = port, hci_port, run_dir
        self.serial = f"emulator-{port}"
        self.proc = None

    def adb(self, *args, timeout=120):
        return subprocess.run([ADB, "-s", self.serial, *args], capture_output=True, text=True, timeout=timeout)

    def start(self):
        if subprocess.run([EMULATOR, "-list-avds"], capture_output=True, text=True).stdout.split().count(AVD) == 0:
            say(f"making the AVD {AVD} ({IMAGE})")
            p = subprocess.run([AVDMANAGER, "create", "avd", "--name", AVD, "--package", IMAGE, "--device", "pixel_6"],
                               input="no\n", capture_output=True, text=True)
            if p.returncode != 0:
                raise Fail(f"the AVD could not be made: {p.stdout[-300:]}{p.stderr[-300:]}")
        say(f"starting the emulator {self.serial}, its Bluetooth's HCI socket on 127.0.0.1:{self.hci_port}")
        log = open(os.path.join(self.run_dir, "emulator.log"), "w")
        self.proc = subprocess.Popen([EMULATOR, "-avd", AVD, "-port", str(self.port), "-wipe-data", "-no-snapshot", "-no-window",
                                      "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect",
                                      "-netsim-args", f"--hci-port {self.hci_port}"], stdout=log, stderr=subprocess.STDOUT)
        subprocess.run([ADB, "-s", self.serial, "wait-for-device"], timeout=300)
        deadline = time.time() + 300
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise Fail("the emulator exited (emulator.log)")
            if self.adb("shell", "getprop", "sys.boot_completed").stdout.strip() == "1" and \
                    "RUNNING_UNLOCKED" in self.adb("shell", "dumpsys", "user").stdout:
                break
            time.sleep(2)
        else:
            raise Fail("the emulator did not finish booting in 300 s")
        deadline = time.time() + 60
        while not port_open(self.hci_port):
            if time.time() > deadline:
                raise Fail(f"netsimd opened no HCI socket on {self.hci_port}")
            time.sleep(1)
        if netsim_hci_port() not in (None, self.hci_port):
            raise Fail(f"netsimd serves HCI on {netsim_hci_port()}, not {self.hci_port}: another emulator's medium")
        if self.adb("shell", "settings", "get", "global", "bluetooth_on").stdout.strip() != "1":
            self.adb("shell", "cmd", "bluetooth_manager", "enable")
        say(f"booted: API {self.adb('shell', 'getprop', 'ro.build.version.sdk').stdout.strip()}")

    def install(self, apks):
        for apk in apks:
            p = self.adb("install", "-r", "-g", apk, timeout=300)
            if "Success" not in p.stdout:
                raise Fail(f"installing {apk}: {p.stdout[-300:]}{p.stderr[-300:]}")
        for perm in PERMISSIONS:
            self.adb("shell", "pm", "grant", APP_ID, perm)

    def stop(self):
        if self.proc is None:
            return
        self.adb("emu", "kill", timeout=30)
        try:
            self.proc.wait(60)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def build_app(run_dir):
    """Marify's debug app and its instrumented tests, with the pinned core."""
    log = os.path.join(run_dir, "build-app.log")
    props = dict(line.strip().split("=", 1) for line in open(os.path.join(WORKSPACE, "marify", "core.properties")) if "=" in line and not line.startswith("#"))
    have = ""
    try:
        have = open(os.path.join(MARIFY, "app", "libs", "CORE_COMMIT")).read().strip()
    except OSError:
        pass
    if have != props.get("kira.commit"):
        say(f"building the core of tpm2-kira {props.get('kira.commit', '?')[:7]} (log: {log})")
        if run([os.path.join(MARIFY, "scripts", "build-core.sh")], log, cwd=MARIFY) != 0:
            raise Fail(f"the core does not build: {log}")
    say(f"building Marify's debug app and its instrumented tests (log: {log})")
    if run(["./gradlew", "--quiet", "assembleDebug", "assembleDebugAndroidTest"], log, cwd=MARIFY) != 0:
        raise Fail(f"Marify does not build: {log}")
    out = os.path.join(MARIFY, "app", "build", "outputs", "apk")
    return [os.path.join(out, "debug", "app-debug.apk"), os.path.join(out, "androidTest", "debug", "app-debug-androidTest.apk")]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", choices=["arch", "debian", "both"], required=True)
    p.add_argument("--fast-kdf", action="store_true", help="WARNING: NO FINAL PROOF. vmtest.py's test build, Argon2id at a test's cost")
    p.add_argument("--run-dir", help="default: .local/runs/phone-vm-<time>")
    p.add_argument("--emulator-port", type=int, default=5592)
    p.add_argument("--hci-port", type=int, default=7302)
    p.add_argument("--keep-emulator", action="store_true", help="leave the emulator running afterwards")
    a = p.parse_args()
    run_dir = os.path.abspath(a.run_dir or os.path.join(LOCAL, "runs", "phone-vm-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    os.makedirs(run_dir, exist_ok=True)
    for tool in (ADB, EMULATOR):
        if not os.access(tool, os.X_OK):
            say(f"phone-vm-test: {tool} not found (ANDROID_HOME)")
            return 2
    if not os.path.exists(VM_CONFIG):
        say(f"phone-vm-test: no {VM_CONFIG}: the machines of tools/localvm.py")
        return 2
    if netsimd_running():
        say("phone-vm-test: a netsimd runs already (another emulator): its medium and its HCI port would be shared; stop it first")
        return 2
    targets = ["arch", "debian"] if a.target == "both" else [a.target]
    emu = Emulator(a.emulator_port, a.hci_port, run_dir)
    results = {}
    try:
        apks = build_app(run_dir)
        emu.start()
        emu.install(apks)
        for t in targets:
            say(f"\n== {t}: tools/vmtest.py --only setup,phone, its ttyS1 on the emulator's Bluetooth")
            env = dict(os.environ, LOCALVM_BT=str(a.hci_port))
            cmd = [sys.executable, os.path.join(REPO, "tools", "vmtest.py"), "--config", VM_CONFIG, "--target", t,
                   "--only", "setup,phone", "--phone", emu.serial, "--run-dir", os.path.join(run_dir, t)]
            if a.fast_kdf:
                cmd.append("--fast-kdf")
            rc = subprocess.run(cmd, cwd=REPO, env=env).returncode
            results[t] = rc
            subprocess.run([sys.executable, os.path.join(REPO, "tools", "localvm.py"), "stop", t], cwd=REPO, capture_output=True)
    except Fail as e:
        say(f"phone-vm-test: {e}")
        results["the run"] = 1
    finally:
        if not a.keep_emulator:
            emu.stop()
    say("")
    for t, rc in results.items():
        say(f"{t}: {'PASS' if rc == 0 else 'FAILED'}")
    ok = bool(results) and all(rc == 0 for rc in results.values()) and len(results) == len(targets)
    if a.fast_kdf:
        say("NOT A FINAL PROOF: a --fast-kdf TEST build, Argon2id at a test's cost, not the production's.")
    say(("ALL PASS" if ok else "FAILED") + f" - logs: {run_dir}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
