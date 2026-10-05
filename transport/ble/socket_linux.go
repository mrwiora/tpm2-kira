//go:build linux

package ble

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Kernel ABI constants from include/net/bluetooth/hci.h and hci_sock.h that
// golang.org/x/sys does not export.
const (
	btprotoHCI     = 1
	hciChannelUser = 1
	hciDevUp       = 0x400448c9 // _IOW('H', 201, int)
	hciDevDown     = 0x400448ca // _IOW('H', 202, int)
	hciGetDevInfo  = 0x800448d3 // _IOR('H', 211, int)
	hciFlagUp      = 1 << 0
	rfkillOpChange = 2
)

// adapterUp reports whether the kernel has the adapter up.
func adapterUp(fd, dev int) (bool, error) {
	// struct hci_dev_info: dev_id u16, name[8], bdaddr[6], flags u32, ...
	var info [128]byte
	binary.LittleEndian.PutUint16(info[0:], uint16(dev))
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), hciGetDevInfo, uintptr(unsafe.Pointer(&info[0]))); e != 0 {
		return false, e
	}
	return binary.LittleEndian.Uint32(info[16:])&hciFlagUp != 0, nil
}

// errRetry marks conditions that clear up by themselves while a freshly
// probed adapter finishes initialising.
type errRetry struct{ err error }

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }

// openUserChannelWait retries openUserChannel until the adapter exists and
// the kernel lets go of it, or wait expires.
func openUserChannelWait(dev int, unblock bool, wait time.Duration, logf func(string, ...any)) (hciTransport, func(), error) {
	deadline := time.Now().Add(wait)
	announced := false
	for {
		tr, release, err := openUserChannel(dev, unblock, logf)
		var r errRetry
		if err == nil || !errors.As(err, &r) || !time.Now().Before(deadline) {
			return tr, release, err
		}
		if !announced && logf != nil {
			logf("waiting for hci%d: %v", dev, err)
			announced = true
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// openUserChannel brings the adapter down in the kernel and binds an HCI
// user channel to it, which gives this process exclusive raw access. The
// returned release function brings the adapter back up if it was up before.
func openUserChannel(dev int, unblock bool, logf func(string, ...any)) (hciTransport, func(), error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if _, err := os.Stat(fmt.Sprintf("/sys/class/bluetooth/hci%d", dev)); err != nil {
		return nil, nil, errRetry{fmt.Errorf("ble: no Bluetooth adapter hci%d (kernel module or firmware missing?)", dev)}
	}
	if err := checkRFKill(dev, unblock, logf); err != nil {
		return nil, nil, err
	}

	ctl, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, btprotoHCI)
	if err != nil {
		return nil, nil, fmt.Errorf("ble: cannot open an HCI socket: %w", err)
	}
	wasUp, err := adapterUp(ctl, dev)
	if err != nil {
		unix.Close(ctl)
		return nil, nil, fmt.Errorf("ble: cannot query hci%d: %w", dev, err)
	}
	if wasUp {
		logf("bringing hci%d down for exclusive use", dev)
		if err := unix.IoctlSetInt(ctl, hciDevDown, dev); err != nil {
			unix.Close(ctl)
			if errors.Is(err, unix.EBUSY) {
				return nil, nil, errRetry{fmt.Errorf("ble: hci%d is still initialising: %w", dev, err)}
			}
			return nil, nil, fmt.Errorf("ble: cannot take hci%d down (needs root / CAP_NET_ADMIN): %w", dev, err)
		}
	}
	release := func() {
		if wasUp {
			if err := unix.IoctlSetInt(ctl, hciDevUp, dev); err != nil && !errors.Is(err, unix.EALREADY) {
				logf("could not bring hci%d back up: %v", dev, err)
			}
		}
		unix.Close(ctl)
	}
	awake := keepUSBAwake(fmt.Sprintf("/sys/class/bluetooth/hci%d/device", dev), logf)
	closeCtl := release
	release = func() { closeCtl(); awake() }

	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, btprotoHCI)
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("ble: cannot open an HCI socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrHCI{Dev: uint16(dev), Channel: hciChannelUser}); err != nil {
		unix.Close(fd)
		release()
		if errors.Is(err, unix.EBUSY) {
			// Right after probing, the kernel runs the controller's setup
			// (firmware download) and refuses the user channel meanwhile.
			return nil, nil, errRetry{fmt.Errorf("ble: hci%d is busy (still initialising, or bluetoothd brought it back up; stop bluetooth.service or use --adapter)", dev)}
		}
		return nil, nil, fmt.Errorf("ble: cannot bind an HCI user channel to hci%d: %w", dev, err)
	}
	// A non-blocking fd wrapped in os.File uses the runtime poller, so Close
	// interrupts a blocked Read.
	return os.NewFile(uintptr(fd), fmt.Sprintf("hci%d-user", dev)), release, nil
}

// keepUSBAwake turns off USB runtime power management for the USB device
// behind the adapter (dev is its sysfs "device" link) and returns a function
// that restores it. Some controllers, the Intel 7265 for one, drop an LE
// connection while autosuspended, which the phone sees as a supervision
// timeout whenever the link idles - typically while the user unlocks the
// phone. Adapters that are not USB, or not set to "auto", are left alone.
func keepUSBAwake(dev string, logf func(string, ...any)) func() {
	d, err := filepath.EvalSymlinks(dev)
	if err != nil {
		return func() {}
	}
	for ; d != "/" && d != "."; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "idVendor")); err != nil {
			continue
		}
		ctl := filepath.Join(d, "power", "control")
		b, err := os.ReadFile(ctl)
		if err != nil || strings.TrimSpace(string(b)) != "auto" {
			return func() {}
		}
		if err := os.WriteFile(ctl, []byte("on"), 0); err != nil {
			logf("could not disable USB autosuspend for %s: %v", filepath.Base(d), err)
			return func() {}
		}
		logf("USB autosuspend disabled for %s while in use", filepath.Base(d))
		return func() {
			if err := os.WriteFile(ctl, []byte("auto"), 0); err != nil {
				logf("could not restore USB autosuspend for %s: %v", filepath.Base(d), err)
			}
		}
	}
	return func() {}
}

// checkRFKill reports a hard block and, if asked, clears a soft block.
func checkRFKill(dev int, unblock bool, logf func(string, ...any)) error {
	matches, _ := filepath.Glob(fmt.Sprintf("/sys/class/bluetooth/hci%d/rfkill*", dev))
	for _, m := range matches {
		read := func(name string) string {
			b, _ := os.ReadFile(filepath.Join(m, name))
			return strings.TrimSpace(string(b))
		}
		if read("hard") == "1" {
			return fmt.Errorf("ble: hci%d is hard-blocked by rfkill (hardware switch or firmware setting)", dev)
		}
		if read("soft") != "1" {
			continue
		}
		if !unblock {
			return fmt.Errorf("ble: hci%d is soft-blocked by rfkill; run 'rfkill unblock bluetooth'", dev)
		}
		idx, err := strconv.ParseUint(read("index"), 10, 32)
		if err != nil {
			return fmt.Errorf("ble: cannot read rfkill index for hci%d", dev)
		}
		f, err := os.OpenFile("/dev/rfkill", os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("ble: hci%d is soft-blocked and /dev/rfkill is unavailable: %w", dev, err)
		}
		// struct rfkill_event { u32 idx; u8 type; u8 op; u8 soft; u8 hard; }
		ev := make([]byte, 8)
		binary.LittleEndian.PutUint32(ev, uint32(idx))
		ev[5] = rfkillOpChange
		_, err = f.Write(ev)
		f.Close()
		if err != nil {
			return fmt.Errorf("ble: could not clear the rfkill soft block on hci%d: %w", dev, err)
		}
		logf("cleared rfkill soft block on hci%d", dev)
	}
	return nil
}
