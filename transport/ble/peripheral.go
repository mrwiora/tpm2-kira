package ble

import (
	"errors"
	"fmt"
	"time"

	"github.com/mrwiora/tpm2-kira/transport/frame"
)

// Config selects and describes the adapter.
type Config struct {
	// Adapter is the HCI device index (hci0 = 0).
	Adapter int
	// DeviceName is the GAP device name readable after connecting. It is
	// never advertised; keep it generic.
	DeviceName string
	// UnblockRFKill clears a soft rfkill block on the adapter before use.
	UnblockRFKill bool
	// Wait is how long to wait for the adapter to appear and become free.
	// In an initramfs the adapter shows up only after its module and
	// firmware have loaded, and the kernel holds it busy while it runs the
	// controller's setup; both take seconds. Zero means do not wait.
	Wait time.Duration
	// Logf receives debug output; nil discards it.
	Logf func(format string, args ...any)
}

// Peripheral owns one adapter exclusively for its lifetime.
type Peripheral struct {
	h       *host
	release func()
}

// Open takes the adapter through an HCI user channel. While it is open,
// nothing else on the machine can use that adapter: on a running desktop
// this disconnects Bluetooth mice, keyboards and headsets until Close.
func Open(cfg Config) (*Peripheral, error) {
	if cfg.DeviceName == "" {
		cfg.DeviceName = "tpm2-kira"
	}
	tr, release, err := openUserChannelWait(cfg.Adapter, cfg.UnblockRFKill, cfg.Wait, cfg.Logf)
	if err != nil {
		return nil, err
	}
	p, err := newPeripheral(tr, cfg)
	if err != nil {
		tr.Close()
		release()
		return nil, err
	}
	p.release = release
	return p, nil
}

func newPeripheral(tr hciTransport, cfg Config) (*Peripheral, error) {
	h := newHost(tr, cfg.DeviceName, cfg.Logf)
	if err := h.init(); err != nil {
		return nil, fmt.Errorf("ble: controller initialisation failed: %w", err)
	}
	return &Peripheral{h: h}, nil
}

// Accept advertises adv and blocks until a central connects, then returns
// the connection as a record-oriented attest.Conn. Advertising stops while a
// central is connected. timeout <= 0 waits forever.
func (p *Peripheral) Accept(adv Advertisement, budget frame.Budget, timeout time.Duration) (*frame.Conn, error) {
	h := p.h
	// A central that connected while nobody was accepting (it raced the end
	// of the previous session) is dropped: it would otherwise hold the only
	// connection slot.
	h.mu.Lock()
	stale := h.link
	if stale != nil && stale.accepted {
		stale = nil
	}
	h.mu.Unlock()
	if stale != nil {
		_ = stale.Close()
	}
	// Wait for a previous connection to finish disconnecting.
	deadline := time.Now().Add(3 * time.Second)
	for {
		h.mu.Lock()
		busy, closed := h.link != nil, h.closed
		h.mu.Unlock()
		if closed {
			return nil, h.err()
		}
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			return nil, errors.New("ble: previous connection did not close")
		}
		time.Sleep(20 * time.Millisecond)
	}

	h.mu.Lock()
	h.adv = adv
	h.db = newGATTDB(h.devName, adv.Info)
	h.budget = budget
	h.mu.Unlock()
	// Drain a link that connected and vanished before anyone accepted it.
	select {
	case <-h.newLinks:
	default:
	}
	if err := h.startAdvertising(); err != nil {
		return nil, err
	}

	var tch <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		tch = t.C
	}
	select {
	case l := <-h.newLinks:
		h.mu.Lock()
		l.accepted = true
		h.mu.Unlock()
		return l.conn, nil
	case <-tch:
		h.stopAdvertising()
		return nil, ErrAcceptTimeout
	case <-h.done:
		return nil, h.err()
	}
}

// ErrAcceptTimeout is returned when no central connected in time.
var ErrAcceptTimeout = errors.New("ble: no phone connected in time")

// Close stops advertising, disconnects, releases the adapter and restores
// its previous state.
func (p *Peripheral) Close() error {
	h := p.h
	h.mu.Lock()
	l := h.link
	h.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	h.stopAdvertising()
	err := h.tr.Close()
	<-h.done
	if p.release != nil {
		p.release()
	}
	return err
}
