package frame

import (
	"errors"
	"sync"
	"time"
)

// Link is a fragment-oriented connection: for BLE, writes to the RX
// characteristic arrive as fragments and fragments leave as TX notifications.
type Link interface {
	// SendFragment transmits one fragment of at most MaxFragment bytes.
	SendFragment(frag []byte) error
	// MaxFragment is the current largest fragment (ATT_MTU - 3 for BLE).
	MaxFragment() int
	// Close tears the link down.
	Close() error
}

// Budget limits one session (PLAN-BLE.md §4.4): exceeding either drops the
// connection and the peripheral returns to advertising.
type Budget struct {
	MaxRecord int           // largest single record
	MaxBytes  int64         // all bytes received on the connection
	Deadline  time.Duration // wall clock for the whole session
}

// DefaultBudget fits an attestation with an event log transfer.
var DefaultBudget = Budget{MaxRecord: MaxRecord, MaxBytes: 4 << 20, Deadline: 2 * time.Minute}

// Conn adapts a Link to the record-oriented attest.Conn interface.
// The link owner calls Deliver for every received fragment.
type Conn struct {
	link Link
	frag *Fragmenter
	reas *Reassembler

	mu      sync.Mutex
	queue   [][]byte
	err     error
	notify  chan struct{}
	timer   *time.Timer
	closeMu sync.Once
}

// ErrDeadline is returned when the session's wall-clock budget runs out.
var ErrDeadline = errors.New("frame: session deadline exceeded")

// ErrClosed is returned after Close or after the link went away.
var ErrClosed = errors.New("frame: connection closed")

// NewConn wraps a link with the given budget.
func NewConn(link Link, b Budget) (*Conn, error) {
	f, err := NewFragmenter(link.MaxFragment())
	if err != nil {
		return nil, err
	}
	c := &Conn{
		link:   link,
		frag:   f,
		reas:   NewReassembler(b.MaxRecord, b.MaxBytes),
		notify: make(chan struct{}, 1),
	}
	if b.Deadline > 0 {
		c.timer = time.AfterFunc(b.Deadline, func() { c.fail(ErrDeadline) })
	}
	return c, nil
}

func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
	// Off the caller's goroutine: fail may run inside the link's own
	// receive path (Deliver), which a blocking Close would stall.
	go func() { _ = c.link.Close() }()
}

// Deliver hands the connection one received fragment.
func (c *Conn) Deliver(frag []byte) {
	rec, err := c.reas.Feed(frag)
	if err != nil {
		c.fail(err)
		return
	}
	if rec == nil {
		return
	}
	c.mu.Lock()
	c.queue = append(c.queue, rec)
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// LinkLost reports that the link went away underneath the connection.
func (c *Conn) LinkLost(err error) {
	if err == nil {
		err = ErrClosed
	}
	c.fail(err)
}

// Send fragments and transmits one record.
func (c *Conn) Send(record []byte) error {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.frag.SetMax(c.link.MaxFragment()); err != nil {
		return err
	}
	frags, err := c.frag.Split(record)
	if err != nil {
		return err
	}
	for _, f := range frags {
		if err := c.link.SendFragment(f); err != nil {
			c.fail(err)
			return err
		}
	}
	return nil
}

// Recv blocks until a record arrives or the connection fails.
func (c *Conn) Recv() ([]byte, error) {
	for {
		c.mu.Lock()
		if len(c.queue) > 0 {
			rec := c.queue[0]
			c.queue = c.queue[1:]
			c.mu.Unlock()
			return rec, nil
		}
		err := c.err
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		<-c.notify
	}
}

// Close ends the connection and the link.
func (c *Conn) Close() error {
	c.closeMu.Do(func() {
		if c.timer != nil {
			c.timer.Stop()
		}
		c.fail(ErrClosed)
	})
	return nil
}
