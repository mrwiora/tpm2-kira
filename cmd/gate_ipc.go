package cmd

// The connection between the radio worker and the coordinator
// (gate_service.go): a Unix socket in /run, one request and one answer at a
// time, each a length-prefixed JSON object.
//
// The coordinator treats what arrives as input from the process that
// listens to the radio: requests are small and bounded, name one of five
// operations, and every operation checks its own arguments. Only a process
// of the coordinator's own user (root) may connect.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/matthias/tpm2-kira/attest"
)

// DefaultGateSocketPath is where the units put the coordinator's socket.
const DefaultGateSocketPath = "/run/tpm2-kira/gate.sock"

const (
	gateOpIdentity = "identity"
	gateOpQuote    = "quote"
	gateOpBoot     = "boot-context"
	gateOpEventlog = "eventlog"
	gateOpReceipt  = "receipt"
	gateOpReport   = "report"
	gateOpBootKey  = "boot-key"

	maxGateRequest  = 64 << 10                         // the largest is a receipt
	maxGateResponse = 2*attest.MaxEventlogSize + 1<<16 // an event log, base64 in JSON
)

type gateRequest struct {
	Op         string          `json:"op"`
	QD         []byte          `json:"qd,omitempty"`
	Alg        uint16          `json:"alg,omitempty"`
	PCRs       []uint8         `json:"pcrs,omitempty"`
	Receipt    *attest.Receipt `json:"receipt,omitempty"`
	VerifierID string          `json:"verifier_id,omitempty"`
	State      GateState       `json:"state,omitempty"`
	// boot-key: the phone's challenge, and the session data it is bound to (QD).
	EphemeralPub []byte `json:"ephemeral_pub,omitempty"`
	Sealed       []byte `json:"sealed,omitempty"`
}

type gateResponse struct {
	Err      string               `json:"err,omitempty"`
	Code     int                  `json:"code,omitempty"`
	Identity *gateIdentity        `json:"identity,omitempty"`
	Quote    *attest.QuoteResult  `json:"quote,omitempty"`
	Boot     *attest.BootContext  `json:"boot,omitempty"`
	Eventlog []byte               `json:"eventlog,omitempty"`
	Check    *attest.ReceiptCheck `json:"check,omitempty"`
	// boot-key: the proof, when the TPM released the key, and the state.
	// The code itself stays with the coordinator.
	BootProof []byte `json:"boot_proof,omitempty"`
	BootState uint8  `json:"boot_state,omitempty"`
}

func writeGateFrame(w io.Writer, v any, limit int) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > limit {
		return fmt.Errorf("message of %d bytes exceeds %d", len(data), limit)
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(data)))
	_, err = w.Write(append(hdr, data...))
	return err
}

func readGateFrame(r io.Reader, v any, limit int) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(hdr))
	if n <= 0 || n > limit {
		return fmt.Errorf("message of %d bytes exceeds %d", n, limit)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// listenGate creates the coordinator's socket: a directory and a socket
// only its own user can enter.
func listenGate(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(path) // a leftover of an earlier run
	old := unix.Umask(0o177)
	l, err := net.Listen("unix", path)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// gateServer is the coordinator's listening side.
type gateServer struct {
	l     net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	done  bool
}

// serveGate answers radio workers until Close. Requests are handled one at
// a time, whichever connection they come from.
func serveGate(l net.Listener, host gateHost) *gateServer {
	g := &gateServer{l: l, conns: map[net.Conn]struct{}{}}
	go g.run(host)
	return g
}

// Close ends the coordinator's service: the socket goes away and every
// worker's connection is closed, which is how a worker learns that the
// phone check is over for this boot.
func (g *gateServer) Close() {
	g.mu.Lock()
	g.done = true
	conns := g.conns
	g.conns = map[net.Conn]struct{}{}
	g.mu.Unlock()
	g.l.Close()
	for c := range conns {
		c.Close()
	}
}

func (g *gateServer) run(host gateHost) {
	var one sync.Mutex
	for {
		conn, err := g.l.Accept()
		if err != nil {
			return
		}
		g.mu.Lock()
		if g.done {
			g.mu.Unlock()
			conn.Close()
			return
		}
		g.conns[conn] = struct{}{}
		g.mu.Unlock()
		go func() {
			defer func() {
				g.mu.Lock()
				delete(g.conns, conn)
				g.mu.Unlock()
				conn.Close()
			}()
			if !sameUser(conn) {
				return
			}
			for {
				var req gateRequest
				if err := readGateFrame(conn, &req, maxGateRequest); err != nil {
					return
				}
				one.Lock()
				resp := answerGate(host, &req)
				one.Unlock()
				if err := writeGateFrame(conn, resp, maxGateResponse); err != nil {
					return
				}
			}
		}()
	}
}

// sameUser reports whether the peer runs as the coordinator's own user.
func sameUser(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	same := false
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		same = err == nil && int(cred.Uid) == os.Getuid()
	})
	return same
}

func answerGate(host gateHost, req *gateRequest) *gateResponse {
	switch req.Op {
	case gateOpIdentity:
		id, code, err := host.Identity()
		if err != nil || code != 0 {
			msg := "no slot to serve"
			if err != nil {
				msg = err.Error()
			}
			return &gateResponse{Err: msg, Code: code}
		}
		return &gateResponse{Identity: id}
	case gateOpQuote:
		q, err := host.Quote(req.QD, attest.PCRSelection{Alg: req.Alg, Indices: req.PCRs})
		if err != nil {
			return &gateResponse{Err: err.Error()}
		}
		return &gateResponse{Quote: q}
	case gateOpBoot:
		bc := host.BootContext()
		return &gateResponse{Boot: &bc}
	case gateOpEventlog:
		log, err := host.Eventlog()
		if err != nil {
			return &gateResponse{Err: err.Error()}
		}
		if len(log) > attest.MaxEventlogSize {
			log = nil // the session does not send a larger one either
		}
		return &gateResponse{Eventlog: log}
	case gateOpReceipt:
		if req.Receipt == nil {
			return &gateResponse{Err: "no receipt"}
		}
		c := host.JudgeReceipt(req.Receipt, req.VerifierID)
		return &gateResponse{Check: &c}
	case gateOpReport:
		host.Report(req.State)
		return &gateResponse{}
	case gateOpBootKey:
		proof, state := host.ProveBootKey(&attest.BootChallenge{EphemeralPub: req.EphemeralPub, Sealed: req.Sealed}, req.QD)
		return &gateResponse{BootProof: proof, BootState: state}
	}
	return &gateResponse{Err: "unknown operation"}
}

// gateClient is the radio worker's side: a gateHost whose every method is
// a question to the coordinator.
type gateClient struct {
	mu    sync.Mutex
	conn  net.Conn
	watch net.Conn      // a second, silent connection: it ends when the coordinator does
	gone  chan struct{} // closed then
}

// dialGate connects to the coordinator, which starts at the same moment as
// the worker and may not be listening yet.
func dialGate(path string, wait time.Duration) (*gateClient, error) {
	deadline := time.Now().Add(wait)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			c := &gateClient{conn: conn, gone: make(chan struct{})}
			if c.watch, err = net.Dial("unix", path); err != nil {
				conn.Close()
				return nil, fmt.Errorf("coordinator at %s: %w", path, err)
			}
			go func() {
				// Nothing is ever sent here; the read returns when the
				// coordinator closes its side or exits.
				_, _ = c.watch.Read(make([]byte, 1))
				close(c.gone)
			}()
			return c, nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("no coordinator at %s (is tpm2-kira.service running?): %w", path, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (c *gateClient) Close() error {
	c.watch.Close()
	return c.conn.Close()
}

// Gone is closed when the coordinator has ended its service.
func (c *gateClient) Gone() <-chan struct{} { return c.gone }

func (c *gateClient) ask(req *gateRequest) (*gateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeGateFrame(c.conn, req, maxGateRequest); err != nil {
		return nil, fmt.Errorf("coordinator: %w", err)
	}
	var resp gateResponse
	if err := readGateFrame(c.conn, &resp, maxGateResponse); err != nil {
		return nil, fmt.Errorf("coordinator: %w", err)
	}
	return &resp, nil
}

// Identity implements gateHost.
func (c *gateClient) Identity() (*gateIdentity, int, error) {
	resp, err := c.ask(&gateRequest{Op: gateOpIdentity})
	if err != nil {
		return nil, ExitUnavailable, err
	}
	if resp.Identity == nil {
		code := resp.Code
		if code == 0 {
			code = ExitInternal
		}
		return nil, code, errors.New(resp.Err)
	}
	return resp.Identity, 0, nil
}

// Quote implements attest.AttesterBackend.
func (c *gateClient) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
	resp, err := c.ask(&gateRequest{Op: gateOpQuote, QD: qd, Alg: sel.Alg, PCRs: sel.Indices})
	if err != nil {
		return nil, err
	}
	if resp.Quote == nil {
		return nil, errors.New(resp.Err)
	}
	return resp.Quote, nil
}

// BootContext implements attest.AttesterBackend.
func (c *gateClient) BootContext() attest.BootContext {
	resp, err := c.ask(&gateRequest{Op: gateOpBoot})
	if err != nil || resp.Boot == nil {
		return attest.BootContext{}
	}
	return *resp.Boot
}

// Eventlog implements attest.AttesterBackend.
func (c *gateClient) Eventlog() ([]byte, error) {
	resp, err := c.ask(&gateRequest{Op: gateOpEventlog})
	if err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return nil, errors.New(resp.Err)
	}
	return resp.Eventlog, nil
}

// JudgeReceipt implements attest.ReceiptJudge: the coordinator decides.
func (c *gateClient) JudgeReceipt(r *attest.Receipt, verifierID string) attest.ReceiptCheck {
	resp, err := c.ask(&gateRequest{Op: gateOpReceipt, Receipt: r, VerifierID: verifierID})
	if err != nil || resp.Check == nil {
		return attest.ReceiptCheck{Verdict: r.Verdict, Ack: attest.AckMalformed, Detail: "the coordinator did not answer"}
	}
	return *resp.Check
}

// ProveBootKey implements attest.AttesterBackend: the coordinator's TPM
// answers, and keeps the code.
func (c *gateClient) ProveBootKey(ch *attest.BootChallenge, context []byte) ([]byte, uint8) {
	resp, err := c.ask(&gateRequest{Op: gateOpBootKey, EphemeralPub: ch.EphemeralPub, Sealed: ch.Sealed, QD: context})
	if err != nil {
		return nil, attest.BootKeyFailed
	}
	return resp.BootProof, resp.BootState
}

// Report implements gateHost.
func (c *gateClient) Report(state GateState) {
	_, _ = c.ask(&gateRequest{Op: gateOpReport, State: state})
}
