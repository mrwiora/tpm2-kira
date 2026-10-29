package phonegate

// The connection between the radio worker and the coordinator
// (gate_service.go): two socket pairs the coordinator makes and hands the
// worker as it starts it (gate_child.go) - one for one request and one
// answer at a time, each a length-prefixed JSON object, and one that stays
// silent and ends when the coordinator does. Nothing is in the file
// system, so nothing else can connect.
//
// The coordinator treats what arrives as input from the process that
// listens to the radio: requests are small and bounded, name one of the
// operations below, and every operation checks its own arguments.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/mrwiora/tpm2-kira/attest"
)

const (
	gateOpIdentity   = "identity"
	gateOpQuote      = "quote"
	gateOpBoot       = "boot-context"
	gateOpEventlog   = "eventlog"
	gateOpReceipt    = "receipt"
	gateOpReport     = "report"
	gateOpBootKey    = "boot-key"
	gateOpFactorKeep = "factor-keep"
	gateOpRelease    = "release"

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
	QuoteDigest  []byte `json:"quote_digest,omitempty"`
	// Release: what the phone released; the coordinator opens it.
	Release *attest.Release `json:"release,omitempty"`
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
	BootAnswer *attest.BootAnswer `json:"boot_answer,omitempty"`
	BootState  uint8              `json:"boot_state,omitempty"`
	// factor-keep: the factor to ask the phone to keep; release: the status.
	Keep          *attest.FactorBlob `json:"keep,omitempty"`
	ReleaseStatus uint8              `json:"release_status,omitempty"`
	Message       string             `json:"message,omitempty"`
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

// GateServer is the coordinator's side of the connection.
type GateServer struct {
	mu    sync.Mutex
	conns []net.Conn
}

// LinkGate makes the connection and serves host on the coordinator's ends,
// one request at a time, until Close. The worker's ends are returned as
// files: ExtraFiles of the worker's process, or GateClientFromFiles.
func LinkGate(host GateHost) (*GateServer, [2]*os.File, error) {
	var worker [2]*os.File
	g := &GateServer{}
	var one sync.Mutex
	for i := range worker {
		mine, theirs, err := socketPair()
		if err != nil {
			g.Close()
			for _, f := range worker[:i] {
				f.Close()
			}
			return nil, worker, err
		}
		g.conns = append(g.conns, mine)
		worker[i] = theirs
		go g.serve(mine, host, &one)
	}
	return g, worker, nil
}

// socketPair is a connected pair of stream sockets: this process's end as
// a connection, the other as a file.
func socketPair() (net.Conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("the gate's socket pair: %w", err)
	}
	f := os.NewFile(uintptr(fds[0]), "gate")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		unix.Close(fds[1])
		return nil, nil, err
	}
	return conn, os.NewFile(uintptr(fds[1]), "gate"), nil
}

// Close ends the coordinator's service: both connections are closed,
// which is how the worker learns that the phone check is over for this
// boot.
func (g *GateServer) Close() {
	g.mu.Lock()
	conns := g.conns
	g.conns = nil
	g.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func (g *GateServer) serve(conn net.Conn, host GateHost, one *sync.Mutex) {
	defer conn.Close()
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
}

func answerGate(host GateHost, req *gateRequest) *gateResponse {
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
		answer, state := host.ProveBootKey(&attest.BootChallenge{EphemeralPub: req.EphemeralPub, Sealed: req.Sealed}, req.QD, req.QuoteDigest)
		return &gateResponse{BootAnswer: answer, BootState: state}
	case gateOpFactorKeep:
		return &gateResponse{Keep: host.FactorToKeep()}
	case gateOpRelease:
		if req.Release == nil {
			return &gateResponse{Err: "no release"}
		}
		status, msg := host.TakeRelease(req.Release)
		return &gateResponse{ReleaseStatus: status, Message: msg}
	}
	return &gateResponse{Err: "unknown operation"}
}

// GateClient is the radio worker's side: a gateHost whose every method is
// a question to the coordinator.
type GateClient struct {
	mu    sync.Mutex
	conn  net.Conn
	watch net.Conn      // a second, silent connection: it ends when the coordinator does
	gone  chan struct{} // closed then
}

// GateClientFromFiles is the worker's side of LinkGate: the connection's
// two ends, as LinkGate returned them or the worker inherited them.
func GateClientFromFiles(conn, watch *os.File) (*GateClient, error) {
	c := &GateClient{gone: make(chan struct{})}
	var err error
	if c.conn, err = net.FileConn(conn); err != nil {
		return nil, fmt.Errorf("the coordinator's connection: %w", err)
	}
	conn.Close()
	if c.watch, err = net.FileConn(watch); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("the coordinator's connection: %w", err)
	}
	watch.Close()
	go func() {
		// Nothing is ever sent here; the read returns when the
		// coordinator closes its side or exits.
		_, _ = c.watch.Read(make([]byte, 1))
		close(c.gone)
	}()
	return c, nil
}

func (c *GateClient) Close() error {
	c.watch.Close()
	return c.conn.Close()
}

// Gone is closed when the coordinator has ended its service.
func (c *GateClient) Gone() <-chan struct{} { return c.gone }

func (c *GateClient) ask(req *gateRequest) (*gateResponse, error) {
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
func (c *GateClient) Identity() (*gateIdentity, int, error) {
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
func (c *GateClient) Quote(qd []byte, sel attest.PCRSelection) (*attest.QuoteResult, error) {
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
func (c *GateClient) BootContext() attest.BootContext {
	resp, err := c.ask(&gateRequest{Op: gateOpBoot})
	if err != nil || resp.Boot == nil {
		return attest.BootContext{}
	}
	return *resp.Boot
}

// Eventlog implements attest.AttesterBackend.
func (c *GateClient) Eventlog() ([]byte, error) {
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
func (c *GateClient) JudgeReceipt(r *attest.Receipt, verifierID string) attest.ReceiptCheck {
	resp, err := c.ask(&gateRequest{Op: gateOpReceipt, Receipt: r, VerifierID: verifierID})
	if err != nil || resp.Check == nil {
		return attest.ReceiptCheck{Verdict: r.Verdict, Ack: attest.AckMalformed, Detail: "the coordinator did not answer"}
	}
	return *resp.Check
}

// ProveBootKey implements attest.AttesterBackend: the coordinator's TPM
// answers, and keeps the code.
func (c *GateClient) ProveBootKey(ch *attest.BootChallenge, context, quoteDigest []byte) (*attest.BootAnswer, uint8) {
	resp, err := c.ask(&gateRequest{Op: gateOpBootKey, EphemeralPub: ch.EphemeralPub, Sealed: ch.Sealed, QD: context, QuoteDigest: quoteDigest})
	if err != nil {
		return nil, attest.BootKeyFailed
	}
	return resp.BootAnswer, resp.BootState
}

// FactorToKeep implements attest.FactorBackend: the coordinator's.
func (c *GateClient) FactorToKeep() *attest.FactorBlob {
	resp, err := c.ask(&gateRequest{Op: gateOpFactorKeep})
	if err != nil {
		return nil
	}
	return resp.Keep
}

// TakeRelease implements attest.FactorBackend: the coordinator's TPM opens it.
func (c *GateClient) TakeRelease(r *attest.Release) (uint8, string) {
	resp, err := c.ask(&gateRequest{Op: gateOpRelease, Release: r})
	if err != nil {
		return attest.ReleaseTPMRefused, "the coordinator did not answer"
	}
	if resp.Err != "" {
		return attest.ReleaseTPMRefused, resp.Err
	}
	return resp.ReleaseStatus, resp.Message
}

// Report implements gateHost.
func (c *GateClient) Report(state GateState) {
	_, _ = c.ask(&gateRequest{Op: gateOpReport, State: state})
}
