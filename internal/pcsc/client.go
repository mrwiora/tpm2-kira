package pcsc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// DefaultSocketPaths are tried in order when PCSCLITE_CSOCK_NAME is unset.
var DefaultSocketPaths = []string{"/run/pcscd/pcscd.comm", "/var/run/pcscd/pcscd.comm"}

// ErrNoDaemon means no pcscd socket could be reached.
var ErrNoDaemon = errors.New("no PC/SC daemon")

// Reader is one reader known to pcscd.
type Reader struct {
	Name        string
	CardPresent bool
	ATR         []byte
}

// Client is a connection to pcscd holding one established context.
//
// pcscd ties contexts and card handles to the socket they were created on,
// so one Client is used for everything, including the Cards it connects.
// A Client is not safe for concurrent use.
type Client struct {
	conn    net.Conn
	path    string
	minor   int32
	context uint32
	timeout time.Duration
}

// socketPath returns the socket pcscd is listening on, honouring
// PCSCLITE_CSOCK_NAME like libpcsclite does.
func socketPath() (string, error) {
	if p := os.Getenv("PCSCLITE_CSOCK_NAME"); p != "" {
		return p, nil
	}
	for _, p := range DefaultSocketPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w at %s — is pcscd installed and pcscd.socket enabled?", ErrNoDaemon, DefaultSocketPaths[0])
}

// Dial connects to pcscd, negotiates the protocol version and establishes a
// context. timeout bounds each individual exchange except Transmit, which may
// legitimately wait for a user to touch the token; zero means no bound.
func Dial(timeout time.Duration) (*Client, error) {
	path, err := socketPath()
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("%w at %s: %v", ErrNoDaemon, path, err)
	}
	c := &Client{conn: conn, path: path, timeout: timeout}
	if err := c.negotiate(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.establish(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close releases the context and closes the socket.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	req := releaseMsg{Context: c.context}
	var rerr error
	if resp, err := c.call(cmdReleaseContext, req.encode(), releaseMsgSize, c.timeout); err == nil {
		rerr = rvError(decodeReleaseMsg(resp).RV)
	}
	cerr := c.conn.Close()
	c.conn = nil
	if rerr != nil {
		return rerr
	}
	return cerr
}

// ProtocolVersion reports the negotiated protocol as "major:minor".
func (c *Client) ProtocolVersion() string {
	return fmt.Sprintf("%d:%d", protocolMajor, c.minor)
}

// negotiate exchanges CMD_VERSION. pcscd answers SCARD_E_SERVICE_STOPPED with
// its own version when it does not speak ours; if that version is one this
// client also understands, it is retried once with the daemon's version.
// Anything else is refused: guessing at a struct layout is how a recovery path
// gets silently corrupted.
func (c *Client) negotiate() error {
	minor := int32(protocolMinor)
	for attempt := 0; attempt < 2; attempt++ {
		req := versionMsg{Major: protocolMajor, Minor: minor}
		raw, err := c.call(cmdVersion, req.encode(), versionMsgSize, c.timeout)
		if err != nil {
			return fmt.Errorf("pcscd at %s did not answer the version handshake: %w", c.path, err)
		}
		resp := decodeVersionMsg(raw)
		if resp.RV == scardSuccess {
			c.minor = minor
			return nil
		}
		if resp.RV == scardEServiceStopped && resp.Major == protocolMajor &&
			resp.Minor >= protocolMinorMin && resp.Minor < minor {
			minor = resp.Minor
			continue
		}
		return fmt.Errorf("pcscd at %s speaks protocol %d:%d; this client supports %d:%d to %d:%d",
			c.path, resp.Major, resp.Minor, protocolMajor, protocolMinorMin, protocolMajor, protocolMinor)
	}
	return fmt.Errorf("pcscd at %s rejected every protocol version offered", c.path)
}

func (c *Client) establish() error {
	req := establishMsg{Scope: scopeSystem}
	raw, err := c.call(cmdEstablishContext, req.encode(), establishMsgSize, c.timeout)
	if err != nil {
		return fmt.Errorf("establishing a PC/SC context: %w", err)
	}
	resp := decodeEstablishMsg(raw)
	if err := rvError(resp.RV); err != nil {
		return fmt.Errorf("establishing a PC/SC context: %w", err)
	}
	c.context = resp.Context
	return nil
}

// Readers lists the readers pcscd knows about.
func (c *Client) Readers() ([]Reader, error) {
	states, err := c.readerStates()
	if err != nil {
		return nil, err
	}
	var readers []Reader
	for _, s := range states {
		if s.Name == "" {
			continue
		}
		readers = append(readers, Reader{
			Name:        s.Name,
			CardPresent: s.State&statePresent != 0,
			ATR:         s.ATR,
		})
	}
	return readers, nil
}

// readerStates fetches the raw reader state array. Protocol 4:5 and earlier
// send a fixed array of maxReadersContexts entries; 4:6 first reports the
// array length (CMD_GET_READERS_STATE_SIZE) and then sends that many.
func (c *Client) readerStates() ([]readerState, error) {
	count := int32(maxReadersContexts)
	cmd := cmdGetReadersState
	if c.minor >= 6 {
		raw, err := c.call(cmdGetReadersStateSize, nil, 4, c.timeout)
		if err != nil {
			return nil, fmt.Errorf("reading the reader count: %w", err)
		}
		count = int32(ne.Uint32(raw))
		if count < 0 || count > 4096 {
			return nil, fmt.Errorf("pcscd reported an implausible reader array size %d", count)
		}
		cmd = cmdGetReadersStateArray
	}
	raw, err := c.call(cmd, nil, int(count)*readerStateSize, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("reading the reader states: %w", err)
	}
	states := make([]readerState, count)
	for i := range states {
		states[i] = decodeReaderState(raw[i*readerStateSize : (i+1)*readerStateSize])
	}
	return states, nil
}

// call sends a header and body and reads a fixed-size reply.
func (c *Client) call(cmd uint32, body []byte, replySize int, timeout time.Duration) ([]byte, error) {
	if err := c.send(cmd, body, timeout); err != nil {
		return nil, err
	}
	return c.recv(replySize, timeout)
}

func (c *Client) send(cmd uint32, body []byte, timeout time.Duration) error {
	if c.conn == nil {
		return errors.New("pcsc client is closed")
	}
	c.setDeadline(timeout)
	msg := append(header{Size: uint32(len(body)), Command: cmd}.encode(), body...)
	_, err := c.conn.Write(msg)
	return err
}

func (c *Client) sendRaw(b []byte, timeout time.Duration) error {
	c.setDeadline(timeout)
	_, err := c.conn.Write(b)
	return err
}

func (c *Client) recv(n int, timeout time.Duration) ([]byte, error) {
	c.setDeadline(timeout)
	b := make([]byte, n)
	if _, err := io.ReadFull(c.conn, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (c *Client) setDeadline(timeout time.Duration) {
	if timeout > 0 {
		c.conn.SetDeadline(time.Now().Add(timeout))
	} else {
		c.conn.SetDeadline(time.Time{})
	}
}

// Card is a connection to the card in one reader.
type Card struct {
	c        *Client
	handle   int32
	protocol uint32
	reader   string
}

// Connect opens the card in reader in shared mode, so other processes such
// as gpg-agent or a browser can keep using the reader.
func (c *Client) Connect(reader string) (*Card, error) {
	req := connectMsg{
		Context:            c.context,
		Reader:             reader,
		ShareMode:          shareShared,
		PreferredProtocols: protocolAny,
	}
	body, err := req.encode()
	if err != nil {
		return nil, err
	}
	raw, err := c.call(cmdConnect, body, connectMsgSize, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %q: %w", reader, err)
	}
	resp := decodeConnectMsg(raw)
	if err := rvError(resp.RV); err != nil {
		return nil, fmt.Errorf("connecting to %q: %w", reader, err)
	}
	return &Card{c: c, handle: resp.Card, protocol: resp.ActiveProtocol, reader: reader}, nil
}

// Reader returns the name of the reader the card sits in.
func (k *Card) Reader() string { return k.reader }

// Disconnect releases the card, leaving it powered and its state intact.
func (k *Card) Disconnect() error { return k.disconnect(leaveCard) }

// DisconnectReset releases the card and resets it, which discards any
// verified PIN. Use it when this process unlocked the card: a PIN left
// verified would let any other process sign until the token is unplugged.
func (k *Card) DisconnectReset() error { return k.disconnect(resetCard) }

func (k *Card) disconnect(disposition uint32) error {
	req := disconnectMsg{Card: k.handle, Disposition: disposition}
	raw, err := k.c.call(cmdDisconnect, req.encode(), disconnectMsgSize, k.c.timeout)
	if err != nil {
		return err
	}
	return rvError(decodeDisconnectMsg(raw).RV)
}

// BeginTransaction gives this connection exclusive use of the card until
// EndTransaction, so no other process can select a different applet between
// two APDUs that belong together (VERIFY and the signature it unlocks).
func (k *Card) BeginTransaction() error {
	req := beginMsg{Card: k.handle}
	raw, err := k.c.call(cmdBeginTransaction, req.encode(), beginMsgSize, k.c.timeout)
	if err != nil {
		return err
	}
	return rvError(decodeBeginMsg(raw).RV)
}

// EndTransaction ends a transaction started by BeginTransaction.
func (k *Card) EndTransaction() error {
	req := disconnectMsg{Card: k.handle, Disposition: leaveCard}
	raw, err := k.c.call(cmdEndTransaction, req.encode(), disconnectMsgSize, k.c.timeout)
	if err != nil {
		return err
	}
	return rvError(decodeDisconnectMsg(raw).RV)
}

// Transmit sends one APDU and returns the response including SW1 SW2.
//
// It is not bounded by the client timeout: a token with a touch policy holds
// the response until it is touched, and pcscd itself gives up after its own
// limit.
func (k *Card) Transmit(apdu []byte) ([]byte, error) {
	if len(apdu) > maxBufferSizeExtended {
		return nil, fmt.Errorf("APDU of %d bytes is too long", len(apdu))
	}
	req := transmitMsg{
		Card:            k.handle,
		SendPCIProtocol: k.protocol,
		SendPCILength:   ioRequestSize,
		SendLength:      uint32(len(apdu)),
		RecvPCIProtocol: protocolAny,
		RecvPCILength:   ioRequestSize,
		RecvLength:      maxBufferSizeExtended,
	}
	if err := k.c.send(cmdTransmit, req.encode(), k.c.timeout); err != nil {
		return nil, err
	}
	if err := k.c.sendRaw(apdu, k.c.timeout); err != nil {
		return nil, err
	}
	raw, err := k.c.recv(transmitMsgSize, 0)
	if err != nil {
		return nil, err
	}
	resp := decodeTransmitMsg(raw)
	if err := rvError(resp.RV); err != nil {
		return nil, err
	}
	if resp.RecvLength > maxBufferSizeExtended {
		return nil, fmt.Errorf("pcscd announced a %d-byte response", resp.RecvLength)
	}
	return k.c.recv(int(resp.RecvLength), k.c.timeout)
}
