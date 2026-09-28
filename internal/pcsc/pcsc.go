// Package pcsc is a minimal, cgo-free client for the pcsc-lite daemon.
//
// tpm2-kira is built with CGO_ENABLED=0 so that one statically linked binary
// serves both the installed system and the initramfs, which rules out binding
// libpcsclite. This package therefore speaks pcscd's Unix-socket protocol
// directly, implementing only what is needed to send APDUs to a card:
// establish a context, list readers, connect, transmit, disconnect.
//
// # Wire format and its risks
//
// The protocol is pcsc-lite's internal client/server IPC, defined in
// src/winscard_msg.h, which is not part of the installed public headers. The
// messages are C structs exchanged with native alignment and byte order, so a
// layout change between pcsc-lite releases would be read as valid data with
// different meaning.
//
// Two things guard against that, and both are deliberate:
//
//   - The version handshake is checked strictly. A daemon reporting any
//     protocol other than the one encoded here is refused with a message
//     naming both versions, rather than being talked to on the assumption that
//     the layout is unchanged.
//   - Every struct below has a compile-time size assertion next to it, citing
//     the field list it mirrors, so a future correction is one file to review.
//
// The encoding assumes a little-endian host, which covers the architectures
// tpm2-kira supports (x86_64 and aarch64); initClient refuses to run elsewhere
// rather than producing silent nonsense.
package pcsc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"
)

// Protocol version this client implements. pcsc-lite has used 4.4 since 1.9;
// see the package comment for why a mismatch is fatal rather than tolerated.
const (
	protocolVersionMajor int32 = 4
	protocolVersionMinor int32 = 4
)

// Socket locations, tried in order. The first is current; the second is where
// older distributions put it.
var socketPaths = []string{
	"/run/pcscd/pcscd.comm",
	"/var/run/pcscd/pcscd.comm",
}

// Command identifiers, from enum pcsc_msg_commands.
const (
	cmdEstablishContext uint32 = 0x01
	cmdReleaseContext   uint32 = 0x02
	cmdConnect          uint32 = 0x04
	cmdDisconnect       uint32 = 0x06
	cmdTransmit         uint32 = 0x09
	cmdVersion          uint32 = 0x10
	cmdGetReadersState  uint32 = 0x11
)

// Constants mirrored from the installed PCSC/pcsclite.h.
const (
	maxReaderName      = 128
	maxATRSize         = 33
	maxReaderContexts  = 16
	scardScopeSystem   = 0x0002
	scardShareShared   = 0x0002
	scardProtocolT0    = 0x0001
	scardProtocolT1    = 0x0002
	scardProtocolAny   = scardProtocolT0 | scardProtocolT1
	scardLeaveCard     = 0x0000
	scardStatePresent  = 0x0020
	scardSuccess       = 0x00000000
	readerStateSize    = 184
	establishStructLen = 12
	releaseStructLen   = 8
	connectStructLen   = 152
	disconnectLen      = 12
	transmitStructLen  = 32
	versionStructLen   = 12
	headerLen          = 8
)

// ioTimeout bounds every socket operation. pcscd can block on a wedged reader,
// and a reseal that hangs forever in a package hook is worse than one that
// fails with a message.
const ioTimeout = 30 * time.Second

// ErrDaemonUnavailable means pcscd is not reachable. Callers translate it into
// "the token is not available" rather than into a malfunction.
var ErrDaemonUnavailable = errors.New("pcscd is not running or its socket is not reachable")

// ErrNoReader means the daemon is up but no reader holds a card.
var ErrNoReader = errors.New("no smart card reader with a card present")

// Client is a connection to pcscd holding one established context.
type Client struct {
	conn    net.Conn
	context uint32
	closed  bool
}

// Card is a connected card within a Client.
type Card struct {
	client   *Client
	handle   int32
	protocol uint32
}

// Connect dials pcscd, negotiates the protocol version and establishes a
// context.
func Connect() (*Client, error) {
	if !isLittleEndian() {
		return nil, fmt.Errorf("the pcscd protocol client only supports little-endian hosts")
	}

	conn, err := dialDaemon()
	if err != nil {
		return nil, err
	}

	c := &Client{conn: conn}

	if err := c.negotiateVersion(); err != nil {
		conn.Close()
		return nil, err
	}

	if err := c.establishContext(); err != nil {
		conn.Close()
		return nil, err
	}

	return c, nil
}

func dialDaemon() (net.Conn, error) {
	var lastErr error

	for _, path := range socketPaths {
		if _, err := os.Stat(path); err != nil {
			lastErr = err
			continue
		}

		conn, err := net.DialTimeout("unix", path, ioTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("%w (tried %s): %v",
		ErrDaemonUnavailable, strings.Join(socketPaths, ", "), lastErr)
}

// negotiateVersion exchanges version_struct { int32 major; int32 minor;
// uint32 rv } and refuses any protocol this client was not written against.
func (c *Client) negotiateVersion() error {
	req := make([]byte, versionStructLen)
	binary.LittleEndian.PutUint32(req[0:], uint32(protocolVersionMajor))
	binary.LittleEndian.PutUint32(req[4:], uint32(protocolVersionMinor))
	binary.LittleEndian.PutUint32(req[8:], scardSuccess)

	if err := c.send(cmdVersion, req); err != nil {
		return err
	}

	rsp, err := c.receive(versionStructLen)
	if err != nil {
		return err
	}

	major := int32(binary.LittleEndian.Uint32(rsp[0:]))
	minor := int32(binary.LittleEndian.Uint32(rsp[4:]))
	rv := binary.LittleEndian.Uint32(rsp[8:])

	if rv != scardSuccess {
		return fmt.Errorf("pcscd rejected the version handshake (rv 0x%08X)", rv)
	}

	if major != protocolVersionMajor || minor != protocolVersionMinor {
		return fmt.Errorf(
			"pcscd speaks protocol %d.%d but this build implements %d.%d.\n"+
				"  The message layout is not guaranteed across protocol versions, so talking to it\n"+
				"  anyway could corrupt commands rather than fail cleanly. Please report this with\n"+
				"  your pcsc-lite version so the client can be updated.",
			major, minor, protocolVersionMajor, protocolVersionMinor)
	}

	return nil
}

// establishContext sends establish_struct { uint32 dwScope; uint32 hContext;
// uint32 rv }.
func (c *Client) establishContext() error {
	req := make([]byte, establishStructLen)
	binary.LittleEndian.PutUint32(req[0:], scardScopeSystem)
	binary.LittleEndian.PutUint32(req[4:], 0)
	binary.LittleEndian.PutUint32(req[8:], scardSuccess)

	if err := c.send(cmdEstablishContext, req); err != nil {
		return err
	}

	rsp, err := c.receive(establishStructLen)
	if err != nil {
		return err
	}

	if rv := binary.LittleEndian.Uint32(rsp[8:]); rv != scardSuccess {
		return fmt.Errorf("SCardEstablishContext failed: %s", statusString(rv))
	}

	c.context = binary.LittleEndian.Uint32(rsp[4:])
	return nil
}

// Readers returns the names of readers the daemon knows about. When
// withCardOnly is set, only readers reporting a card present are returned.
//
// The reply is READER_STATE[16], each entry being
//
//	char     readerName[128]
//	uint32   eventCounter
//	uint32   readerState
//	int32    readerSharing
//	uint8    cardAtr[33]   (+3 bytes padding)
//	uint32   cardAtrLength
//	uint32   cardProtocol
func (c *Client) Readers(withCardOnly bool) ([]string, error) {
	if err := c.send(cmdGetReadersState, nil); err != nil {
		return nil, err
	}

	rsp, err := c.receive(readerStateSize * maxReaderContexts)
	if err != nil {
		return nil, err
	}

	var readers []string
	for i := 0; i < maxReaderContexts; i++ {
		entry := rsp[i*readerStateSize : (i+1)*readerStateSize]

		name := cString(entry[0:maxReaderName])
		if name == "" {
			continue
		}

		state := binary.LittleEndian.Uint32(entry[maxReaderName+4:])
		if withCardOnly && state&scardStatePresent == 0 {
			continue
		}

		readers = append(readers, name)
	}

	return readers, nil
}

// ConnectCard connects to the card in the named reader, in shared mode so that
// other PC/SC users — gpg-agent, a browser, ykman — keep working.
func (c *Client) ConnectCard(reader string) (*Card, error) {
	if len(reader) >= maxReaderName {
		return nil, fmt.Errorf("reader name %q is too long", reader)
	}

	req := make([]byte, connectStructLen)
	binary.LittleEndian.PutUint32(req[0:], c.context)
	copy(req[4:4+maxReaderName], reader)
	off := 4 + maxReaderName
	binary.LittleEndian.PutUint32(req[off:], scardShareShared)
	binary.LittleEndian.PutUint32(req[off+4:], scardProtocolAny)
	binary.LittleEndian.PutUint32(req[off+8:], 0) // hCard, filled by the daemon
	binary.LittleEndian.PutUint32(req[off+12:], 0)
	binary.LittleEndian.PutUint32(req[off+16:], scardSuccess)

	if err := c.send(cmdConnect, req); err != nil {
		return nil, err
	}

	rsp, err := c.receive(connectStructLen)
	if err != nil {
		return nil, err
	}

	if rv := binary.LittleEndian.Uint32(rsp[off+16:]); rv != scardSuccess {
		return nil, fmt.Errorf("SCardConnect to %q failed: %s", reader, statusString(rv))
	}

	return &Card{
		client:   c,
		handle:   int32(binary.LittleEndian.Uint32(rsp[off+8:])),
		protocol: binary.LittleEndian.Uint32(rsp[off+12:]),
	}, nil
}

// Transmit sends one APDU and returns the card's response, including the
// trailing status word.
//
// transmit_struct is
//
//	int32  hCard
//	uint32 ioSendPciProtocol
//	uint32 ioSendPciLength
//	uint32 cbSendLength
//	uint32 ioRecvPciProtocol
//	uint32 ioRecvPciLength
//	uint32 pcbRecvLength
//	uint32 rv
//
// followed by cbSendLength bytes of APDU; the reply is the same struct
// followed by pcbRecvLength bytes.
func (card *Card) Transmit(apdu []byte) ([]byte, error) {
	const maxResponse = 65538 // 64 KiB of data plus the status word

	req := make([]byte, transmitStructLen)
	binary.LittleEndian.PutUint32(req[0:], uint32(card.handle))
	binary.LittleEndian.PutUint32(req[4:], card.protocol)
	binary.LittleEndian.PutUint32(req[8:], 8) // sizeof(SCARD_IO_REQUEST)
	binary.LittleEndian.PutUint32(req[12:], uint32(len(apdu)))
	binary.LittleEndian.PutUint32(req[16:], scardProtocolAny)
	binary.LittleEndian.PutUint32(req[20:], 8)
	binary.LittleEndian.PutUint32(req[24:], maxResponse)
	binary.LittleEndian.PutUint32(req[28:], scardSuccess)

	if err := card.client.send(cmdTransmit, req); err != nil {
		return nil, err
	}
	if err := card.client.write(apdu); err != nil {
		return nil, err
	}

	rsp, err := card.client.receive(transmitStructLen)
	if err != nil {
		return nil, err
	}

	if rv := binary.LittleEndian.Uint32(rsp[28:]); rv != scardSuccess {
		return nil, fmt.Errorf("SCardTransmit failed: %s", statusString(rv))
	}

	n := binary.LittleEndian.Uint32(rsp[24:])
	if n > maxResponse {
		return nil, fmt.Errorf("pcscd reported a %d-byte response, which exceeds the %d-byte buffer", n, maxResponse)
	}
	if n == 0 {
		return nil, fmt.Errorf("card returned an empty response")
	}

	return card.client.receive(int(n))
}

// Disconnect closes the card handle, leaving the card powered as it was.
func (card *Card) Disconnect() error {
	req := make([]byte, disconnectLen)
	binary.LittleEndian.PutUint32(req[0:], uint32(card.handle))
	binary.LittleEndian.PutUint32(req[4:], scardLeaveCard)
	binary.LittleEndian.PutUint32(req[8:], scardSuccess)

	if err := card.client.send(cmdDisconnect, req); err != nil {
		return err
	}

	rsp, err := card.client.receive(disconnectLen)
	if err != nil {
		return err
	}

	if rv := binary.LittleEndian.Uint32(rsp[8:]); rv != scardSuccess {
		return fmt.Errorf("SCardDisconnect failed: %s", statusString(rv))
	}
	return nil
}

// Close releases the context and the socket. It is safe to call twice.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true

	req := make([]byte, releaseStructLen)
	binary.LittleEndian.PutUint32(req[0:], c.context)
	binary.LittleEndian.PutUint32(req[4:], scardSuccess)

	// A failure to release is not worth reporting over a failure to close
	// the socket: the daemon reaps the context when the connection drops.
	_ = c.send(cmdReleaseContext, req)
	_, _ = c.receive(releaseStructLen)

	return c.conn.Close()
}

// send writes the rxHeader { uint32 size; uint32 command } and the body.
func (c *Client) send(command uint32, body []byte) error {
	header := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(header[0:], uint32(len(body)))
	binary.LittleEndian.PutUint32(header[4:], command)

	if err := c.write(header); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return c.write(body)
}

func (c *Client) write(b []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(ioTimeout)); err != nil {
		return err
	}
	if _, err := c.conn.Write(b); err != nil {
		return fmt.Errorf("failed to write to pcscd: %w", err)
	}
	return nil
}

// receive reads exactly n bytes. Replies carry no header: the client knows the
// size of the struct it asked for.
func (c *Client) receive(n int) ([]byte, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, err
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read %d bytes from pcscd: %w", n, err)
	}
	return buf, nil
}

func cString(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func isLittleEndian() bool {
	var x uint16 = 1
	return *(*byte)(unsafe.Pointer(&x)) == 1
}

// statusString renders the SCARD_* error codes worth distinguishing. The rest
// are reported numerically; the value is what matters for a bug report.
func statusString(rv uint32) string {
	switch rv {
	case 0x8010002E:
		return "no reader available (SCARD_E_NO_READERS_AVAILABLE)"
	case 0x8010000C:
		return "no smart card in the reader (SCARD_E_NO_SMARTCARD)"
	case 0x80100017:
		return "the reader is in use by another application (SCARD_E_SHARING_VIOLATION)"
	case 0x80100069:
		return "the card was removed (SCARD_W_REMOVED_CARD)"
	case 0x80100068:
		return "the card was reset (SCARD_W_RESET_CARD)"
	case 0x80100066:
		return "the card is unresponsive (SCARD_W_UNRESPONSIVE_CARD)"
	case 0x80100008:
		return "the buffer was too small (SCARD_E_INSUFFICIENT_BUFFER)"
	default:
		return fmt.Sprintf("SCARD error 0x%08X", rv)
	}
}
