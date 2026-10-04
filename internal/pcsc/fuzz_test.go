package pcsc

import "testing"

// pcscd's replies are parsed by every seal and reseal with a YubiKey key.
// The client reads each reply with io.ReadFull at its fixed wire size, so
// every decoder is given exactly that many bytes.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, readerStateSize))
	sized := func(b []byte, n int) []byte {
		out := make([]byte, n)
		copy(out, b)
		return out
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		decodeVersionMsg(sized(b, versionMsgSize))
		decodeEstablishMsg(sized(b, establishMsgSize))
		decodeReleaseMsg(sized(b, releaseMsgSize))
		decodeConnectMsg(sized(b, connectMsgSize))
		decodeDisconnectMsg(sized(b, disconnectMsgSize))
		decodeBeginMsg(sized(b, beginMsgSize))
		decodeTransmitMsg(sized(b, transmitMsgSize))
		decodeReaderState(sized(b, readerStateSize))
		cString(b)
	})
}
