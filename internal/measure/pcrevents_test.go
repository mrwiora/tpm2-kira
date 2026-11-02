package measure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"
)

// variableData builds a UEFI_VARIABLE_DATA.
func variableData(name string, data []byte) []byte {
	units := utf16.Encode([]rune(name))
	b := make([]byte, 16, 32+2*len(units)+len(data))
	b = binary.LittleEndian.AppendUint64(b, uint64(len(units)))
	b = binary.LittleEndian.AppendUint64(b, uint64(len(data)))
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return append(b, data...)
}

func TestDescribeEvent(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Someone's db key"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0xAB}, 32)
	for _, tc := range []struct {
		name  string
		typ   uint32
		data  []byte
		want  string
		wantN string
	}{
		{"Secure Boot on", evEFIVariableConfig, variableData("SecureBoot", []byte{1}), "SecureBoot: on", ""},
		{"Secure Boot off", evEFIVariableConfig, variableData("SecureBoot", []byte{0}), "SecureBoot: off", ""},
		{"an empty PK", evEFIVariableConfig, variableData("PK", nil), "PK: empty, digest abababababababab", ""},
		{"a db that does not parse", evEFIVariableConfig, variableData("db", []byte{1, 2, 3}), "db: 3 bytes, digest abababababababab", ""},
		{"a certificate", evEFIVariableSigner, variableData("db", append(make([]byte, 16), der...)), `verified by db: "CN=Someone's db key", digest`, ""},
		{"a name with control characters", evEFIVariableConfig, variableData("db\x1b[31m", nil), `"db\x1b[31m": empty`, "\x1b"},
		{"a variable cut short", evEFIVariableConfig, []byte{1, 2}, "a Secure Boot variable, unreadable in the log", ""},
		{"a separator", evSeparator, []byte{0, 0, 0, 0}, "separator", ""},
		{"an action", evEFIAction, []byte("Calling EFI"), `action "Calling EFI"`, ""},
		{"something else", 0x12345, nil, "digest abababababababab", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := describeEvent(attest.Event{Type: attest.EventType(tc.typ), Data: tc.data, Digest: digest})
			if !strings.Contains(got, tc.want) {
				t.Fatalf("%q, want %q in it", got, tc.want)
			}
			if tc.wantN != "" && strings.Contains(got, tc.wantN) {
				t.Fatalf("%q carries %q", got, tc.wantN)
			}
		})
	}
}

// The log comes from outside what is checked here: no input crashes the description,
// and nothing unquoted reaches the terminal.
func FuzzDescribeEvent(f *testing.F) {
	f.Add(uint32(evEFIVariableConfig), variableData("db", []byte{1, 2, 3}))
	f.Add(uint32(evEFIVariableSigner), variableData("Shim", make([]byte, 40)))
	f.Add(uint32(evEFIAction), []byte("text"))
	f.Add(uint32(evEFIVariableConfig), bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, typ uint32, data []byte) {
		if got := describeEvent(attest.Event{Type: attest.EventType(typ), Data: data, Digest: []byte{1}}); strings.ContainsAny(got, "\x1b\n\r") {
			t.Fatalf("not quoted: %q", got)
		}
	})
}
