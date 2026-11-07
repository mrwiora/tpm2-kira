package admin

import (
	"crypto"
	"os"

	"github.com/tpm2-trust/tpm2-kira/internal/signing"
)

// loadSigner reads a signing key file without the checks of LoadCheckedSigningPrivateKey (its
// owner and mode, which a test's temporary file does not have).
func loadSigner(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return signing.ParseSigningPrivateKey(b, path)
}
