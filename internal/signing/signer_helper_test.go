package signing

import (
	"crypto"
	"os"
)

// loadSigner reads a signing key file without the checks of LoadCheckedSigningPrivateKey.
func loadSigner(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSigningPrivateKey(b, path)
}
