package cmd

const (
	// DefaultKeysDir is the directory where tpm2-kira stores its signing keys.
	DefaultKeysDir = "/var/lib/tpm2-kira/keys"

	// DefaultPublicKeyPath is the default path for the signing public key.
	DefaultPublicKeyPath = DefaultKeysDir + "/seal.pub"

	// DefaultPrivateKeyPath is the default path for the signing private key.
	DefaultPrivateKeyPath = DefaultKeysDir + "/seal.key"
)

// PINFileSetting is the --pin-file value, used when a signing key lives on a
// hardware token. It follows MeasurePointModeSetting in being a package
// variable rather than another parameter on every command signature.
var PINFileSetting string
