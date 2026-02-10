package cmd

const (
	// DefaultKeysDir is the directory where tpm2-kira stores its signing keys.
	DefaultKeysDir = "/var/lib/tpm2-kira/keys"

	// DefaultPublicKeyPath is the default path for the signing public key.
	DefaultPublicKeyPath = DefaultKeysDir + "/seal.pub"

	// DefaultPrivateKeyPath is the default path for the signing private key.
	DefaultPrivateKeyPath = DefaultKeysDir + "/seal.key"
)
