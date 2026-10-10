package cmd

const (
	// DefaultKeysDir is the directory where tpm2-kira stores its signing keys:
	// under /etc, where systemd keeps its own key material (systemd-cryptenroll,
	// systemd-measure: /etc/systemd/tpm2-pcr-*), not under /var/lib.
	DefaultKeysDir = "/etc/tpm2-kira/keys"

	// DefaultPublicKeyPath is the default path for the signing public key.
	DefaultPublicKeyPath = DefaultKeysDir + "/seal.pub"

	// DefaultPrivateKeyPath is the default path for the signing private key.
	DefaultPrivateKeyPath = DefaultKeysDir + "/seal.key"
)
