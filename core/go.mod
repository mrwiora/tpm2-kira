module github.com/mrwiora/tpm2-kira/core

go 1.26.0

require (
	github.com/google/go-tpm v0.9.9-0.20261001171150-36f205946d7e
	github.com/tpm2-trust/tpm2-verifier v0.0.0
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
)

require go.yaml.in/yaml/v3 v3.0.4 // indirect

// The EK root store (tpm2-verifier's ekroots): the submodule tpm2-verifier/
// beside this module, the commit tpm2-kira pins (the workspace's
// ./pin tpm2-verifier moves it).
replace github.com/tpm2-trust/tpm2-verifier => ../tpm2-verifier
