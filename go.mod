module github.com/tpm2-trust/tpm2-kira

go 1.26.0

require (
	github.com/google/go-attestation v0.6.4
	github.com/google/go-tpm v0.9.9-0.20261030171821-c395998989d7
	github.com/tpm2-trust/tpm2-kira/core v0.0.0
	github.com/tpm2-trust/assh v0.0.0
	github.com/tpm2-trust/go-uefi-slim v0.0.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	rsc.io/qr v0.2.0
)

require (
	github.com/tpm2-trust/tpm2-verifier v0.0.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
)

replace github.com/tpm2-trust/assh => ./assh

// The shared core (attest, transport, vaultproto, mobile): a module of its
// own, which the vault and Marify require alone; here its checkout.
replace github.com/tpm2-trust/tpm2-kira/core => ./core

// The core's EK root store, tpm2-verifier: its submodule (a replace of a
// dependency does not reach its users).
replace github.com/tpm2-trust/tpm2-verifier => ./tpm2-verifier

// EFI variables and Secure Boot: the workspace's go-uefi-slim module, its
// submodule (aSSH's replace of it does not reach here).
replace github.com/tpm2-trust/go-uefi-slim => ./go-uefi-slim
