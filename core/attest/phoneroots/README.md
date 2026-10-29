# Android key attestation roots

The machine checks the phone's key attestation (its keystore key is in
hardware, its boot state locked) against the roots in this directory.
Everything here is embedded at build time; nothing can be added at runtime.

The TPM vendors' EK roots are not here: they are tpm2-verifier's EK root
store (`github.com/tpm2-trust/tpm2-verifier/ekroots`, its `ekroots/vendors/`),
curated and signed there for every project.

## Layout

```
vendors.json          one entry per vendor: name, sources, pinned SHA-256 of every file
<vendor>/root*.der    trust anchors (self-signed roots)
<vendor>/*.der        intermediates (helpers, never anchors)
```

The core loads `vendors.json` once and checks every file against its pinned
SHA-256; a vendor with a missing or changed file is ignored. Tests fail on
any file that is not pinned, on any pin that does not match, and on
certificates that do not parse.

## Adding a root

1. Get it from **two independent sources**, at least one of them the
   vendor's own site over HTTPS. Compare the bytes; they must be identical.
2. Put it in the vendor's directory, DER encoded.
3. Add it to `vendors.json` with `file`, `subject` and `sha256`
   (`sha256sum <vendor>/*.der`), and the vendor's `sources` and `verified`.
4. `go test ./attest/` in `core/`.
