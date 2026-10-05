# EK certificate trust anchors

The phone app decides whether a machine's TPM is genuine hardware: at
enrolment the core (`../ekcert.go`, compiled into the app) checks the TPM's
endorsement key certificate against the roots in this directory. The machine
only *sends* its certificate and intermediates; a compromised machine could
claim anything it checked itself.

Everything here is embedded at build time. Nothing can be added on the phone
at runtime: a trust anchor someone could slip onto the phone would let a
software TPM pass as genuine.

## Layout

```
vendors.json          one entry per vendor: name, sources, pinned SHA-256 of every file
<vendor>/root*.der    trust anchors (self-signed roots)
<vendor>/*.der        intermediates the TPM does not carry itself (helpers, never anchors)
```

The core loads `vendors.json` once and checks every file against its pinned
SHA-256; a vendor with a missing or changed file is ignored (its TPMs show as
"not verified"). Tests fail on any file that is not pinned, on any pin that
does not match, and on certificates that do not parse.

## Adding a vendor

1. Get the root (and any intermediates the TPM does not store) from **two
   independent sources**, at least one of them the vendor's own site over
   HTTPS. Compare the bytes; they must be identical.
2. Put them in a new directory, DER encoded:
   `mkdir <vendor>; cp root.der intermediate.der <vendor>/`
3. Add an entry to `vendors.json` with `name` (shown to the user: "TPM
   verified as genuine: <name>"), `sources`, `verified` (date and how), and
   `roots` / `intermediates` with `file`, `subject` and
   `sha256` (`sha256sum <vendor>/*.der`).
4. If the vendor's TPMs store intermediates in NV, make sure the machine
   sends them (`readEKCertChain` in `cmd/attest_tpm.go`; Intel uses
   `0x01C00100`).
5. `go test ./attest/` — then check a real TPM of that vendor with
   `sudo tpm2-kira attest ekcert`.
6. Rebuild the app's core (`android/scripts/build-core.sh` in the app
   repository, after updating its pinned commit). Until then the app still
   carries the old list.

Removing a vendor or a root works the same way; enrolled machines keep the
result recorded at enrolment (`ek_verified_by`).
