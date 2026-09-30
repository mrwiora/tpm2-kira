# Code layout

Where things live, and the rule that decides it — so a new file has an obvious
home.

---

## The tree

`main.go` parses flags and dispatches; everything else is under `internal/`, so
none of it is importable from outside this module.

The split inside `internal/` is by **subsystem boundary**, not by layer:

- `pcsc`, `piv` and `virtualpiv` are self-contained — a wire protocol, a card
  applet, and a simulator for them. They define their own vocabulary, talk to
  nothing else in the project, and are unit-testable on their own. That is what
  earns a separate package.
- `kira` is the application: the verbs and the mechanism they drive. These stay
  together because they share one vocabulary — PCR specs, the blob, TPM handles —
  and because output is interleaved with logic throughout. Splitting them by
  layer would mean either a shared types package or extracting printing from
  nearly every file, and would buy less than it cost.

Within `kira`, files are named after the verb they implement (`seal.go`,
`reseal.go`) or the subject they own (`blob.go`, `pcr.go`), and a subsystem with
several files shares a prefix (`signer*.go`).

```
├── main.go                  # CLI entrypoint: flag parsing and dispatch
├── internal/
│   ├── kira/                # The application. One package, because the verbs
│   │   │                    #   and the mechanism share one vocabulary (PCR
│   │   │                    #   specs, blob, TPM handles) and splitting it
│   │   │                    #   would mean a shared types package.
│   │   ├── setup.go         #   verb: create the signing key
│   │   ├── seal.go          #   verb: seal a TOTP secret
│   │   ├── sealadvice.go    #   verb: suggest PCRs and a slot for this machine
│   │   ├── reseal.go        #   verb: re-seal against current PCR values
│   │   ├── scan.go          #   verb: reveal / run, multi-slot scanning
│   │   ├── info.go          #   verb: inspect sealed blob metadata
│   │   ├── nvram.go         #   verb: NVRAM define/read/write/delete
│   │   ├── restore.go       #   verb: write a stashed blob back to NVRAM
│   │   ├── yubikey.go       #   verb: yubikey list/adopt/status/export-pubkey
│   │   ├── signer.go        # key references and the SigningKey abstraction
│   │   ├── signer_pin.go    #   PIN resolution for a token-held key
│   │   ├── signer_yubikey.go#   the PIV slot backend and token discovery
│   │   ├── blob.go          # sealed blob serialisation (format version 9)
│   │   ├── policy_or.go     # PolicyOR / PolicySigned digests and unsealing
│   │   ├── pcr.go           # PCR vocabulary: specs, sources, hash algorithm
│   │   ├── pcrwarn.go       #   warnings for selections that attest little
│   │   ├── pcrtips.go       #   the PCR reference guide
│   │   ├── eventlog_utils.go#   replaying the firmware event log
│   │   ├── measurepoint.go  #   userspace extends before tpm2-kira reads PCRs
│   │   ├── ukipredict.go    #   native PCR 11 computation from a UKI
│   │   ├── tpm_utils.go     # low-level TPM operations
│   │   ├── privilege.go     # root checks and key-permission warnings
│   │   ├── prompt.go        # terminal input shared by every prompt
│   │   ├── totp_utils.go    # TOTP generation and display
│   │   └── constants.go     # default paths and constants
│   ├── pcsc/                # cgo-free pcscd client (Unix socket protocol)
│   ├── piv/                 # PIV applet: read a slot, verify a PIN, sign
│   └── virtualpiv/          # Virtual YubiKey for tests (never in the binary)
├── test/
│   ├── integration/         # CLI tests driving the built binary (build-tagged)
│   └── docker/              # Container with swtpm, pcscd and a virtual reader
├── tools/
│   ├── pcrtool.py            # PCR replay and full-chain diagnosis
│   └── tpm2-pcr11predict     # Independent cross-check of the built-in PCR 11 computation
├── docs/
│   ├── YUBIKEY.md                # Signing key on a YubiKey PIV slot
│   ├── PLATFORM-OBSERVATIONS.md  # Measured facts about Arch and Debian boots
│   ├── pentest1/, pentest2/      # Security review findings and mitigations
│   └── *.issue                   # Write-ups of specific bugs
├── initramfs/               # Everything that goes into, or builds, an initramfs
│   ├── systemd/tpm2-kira.service   # Unit, pulled into systemd-based images
│   ├── mkinitcpio/                 # Arch
│   │   ├── install/sd-tpm2-kira    # Build hook: puts the binary in the image
│   │   ├── post/sd-tpm2-kira       # Reseal after the image is written
│   │   └── mkinitcpio.conf.example
│   └── initramfs-tools/            # Debian
│       ├── hooks/tpm2-kira         # Build hook: copies the static binary
│       ├── scripts/init-premount/tpm2-kira  # Shows the code before unlock
│       ├── scripts/init-bottom/tpm2-kira    # Stops it before switching root
│       ├── post-update.d/tpm2-kira          # Reseal reminder
│       └── initramfs.conf          # Display mode (run / once)
├── debian/                  # Debian package definition (must sit at the root)
├── packaging/
│   ├── aur/                 # Arch Linux PKGBUILD
│   └── deb-version.sh       # git describe -> a Debian-valid version
└── Makefile
```
