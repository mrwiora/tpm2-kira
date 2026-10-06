package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/matthias/tpm2-kira/cmd"
)

// Version is the application version, set by build flags
// Default is "dev" for development builds
var Version = "dev"

// fail reports a command failure and exits 0 on purpose: tpm2-kira is meant to
// be chainable (`tpm2-kira && cryptsetup ...`), so a TPM or read failure must
// not stop the commands after it. Scripts must therefore detect failure from
// the output, not the exit status — grep for the FAILED marker below.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "tpm2-kira: FAILED: %v\n", err)
	fmt.Fprintln(os.Stderr, "tpm2-kira: (exit status is 0 by design; this command did NOT succeed)")
	os.Exit(0)
}

func main() {
	// Set application version in cmd package
	cmd.AppVersion = Version

	// Global flags (shared across all commands)
	globalFlags := flag.NewFlagSet("global", flag.ExitOnError)
	tpmPath := globalFlags.String("tpm", "/dev/tpm0", "Path to TPM device")
	nvramIndex := globalFlags.Uint("nvram", 0x01803010, "TPM NVRAM index to use for storage")
	debug := globalFlags.Bool("debug", false, "Enable debug output")

	// Default to 'reveal' command if no arguments provided
	command := "reveal"
	argsOffset := 1
	if len(os.Args) >= 2 {
		command = os.Args[1]
		argsOffset = 2
	}

	var commandArgs []string
	if len(os.Args) >= argsOffset {
		commandArgs = os.Args[argsOffset:]
	}

	switch command {
	case "setup":
		runSetup(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "seal":
		runSeal(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "reseal":
		runReseal(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "info":
		runInfo(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "nvram":
		runNVRAM(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "reveal":
		runReveal(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "reveal-plain":
		runRevealPlain(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "run":
		runRun(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "attest":
		runAttest(commandArgs, *tpmPath, *debug)
	case "pcrtips":
		if err := cmd.PCRTips(); err != nil {
			fail(err)
		}
	case "version", "-v", "--version":
		fmt.Printf("tpm2-kira version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		fail(fmt.Errorf("unknown command %q", command))
	}
}

// nvramExplicit checks whether --nvram (or -nvram) appears in the argument
// list.  This lets us distinguish "flag absent" from "flag set to default".
func nvramExplicit(args []string) bool {
	for _, arg := range args {
		if arg == "--nvram" || arg == "-nvram" {
			return true
		}
	}
	return false
}

// resolveOrScanAll returns the resolved NVRAM index when the user supplied
// --nvram explicitly, or 0 (the "scan all slots" sentinel) when they did not.
func resolveOrScanAll(rawValue uint32, provided bool) uint32 {
	if !provided {
		return 0 // scan all slots
	}
	return cmd.ResolveNVRAMIndex(rawValue)
}

func runSetup(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	sealIndex := cmd.ResolveNVRAMIndex(uint32(*nvram))

	if err := cmd.Setup(*tpm, sealIndex, *debug); err != nil {
		fail(err)
	}
}

func runSeal(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", "0,2,7", "PCR indices to use for policy")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")
	useSHA1 := fs.Bool("sha1", false, "Use SHA-1 PCR bank instead of SHA-256 (use only if firmware does not support SHA-256 eventlog)")
	pubKeyPath := fs.String("pubkey", cmd.DefaultPublicKeyPath, "Path to signing public key PEM (X.509 certificate or raw public key)")
	privKeyPath := fs.String("privkey", cmd.DefaultPrivateKeyPath, "Path to signing private key PEM (stored in blob for reseal convenience)")
	measurePoint := fs.String("measure-point", "auto", "Account for systemd's userspace PCR extends before tpm2-kira runs (auto, on, off)")
	verifyUKI := fs.Bool("verify-uki", true, "Check the built-in PCR 11 computation against this boot's event log before sealing")

	fs.Parse(args)

	mode, err := cmd.ParseMeasurePointMode(*measurePoint)
	if err != nil {
		fail(err)
	}
	cmd.MeasurePointModeSetting = mode

	// Validate PCR specs before proceeding
	if _, err := cmd.ParsePCRSpecs(*pcrs); err != nil {
		fail(err)
	}

	hashAlgo := cmd.PCRHashAlgoSHA256
	if *useSHA1 {
		hashAlgo = cmd.PCRHashAlgoSHA1
	}

	sealIndex := cmd.ResolveNVRAMIndex(uint32(*nvram))

	if err := cmd.Seal(*tpm, *pcrs, sealIndex, *pubKeyPath, *privKeyPath, *debug, hashAlgo, *verifyUKI); err != nil {
		fail(err)
	}
}

func runReseal(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reseal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", "", "PCR indices to use for policy (if not specified, preserves original selection)")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")
	pubKeyPath := fs.String("pubkey", "", "Path to signing public key PEM (default: derived from --privkey, or preserved from blob)")
	privKeyPath := fs.String("privkey", "", "Path to signing private key PEM (required when PCR values have changed)")
	measurePoint := fs.String("measure-point", "auto", "Account for systemd's userspace PCR extends before tpm2-kira runs (auto, on, off)")

	fs.Parse(args)

	mode, err := cmd.ParseMeasurePointMode(*measurePoint)
	if err != nil {
		fail(err)
	}
	cmd.MeasurePointModeSetting = mode

	// Validate PCR specs before proceeding (only if explicitly provided)
	if *pcrs != "" {
		if _, err := cmd.ParsePCRSpecs(*pcrs); err != nil {
			fail(err)
		}
	}

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	if err := cmd.ResealCommand(*tpm, scanIndex, *pcrs, *pubKeyPath, *privKeyPath, *debug); err != nil {
		fail(err)
	}
}

func runInfo(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Parse(args)

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	if err := cmd.InfoCommand(*tpm, scanIndex, *debug, *jsonOutput); err != nil {
		fail(err)
	}
}

func runReveal(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	cmd.RevealCommand(*tpm, scanIndex, *debug, false)
}

func runRevealPlain(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal-plain", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	cmd.RevealCommand(*tpm, scanIndex, *debug, true)
}

func runRun(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	cmd.RunCommand(*tpm, scanIndex, *debug)
}

func runNVRAM(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	if len(args) == 0 {
		fail(fmt.Errorf("nvram command requires a subcommand (list, status, delete)"))
	}

	subcommand := args[0]
	args = args[1:]

	fs := flag.NewFlagSet("nvram", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	provided := nvramExplicit(args)

	switch subcommand {
	case "list":
		listIndex := cmd.ResolveNVRAMIndex(uint32(*nvram))
		if err := cmd.NVRAMList(*tpm, listIndex, *debug); err != nil {
			fail(err)
		}
	case "status":
		statusIndex := cmd.ResolveNVRAMIndex(uint32(*nvram))
		if err := cmd.NVRAMStatus(*tpm, statusIndex, *debug); err != nil {
			fail(err)
		}
	case "delete":
		deleteIndex := resolveOrScanAll(uint32(*nvram), provided)
		if err := cmd.NVRAMDeleteCommand(*tpm, deleteIndex, *debug); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unknown nvram subcommand %q", subcommand))
	}
}

// failAttest reports a failure of an attest command that gates or judges
// something. These are the documented exceptions to the exit-0 rule
// (PLAN-REMOTEATTESTATION.md §12.1): a gate that exits 0 on failure is not a
// gate, and a verifier that exits 0 on a failed check is not a verifier.
func failAttest(code int, err error) {
	fmt.Fprintf(os.Stderr, "tpm2-kira: FAILED: %v\n", err)
	os.Exit(code)
}

func runAttest(args []string, tpmPath string, debugFlag bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "attest requires a subcommand: enrol, gate, status, check, ekcert, quote, verify, unenrol")
		os.Exit(cmd.ExitUsage)
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("attest "+sub, flag.ExitOnError)
	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", 0, "Slot (0-15) or sealed-blob NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	switch sub {
	case "enrol", "enroll":
		name := fs.String("name", "", "Name shown on the phone (default: hostname)")
		pcrs := fs.String("pcrs", "", "PCRs to quote (default: the slot's sealed selection, else 0,2,4,7)")
		adapter := fs.Int("adapter", 0, "Bluetooth adapter index (hciN)")
		privKey := fs.String("privkey", "", "Signing key for the attestation blob (default: the slot's, else "+cmd.DefaultPrivateKeyPath+")")
		timeout := fs.Duration("timeout", 10*time.Minute, "Give up after this long (0 = wait forever)")
		verifyTPM := fs.String("verify-tpm", "warn", "If this machine's TPM is not verified as genuine: warn (ask), require (refuse) or off")
		verifyPhone := fs.String("verify-phone", "warn", "If the phone's key is not attested by genuine secure hardware: warn (ask), require (refuse) or off")
		fs.Parse(args)
		vt, err := cmd.ParseHWCheckPolicy(*verifyTPM)
		if err != nil {
			failAttest(cmd.ExitUsage, err)
		}
		vp, err := cmd.ParseHWCheckPolicy(*verifyPhone)
		if err != nil {
			failAttest(cmd.ExitUsage, err)
		}
		err = cmd.AttestEnrol(cmd.EnrolOptions{
			TPMPath: *tpm, SealIndex: uint32(*nvram), Name: *name, PCRs: *pcrs,
			Adapter: *adapter, PrivKeyPath: *privKey, Timeout: *timeout, Debug: *debug,
			VerifyTPM: vt, VerifyPhone: vp,
		})
		if err != nil {
			failAttest(cmd.ExitInternal, err)
		}
	case "gate":
		configPath := fs.String("config", cmd.DefaultAttestConfigPath, "Attestation config (adapter, timeouts)")
		adapter := fs.Int("adapter", -1, "Bluetooth adapter index (hciN); default from the config, else 0")
		timeout := fs.Duration("timeout", -1, "Give up after this long (0 = wait forever); default from the config")
		adapterWait := fs.Duration("adapter-wait", -1, "Wait this long for the adapter to appear; default from the config, else 30s")
		mode := fs.String("mode", "lazy", "Gate mode; only 'lazy' is implemented")
		fs.Parse(args)
		if *mode != "lazy" {
			failAttest(cmd.ExitUsage, fmt.Errorf("mode %q is not implemented; only 'lazy' is available", *mode))
		}
		cfg, err := cmd.LoadAttestConfig(*configPath)
		if err != nil {
			failAttest(cmd.ExitUsage, err)
		}
		if *adapter >= 0 {
			cfg.Adapter = *adapter
		}
		if *timeout >= 0 {
			cfg.Timeout = *timeout
		}
		if *adapterWait >= 0 {
			cfg.AdapterWait = *adapterWait
		}
		var slot uint32
		if nvramExplicit(args) {
			slot = cmd.ResolveNVRAMIndex(uint32(*nvram))
		}
		os.Exit(cmd.AttestGate(cmd.GateOptions{
			TPMPath: *tpm, SealIndex: slot, Adapter: cfg.Adapter, Timeout: cfg.Timeout,
			AdapterWait: cfg.AdapterWait, Debug: *debug,
		}))
	case "initramfs-deps":
		// Used by the initramfs hooks; prints "module", "firmware" and
		// "warning" lines for the adapter on this machine.
		adapter := fs.Int("adapter", 0, "Bluetooth adapter index (hciN)")
		kernelLog := fs.String("kernel-log", "", "Extra kernel log text (e.g. 'journalctl -k -b -o cat' output)")
		fwDir := fs.String("firmware-dir", cmd.DefaultFirmwareDir, "Firmware directory")
		fs.Parse(args)
		os.Exit(cmd.AttestInitramfsDeps(*adapter, *kernelLog, *fwDir))
	case "status":
		jsonOut := fs.Bool("json", false, "Output as JSON")
		fs.Parse(args)
		var slot uint32
		if nvramExplicit(args) {
			slot = cmd.ResolveNVRAMIndex(uint32(*nvram))
		}
		if err := cmd.AttestStatus(*tpm, slot, *jsonOut, *debug); err != nil {
			fail(err)
		}
	case "quote":
		nonce := fs.String("nonce", "", "Hex nonce chosen by whoever will verify (16-64 bytes)")
		pcrs := fs.String("pcrs", "", "PCRs to quote (default: the enrolled selection)")
		out := fs.String("out", "", "Write evidence to this file (default: stdout)")
		fs.Parse(args)
		if err := cmd.AttestQuote(*tpm, uint32(*nvram), *nonce, *pcrs, *out, *debug); err != nil {
			failAttest(cmd.ExitInternal, err)
		}
	case "verify":
		evidence := fs.String("evidence", "", "Evidence file from 'attest quote'")
		record := fs.String("record", "", "Machine record JSON exported from a verifier")
		nonce := fs.String("nonce", "", "The nonce given to 'attest quote'")
		jsonOut := fs.Bool("json", false, "Output the verdict as JSON")
		fs.Parse(args)
		ok, err := cmd.AttestVerify(*evidence, *record, *nonce, *jsonOut)
		if err != nil {
			failAttest(cmd.ExitInternal, err)
		}
		if !ok {
			os.Exit(cmd.ExitRejected)
		}
	case "check":
		pubKey := fs.String("pubkey", "", "Signing public key (default: the slot's, else "+cmd.DefaultPublicKeyPath+")")
		stateDir := fs.String("state-dir", cmd.DefaultAttestStateDir, "Where the accepted blob of each slot is recorded")
		accept := fs.Bool("accept", false, "Record the current, validly signed blob as accepted")
		fs.Parse(args)
		var slot uint32
		if nvramExplicit(args) {
			slot = cmd.ResolveNVRAMIndex(uint32(*nvram))
		}
		os.Exit(cmd.AttestCheck(cmd.CheckOptions{
			TPMPath: *tpm, SealIndex: slot, PubKeyPath: *pubKey, StateDir: *stateDir, Accept: *accept, Debug: *debug,
		}))
	case "ekcert":
		fs.Parse(args)
		if err := cmd.AttestEKCert(*tpm, *debug); err != nil {
			fail(err)
		}
	case "unenrol", "unenroll":
		fs.Parse(args)
		if err := cmd.AttestUnenrol(*tpm, uint32(*nvram), *debug); err != nil {
			fail(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown attest subcommand %q\n", sub)
		os.Exit(cmd.ExitUsage)
	}
}

func printUsage() {
	fmt.Printf(`tpm2-kira - TPM2-based TOTP authenticator with PCR policies

USAGE:
  tpm2-kira <command> [options]

COMMANDS:
  setup       Initial setup: generate P-256 signing keys and seal (PCRs 0,7)
  seal        Generate and seal TOTP secret to TPM NVRAM
  reseal      Reseal secret with current PCR values (requires signing key)
  reveal      Generate TOTP code with colored KIRA format
  reveal-plain Generate TOTP code (plain output)
  run         Continuously display TOTP codes (runs until stopped)
  info        Display sealed secret information
  nvram       Manage TPM NVRAM (list, status, delete)
  attest      Remote attestation with a phone over Bluetooth LE (see ATTEST below)
  pcrtips     Show PCR (Platform Configuration Register) reference guide
  version     Show version information
  help        Show this help message

GLOBAL OPTIONS:
  --tpm PATH      Path to TPM device (default: /dev/tpm0)
  --nvram INDEX   NVRAM slot number or full index in hex
                  Slot shorthand: 0-15 maps to 0x01803010-0x0180301F
                  Full index:     any hex value like 0x01803010
                  When omitted, commands automatically discover and operate on
                  all populated slots in the default range.
  --debug         Enable debug output

SEAL OPTIONS:
  --pcrs INDICES     PCR indices with optional source suffix (default: 0,2,7)
                     Suffix 'r' = read from TPM registers (default if no suffix)
                     Suffix 'e' = calculate from TPM eventlog (PCRs 0-12 only)
                     Suffix 'u[:PATH]' = compute from a unified kernel image (PCR 11 only)
                       Replays systemd-stub's section measurements internally
                     Examples: "0,2,7" (all register), "0e,2e,7e" (all eventlog),
                               "0e,2,7e" (mixed: 0 and 7 from eventlog, 2 from register)
                               "0e,2e,7e,11u" (eventlog + UKI-computed PCR 11)
  --measure-point M  Account for systemd's enter-initrd extend of PCR 11, which
                     happens before tpm2-kira runs: auto (default), on, off.
                     PCRs 0-7, 9, 12-14 are always sealed to their values before
                     systemd-pcrosseparator.service (replayed from the event
                     log): the display runs before it, and the separator then
                     locks the secret until the next boot
  --pubkey PATH      Path to signing public key PEM for PolicySigned branch
                     (default: %s)
                     Accepts X.509 certificates or raw public keys (RSA, ECDSA)
  --privkey PATH     Path to signing private key PEM (optional)
                     Both key paths are stored in the blob so reseal can find
                     them automatically without requiring --pubkey / --privkey
  --sha1             Use SHA-1 PCR bank instead of SHA-256 (default: SHA-256)
                     Use only if firmware eventlog does not provide SHA-256 digests
  --verify-uki       Check the built-in PCR 11 computation against this boot's
                     event log before sealing (default: true)

RESEAL OPTIONS:
  --pcrs INDICES     New PCR indices with optional source suffix (optional,
                     preserves original selection and per-PCR sources if omitted)
  --measure-point M  Same as for seal: auto (default), on, off
  --pubkey PATH      Path to signing public key PEM for re-sealing (optional)
                     Default: derived from --privkey, or loaded from blob's
                     stored key path. Use this to change the signing key.
  --privkey PATH     Path to signing private key PEM (required when PCRs changed)
                     The TPM verifies the signature via PolicySigned.
                     Also used to derive the public key when --pubkey is omitted.

INFO OPTIONS:
  --json             Output as JSON

NVRAM SUBCOMMANDS:
  list               List all NVRAM indices
  status             Show NVRAM index status
  delete             Delete NVRAM index (or all populated slots when --nvram is omitted)

ATTEST SUBCOMMANDS:
  attest enrol    Bind a phone to this slot over BLE (booted system; needs the
                  signing key). Prints a 6-digit code to compare with the app.
                  --name STR --pcrs LIST --adapter N --privkey PATH --timeout DUR
                  --verify-tpm warn|require|off    this machine's TPM genuine (EK certificate)?
                  --verify-phone warn|require|off  the phone's key in genuine secure hardware
                                                   (Android key attestation, Google roots)?
  attest gate     Serve attestation requests until a phone returns a receipt.
                  Defaults from /etc/tpm2-kira/attest.conf; uses /dev/tpmrm0
                  when available so it can run beside the TOTP display.
                  --mode lazy --adapter N --timeout DUR --adapter-wait DUR
  attest status   Show enrolled phones per slot and whether the blob is signed
                  by this machine's signing key (--json); exits 1 if not
  attest check    Verify the attestation blobs on the booted system: signed by
                  this machine's key, and unchanged since tpm2-kira last wrote
                  or accepted them (exit 6 if not). Run after unlock by
                  tpm2-kira-attest-check.service. --pubkey PATH --accept
  attest ekcert   Show whether the phone will verify this TPM as genuine
                  (EK certificate chain against the vendor roots in the core)
  attest quote    Produce evidence without a phone (--nonce HEX --out FILE)
  attest verify   Judge evidence offline (--evidence FILE --record FILE --nonce HEX)
  attest unenrol  Remove a slot's attestation enrolment
  attest initramfs-deps  Modules and firmware the adapter needs (used by the
                  initramfs hooks)

  EXIT STATUS: unlike every other command, 'attest gate', 'attest verify',
  'attest quote' and 'attest enrol' exit non-zero on failure:
    0 attested   1 internal error   2 usage   3 no phone / no adapter
    4 rejected (do not type a passphrase before checking)   5 anchor mismatch
    6 (attest check) attestation blob replaced or changed

AUTHENTICATION:
  tpm2-kira uses TPM2 PolicyOR with two branches for access control:
    Branch 1 (PCR):    Direct PCR policy - succeeds when PCR values match
    Branch 2 (Signed): PolicySigned - requires signature from configured key

  The signing key defaults to a dedicated ECDSA P-256 pair created by 'setup'.
  Point --privkey at the sbctl secure boot DB key instead to reseal with the
  same key that signs your boot components.

  No password authentication is used. Recovery after PCR changes requires
  the signing private key.

SETUP OPTIONS:
  --tpm PATH      Path to TPM device (default: /dev/tpm0)
  --nvram INDEX   NVRAM slot number or full index (default: 0x01803010)
  --debug         Enable debug output

  Setup creates /var/lib/tpm2-kira/keys/ with a fresh ECDSA P-256 key pair
  (seal.pub + seal.key) and seals a TOTP secret using PCRs 0,7.
  If the keys directory already exists, setup aborts — further changes must
  be made manually via 'seal' or 'reseal'.

EXAMPLES:
  tpm2-kira setup
  tpm2-kira seal
  tpm2-kira seal --nvram 0
  tpm2-kira seal --pcrs "0e,2e,7e"
  tpm2-kira seal --pcrs "0e,2e,7e,11u"
  tpm2-kira seal --pubkey /path/to/my-key.pem
  tpm2-kira seal --sha1 --pcrs "0e,2e,7e"
  tpm2-kira seal --pcrs "0e,2,4,7e"
  tpm2-kira reveal
  tpm2-kira reveal --nvram 3
  tpm2-kira reveal-plain
  tpm2-kira run
  tpm2-kira reseal
  tpm2-kira reseal --nvram 0
  tpm2-kira reseal --pcrs "0e,2,4,7e"
  tpm2-kira reseal --privkey /path/to/my-key.key
  tpm2-kira info
  tpm2-kira info --nvram 0
  tpm2-kira info --nvram 0x01803010
  tpm2-kira nvram list
  tpm2-kira nvram delete
  tpm2-kira nvram delete --nvram 0
  tpm2-kira nvram delete --nvram 0x01803010

For detailed documentation, see README.md
`, cmd.DefaultPublicKeyPath)
}
