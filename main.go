package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/matthias/tpm2-kira/internal/kira"
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

	// Exit 0 deliberately: tpm2-kira is meant to be chainable in a boot
	// sequence, so a TPM or NVRAM problem must not stop the commands after it.
	// Callers judge success from the output, not the status — see the "Exit
	// status" section of the README.
	os.Exit(0)
}

func main() {
	// Set application version in cmd package
	kira.AppVersion = Version

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

	// Named so that a privilege message can show a command worth re-running.
	kira.InvokedCommand = command

	// Commands that write under /var/lib need root whatever their TPM path is.
	// The TPM itself is checked at the moment it is opened, because whether
	// root is needed depends on the device rather than on the command.
	if err := kira.CheckPrivilege(command, commandArgs); err != nil {
		fail(err)
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
	case "yubikey":
		runYubiKey(commandArgs, *tpmPath, *debug)
	case "reveal":
		runReveal(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "reveal-plain":
		runRevealPlain(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "run":
		runRun(commandArgs, *tpmPath, uint32(*nvramIndex), *debug)
	case "pcrtips":
		if err := kira.PCRTips(); err != nil {
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
	return kira.ResolveNVRAMIndex(rawValue)
}

func runSetup(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")
	yubikey := fs.String("yubikey", "", "Use a YubiKey PIV slot for the signing key, e.g. 'yubikey:slot=9a' or just 'yubikey:'")
	local := fs.Bool("local", false, "Use a signing key file without asking about a token")

	fs.Parse(args)
	rejectPositional(fs, "setup")

	choice := kira.SetupKeyChoice{Local: *local, TokenRef: *yubikey}
	if choice.Local && choice.TokenRef != "" {
		fail(fmt.Errorf("--local and --yubikey ask for opposite things; pick one"))
	}

	if err := kira.Setup(*tpm, choice, *debug); err != nil {
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
	pubKeyPath := fs.String("pubkey", kira.DefaultPublicKeyPath, "Path to signing public key PEM (X.509 certificate or raw public key)")
	privKeyPath := fs.String("privkey", kira.DefaultPrivateKeyPath, "Signing private key: a PEM path, or a YubiKey slot such as yubikey:serial=12345678;slot=9a")
	pinFile := fs.String("pin-file", "", "File holding the YubiKey PIN (mode 0600); alternative to $TPM2_KIRA_PIN")
	measurePoint := fs.String("measure-point", "auto", "Account for systemd's userspace PCR extends before tpm2-kira runs (auto, on, off)")
	verifyUKI := fs.Bool("verify-uki", true, "Check the built-in PCR 11 computation against this boot's event log before sealing")

	fs.Parse(args)
	rejectPositional(fs, "seal")

	kira.PINFileSetting = *pinFile

	given := flagsGiven(fs)

	mode, err := kira.ParseMeasurePointMode(*measurePoint)
	if err != nil {
		fail(err)
	}
	kira.MeasurePointModeSetting = mode

	hashAlgo := kira.PCRHashAlgoSHA256
	if *useSHA1 {
		hashAlgo = kira.PCRHashAlgoSHA1
	}

	sealIndex := kira.ResolveNVRAMIndex(uint32(*nvram))

	// Choosing PCRs needs to know about this machine, so an unqualified
	// "tpm2-kira seal" explains what it found and suggests a selection. An
	// explicit --pcrs is used exactly as written — the person typing it may
	// know something this code does not — and a hook or script, which has
	// nobody to answer, gets the documented default silently.
	if !given["pcrs"] && kira.IsInteractive() {
		plan, planErr := kira.GuideSealSelection(*tpm, sealIndex, given["nvram"], *debug)
		if planErr != nil {
			fail(planErr)
		}
		if !plan.Proceed {
			return
		}
		*pcrs = plan.PCRs
		sealIndex = plan.Index
	}

	// Validate PCR specs before proceeding
	if _, err := kira.ParsePCRSpecs(*pcrs); err != nil {
		fail(err)
	}

	if err := kira.Seal(*tpm, *pcrs, sealIndex, *pubKeyPath, *privKeyPath, *debug, hashAlgo, *verifyUKI); err != nil {
		fail(err)
	}
}

// rejectPositional stops a command that was given arguments it does not take.
// The message is built in the kira package, where it can be tested.
func rejectPositional(fs *flag.FlagSet, command string) {
	if fs.NArg() > 0 {
		fail(kira.PositionalArgError(command, fs.Args()))
	}
}

// flagsGiven reports which flags were named on the command line, as opposed to
// left at their default. A default is a fallback; a flag someone typed is an
// instruction, and the two deserve different treatment.
func flagsGiven(fs *flag.FlagSet) map[string]bool {
	given := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	return given
}

func runReseal(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reseal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", "", "PCR indices to use for policy (if not specified, preserves original selection)")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")
	pubKeyPath := fs.String("pubkey", "", "Path to signing public key PEM (default: derived from --privkey, or preserved from blob)")
	privKeyPath := fs.String("privkey", "", "Signing private key: a PEM path, or a YubiKey slot such as yubikey:serial=12345678;slot=9a")
	pinFile := fs.String("pin-file", "", "File holding the YubiKey PIN (mode 0600); alternative to $TPM2_KIRA_PIN")
	requireKey := fs.Bool("require-key", false, "Fail instead of warning when the signing key is unavailable")
	measurePoint := fs.String("measure-point", "auto", "Account for systemd's userspace PCR extends before tpm2-kira runs (auto, on, off)")

	fs.Parse(args)
	rejectPositional(fs, "reseal")

	kira.PINFileSetting = *pinFile
	kira.RequireKeySetting = *requireKey

	mode, err := kira.ParseMeasurePointMode(*measurePoint)
	if err != nil {
		fail(err)
	}
	kira.MeasurePointModeSetting = mode

	// Validate PCR specs before proceeding (only if explicitly provided)
	if *pcrs != "" {
		if _, err := kira.ParsePCRSpecs(*pcrs); err != nil {
			fail(err)
		}
	}

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	if err := kira.ResealCommand(*tpm, scanIndex, *pcrs, *pubKeyPath, *privKeyPath, *debug); err != nil {
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
	rejectPositional(fs, "info")

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	if err := kira.InfoCommand(*tpm, scanIndex, *debug, *jsonOutput); err != nil {
		fail(err)
	}
}

func runReveal(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)
	rejectPositional(fs, "reveal")

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	kira.RevealCommand(*tpm, scanIndex, *debug, false)
}

func runRevealPlain(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal-plain", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)
	rejectPositional(fs, "reveal-plain")

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	kira.RevealCommand(*tpm, scanIndex, *debug, true)
}

func runRun(args []string, tpmPath string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)
	rejectPositional(fs, "run")

	scanIndex := resolveOrScanAll(uint32(*nvram), nvramExplicit(args))

	kira.RunCommand(*tpm, scanIndex, *debug)
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
	from := fs.String("from", "", "restore: stashed blob to write back (default: the newest for this slot)")
	privKey := fs.String("privkey", "", "restore: signing key, if not the one recorded in the blob")
	pinFile := fs.String("pin-file", "", "restore: file holding the YubiKey PIN (mode 0600)")
	force := fs.Bool("force", false, "restore: overwrite a different blob already in the index")
	all := fs.Bool("all", false, "delete: every populated slot, not just one")

	fs.Parse(args)
	rejectPositional(fs, "nvram "+subcommand)

	kira.PINFileSetting = *pinFile

	provided := nvramExplicit(args)

	switch subcommand {
	case "list":
		listIndex := kira.ResolveNVRAMIndex(uint32(*nvram))
		if err := kira.NVRAMList(*tpm, listIndex, *debug); err != nil {
			fail(err)
		}
	case "status":
		statusIndex := kira.ResolveNVRAMIndex(uint32(*nvram))
		if err := kira.NVRAMStatus(*tpm, statusIndex, *debug); err != nil {
			fail(err)
		}
	case "delete":
		// Deleting a sealed secret cannot be undone: the TOTP secret is gone
		// and the authenticator has to be re-enrolled. Wiping every slot is
		// therefore something to ask for rather than the default when --nvram
		// happens to be missing.
		if !provided && !*all {
			fail(errors.New("'tpm2-kira nvram delete' needs to know what to delete.\n" +
				"  One slot:    tpm2-kira nvram delete --nvram 0\n" +
				"  Every slot:  tpm2-kira nvram delete --all\n" +
				"  Deleting a sealed secret cannot be undone — the TOTP secret is gone and\n" +
				"  the authenticator has to be re-enrolled, so --all is not the default."))
		}
		if provided && *all {
			fail(errors.New("--nvram names one slot and --all means every slot; pick one"))
		}

		deleteIndex := resolveOrScanAll(uint32(*nvram), provided)
		if err := kira.NVRAMDeleteCommand(*tpm, deleteIndex, *debug); err != nil {
			fail(err)
		}
	case "restore":
		// Restoring writes one specific index, so there is nothing sensible
		// to scan for: require it.
		if !provided {
			fail(fmt.Errorf("nvram restore needs --nvram to say which index to write"))
		}
		restoreIndex := kira.ResolveNVRAMIndex(uint32(*nvram))
		if err := kira.NVRAMRestore(*tpm, restoreIndex, *from, *privKey, *force, *debug); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("unknown nvram subcommand %q", subcommand))
	}
}

// runYubiKey handles the read-only token subcommands. tpm2-kira never writes
// to a token; populating a slot is done with ykman.
func runYubiKey(args []string, tpmPath string, debugFlag bool) {
	if len(args) == 0 {
		fail(fmt.Errorf("yubikey requires a subcommand (list, adopt, status, export-pubkey)"))
	}

	subcommand := args[0]

	fs := flag.NewFlagSet("yubikey", flag.ExitOnError)
	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	ref := fs.String("key", "", "Key reference, e.g. yubikey:serial=12345678;slot=9a")
	out := fs.String("out", "", "Where to write the public key PEM")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args[1:])
	rejectPositional(fs, "yubikey "+subcommand)

	if err := kira.YubiKeyCommand(*tpm, []string{subcommand}, *ref, *out, *debug); err != nil {
		fail(err)
	}
}

func printUsage() {
	fmt.Printf(`tpm2-kira - TPM2-based TOTP authenticator with PCR policies

USAGE:
  tpm2-kira <command> [options]

COMMANDS:
  setup       Create the signing keys. Does NOT seal — run 'seal' next.
  seal        Generate and seal TOTP secret to TPM NVRAM. Run without --pcrs
              on a terminal and it suggests a selection for this machine.
  reseal      Reseal secret with current PCR values (requires signing key)
  reveal      Generate TOTP code with colored KIRA format
  reveal-plain Generate TOTP code (plain output)
  run         Continuously display TOTP codes (runs until stopped)
  info        Display sealed secret information
  nvram       Manage TPM NVRAM (list, status, delete, restore)
  yubikey     Inspect a YubiKey PIV signing key (list, adopt, status,
              export-pubkey). Read-only: tpm2-kira never writes to a token.
  pcrtips     Show PCR (Platform Configuration Register) reference guide
  version     Show version information
  help        Show this help message

ENVIRONMENT:
  TPM2_KIRA_PIN   PIN for a signing key held in a YubiKey PIV slot. Only read
                  when the key reference names a token.

GLOBAL OPTIONS:
  --tpm PATH      Path to TPM device (default: /dev/tpm0)
  --nvram INDEX   NVRAM slot number or full index in hex
                  Slot shorthand: 0-15 maps to 0x01803010-0x0180301F
                  Full index:     any hex value like 0x01803010
                  When omitted, commands automatically discover and operate on
                  all populated slots in the default range.
  --debug         Enable debug output

SETUP OPTIONS:
  setup only prepares the signing key; it never writes to TPM NVRAM and never
  needs a PIN. Run 'tpm2-kira seal' afterwards to create the TOTP secret.

  --yubikey [REF]    Put the signing key on a YubiKey PIV slot instead of in a
                     file. With no reference, the first token found is used.
                     Without this flag, setup offers any connected token when
                     run from a terminal, and defaults to a key file.
  --local            Use a key file without asking about a token. This is what
                     setup does anyway when it is not run from a terminal.

SEAL OPTIONS:
  Run 'tpm2-kira seal' with no --pcrs from a terminal and it reports what it
  found on this machine — Secure Boot state, event log, unified kernel image,
  bootloader — suggests a selection to match, names the risks, and offers a free
  NVRAM slot. Passing --pcrs skips all of it and uses exactly what you asked for.

  --pcrs INDICES     PCR indices with optional source suffix (default: 0,2,7
                     when not asked interactively)
                     Suffix 'r' = read from TPM registers (default if no suffix)
                     Suffix 'e' = calculate from TPM eventlog (PCRs 0-12 only)
                     Suffix 'u[:PATH]' = compute from a unified kernel image (PCR 11 only)
                       Replays systemd-stub's section measurements internally
                     Examples: "0,2,7" (all register), "0e,2e,7e" (all eventlog),
                               "0e,2,7e" (mixed: 0 and 7 from eventlog, 2 from register)
                               "0e,2e,7e,11u" (eventlog + UKI-computed PCR 11)
  --measure-point M  Account for systemd's userspace PCR extends that happen
                     before tpm2-kira runs: auto (default), on, off
  --pubkey PATH      Path to signing public key PEM for PolicySigned branch
                     (default: %s)
                     Accepts X.509 certificates or raw public keys (RSA, ECDSA)
  --privkey REF      Signing private key, stored in the blob so reseal can find
                     it automatically. Either a path to a PEM file (the default)
                     or a YubiKey PIV slot:
                       /var/lib/tpm2-kira/keys/seal.key
                       yubikey:serial=12345678;slot=9a
  --pin-file PATH    File holding the YubiKey PIN, mode 0600.
  --require-key      Fail instead of warning when the signing key is not
                     available. Without it, a reseal that cannot reach the key
                     prints a SKIPPED warning, changes nothing, and the next
                     boot shows a PCR mismatch. Alternative to
                     the TPM2_KIRA_PIN environment variable.
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
  --privkey REF      Signing private key: a PEM path or a yubikey: reference.
                     Required for every reseal, because the NV write policy is
                     PolicySigned. The TPM verifies the signature.
                     Also used to derive the public key when --pubkey is omitted.
  --pin-file PATH    File holding the YubiKey PIN, mode 0600.

INFO OPTIONS:
  --json             Output as JSON

NVRAM SUBCOMMANDS:
  list               List all NVRAM indices
  status             Show NVRAM index status
  delete             Delete NVRAM index (or all populated slots when --nvram is omitted)

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
  tpm2-kira nvram delete --nvram 0
  tpm2-kira nvram delete --nvram 0x01803010
  tpm2-kira nvram delete --all
  tpm2-kira nvram restore --nvram 0
  tpm2-kira nvram restore --nvram 0 --from /var/lib/tpm2-kira/recovery/slot-0x01803010-1700000000.blob

For detailed documentation, see README.md
`, kira.DefaultPublicKeyPath)
}
