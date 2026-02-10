package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/matthias/tpm2-kira/cmd"
)

// Version is the application version, set by build flags
// Default is "dev" for development builds
var Version = "dev"

func main() {
	// Set application version in cmd package
	cmd.AppVersion = Version

	// Global flags
	globalFlags := flag.NewFlagSet("global", flag.ExitOnError)
	tpmPath := globalFlags.String("tpm", "/dev/tpm0", "Path to TPM device")
	pcrs := globalFlags.String("pcrs", "0,2,7", "PCR indices to use for policy (comma-separated)")
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
	case "seal":
		runSeal(commandArgs, *tpmPath, *pcrs, uint32(*nvramIndex), *debug)
	case "reseal":
		runReseal(commandArgs, *tpmPath, "", uint32(*nvramIndex), *debug)
	case "info":
		runInfo(commandArgs, *tpmPath, *pcrs, uint32(*nvramIndex), *debug)
	case "nvram":
		runNVRAM(commandArgs, *tpmPath, *pcrs, uint32(*nvramIndex), *debug)
	case "reveal":
		runReveal(commandArgs, *tpmPath, *pcrs, uint32(*nvramIndex), *debug)
	case "reveal-plain":
		runRevealPlain(commandArgs, *tpmPath, *pcrs, uint32(*nvramIndex), *debug)
	case "run":
		runRun(commandArgs, *tpmPath, *pcrs, uint32(*nvramIndex), *debug)
	case "pcrtips":
		if err := cmd.PCRTips(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(0)
		}
	case "version", "-v", "--version":
		fmt.Printf("tpm2-kira version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(0)
	}
}

func runSeal(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", pcrsStr, "PCR indices to use for policy")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")
	useSHA1 := fs.Bool("sha1", false, "Use SHA-1 PCR bank instead of SHA-256 (use only if firmware does not support SHA-256 eventlog)")
	pubKeyPath := fs.String("pubkey", cmd.DefaultPublicKeyPath, "Path to signing public key PEM (X.509 certificate or raw public key)")
	privKeyPath := fs.String("privkey", "", "Path to signing private key PEM (stored in blob for reseal convenience)")

	fs.Parse(args)

	// Validate PCR specs before proceeding
	if _, err := cmd.ParsePCRSpecs(*pcrs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}

	hashAlgo := cmd.PCRHashAlgoSHA256
	if *useSHA1 {
		hashAlgo = cmd.PCRHashAlgoSHA1
	}

	if err := cmd.Seal(*tpm, *pcrs, uint32(*nvram), *pubKeyPath, *privKeyPath, *debug, hashAlgo); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}
}

func runReseal(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reseal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", pcrsStr, "PCR indices to use for policy (if not specified, preserves original selection)")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")
	pubKeyPath := fs.String("pubkey", "", "Path to signing public key PEM (default: derived from --privkey, or preserved from blob)")
	privKeyPath := fs.String("privkey", "", "Path to signing private key PEM (required when PCR values have changed)")

	fs.Parse(args)

	// Validate PCR specs before proceeding (only if explicitly provided)
	if *pcrs != "" {
		if _, err := cmd.ParsePCRSpecs(*pcrs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(0)
		}
	}

	if err := cmd.Reseal(*tpm, *pcrs, uint32(*nvram), *pubKeyPath, *privKeyPath, *debug); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}
}

func runInfo(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", pcrsStr, "PCR indices to use for policy")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	jsonOutput := fs.Bool("json", false, "Output as JSON")

	fs.Parse(args)

	if err := cmd.InfoWithFormat(*tpm, *pcrs, uint32(*nvram), *debug, *jsonOutput); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(0)
	}
}

func runReveal(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	// Check if --nvram was explicitly provided
	nvramProvided := false
	for _, arg := range args {
		if arg == "--nvram" || arg == "-nvram" {
			nvramProvided = true
			break
		}
	}

	// Use special value 0 to indicate "scan all" when flag not provided
	scanIndex := uint32(*nvram)
	if !nvramProvided {
		scanIndex = 0 // Signal to scan all slots
	}

	cmd.RevealCommand(*tpm, scanIndex, *debug, false)
}

func runRevealPlain(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal-plain", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	// Check if --nvram was explicitly provided
	nvramProvided := false
	for _, arg := range args {
		if arg == "--nvram" || arg == "-nvram" {
			nvramProvided = true
			break
		}
	}

	// Use special value 0 to indicate "scan all" when flag not provided
	scanIndex := uint32(*nvram)
	if !nvramProvided {
		scanIndex = 0 // Signal to scan all slots
	}

	cmd.RevealCommand(*tpm, scanIndex, *debug, true)
}

func runRun(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	// Check if --nvram was explicitly provided
	nvramProvided := false
	for _, arg := range args {
		if arg == "--nvram" || arg == "-nvram" {
			nvramProvided = true
			break
		}
	}

	// Use special value 0 to indicate "scan all" when flag not provided
	scanIndex := uint32(*nvram)
	if !nvramProvided {
		scanIndex = 0 // Signal to scan all slots
	}

	cmd.RunCommand(*tpm, scanIndex, *debug)
}

func runNVRAM(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: nvram command requires a subcommand (list, status, delete)\n")
		os.Exit(0)
	}

	subcommand := args[0]
	args = args[1:]

	fs := flag.NewFlagSet("nvram", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	switch subcommand {
	case "list":
		if err := cmd.NVRAMList(*tpm, uint32(*nvram), *debug); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(0)
		}
	case "status":
		if err := cmd.NVRAMStatus(*tpm, uint32(*nvram), *debug); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(0)
		}
	case "delete":
		if err := cmd.NVRAMDelete(*tpm, uint32(*nvram), *debug); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(0)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown nvram subcommand: %s\n", subcommand)
		os.Exit(0)
	}
}

func printUsage() {
	fmt.Printf(`tpm2-kira - TPM2-based TOTP authenticator with PCR policies

USAGE:
  tpm2-kira <command> [options]

COMMANDS:
  seal        Generate and seal TOTP secret to TPM NVRAM
  reseal      Reseal secret with current PCR values (requires signing key)
  reveal      Generate TOTP code with colored KIRA format
  reveal-plain Generate TOTP code (plain output)
  run         Continuously display TOTP codes (runs until stopped)
  info        Display sealed secret information
  nvram       Manage TPM NVRAM (list, status, delete)
  pcrtips     Show PCR (Platform Configuration Register) reference guide
  version     Show version information
  help        Show this help message

GLOBAL OPTIONS:
  --tpm PATH      Path to TPM device (default: /dev/tpm0)
  --nvram INDEX   NVRAM index in hex (default: 0x01803010)
  --debug         Enable debug output

SEAL OPTIONS:
  --pcrs INDICES     PCR indices with optional source suffix (default: 0,2,7)
                     Suffix 'r' = read from TPM registers (default if no suffix)
                     Suffix 'e' = calculate from TPM eventlog (PCRs 0-12 only)
                     Suffix 'p:CMD' = predict via external command (PCR 11 only)
                       CMD must print a single hex digest line to stdout
                     Examples: "0,2,7" (all register), "0e,2e,7e" (all eventlog),
                               "0e,2,7e" (mixed: 0 and 7 from eventlog, 2 from register)
                               "0e,2e,7e,11p:tpm2-pcr11predict" (eventlog + predicted PCR 11)
  --pubkey PATH      Path to signing public key PEM for PolicySigned branch
                     (default: %s)
                     Accepts X.509 certificates or raw public keys (RSA, ECDSA)
  --privkey PATH     Path to signing private key PEM (optional)
                     Both key paths are stored in the blob so reseal can find
                     them automatically without requiring --pubkey / --privkey
  --sha1             Use SHA-1 PCR bank instead of SHA-256 (default: SHA-256)
                     Use only if firmware eventlog does not provide SHA-256 digests

RESEAL OPTIONS:
  --pcrs INDICES     New PCR indices with optional source suffix (optional,
                     preserves original selection and per-PCR sources if omitted)
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
  delete             Delete NVRAM index

AUTHENTICATION:
  tpm2-kira uses TPM2 PolicyOR with two branches for access control:
    Branch 1 (PCR):    Direct PCR policy - succeeds when PCR values match
    Branch 2 (Signed): PolicySigned - requires signature from configured key

  The signing key defaults to the sbctl secure boot DB key pair, allowing
  automated resealing in conjunction with secure boot key management.

  No password authentication is used. Recovery after PCR changes requires
  the signing private key.

EXAMPLES:
  tpm2-kira seal
  tpm2-kira seal --pcrs "0e,2e,7e"
  tpm2-kira seal --pcrs "0e,2e,7e,11p:tpm2-pcr11predict"
  tpm2-kira seal --pubkey /path/to/my-key.pem
  tpm2-kira seal --sha1 --pcrs "0e,2e,7e"
  tpm2-kira seal --pcrs "0e,2,4,7e"
  tpm2-kira reveal
  tpm2-kira reveal-plain
  tpm2-kira run
  tpm2-kira reseal
  tpm2-kira reseal --pcrs "0e,2,4,7e"
  tpm2-kira reseal --privkey /path/to/my-key.key
  tpm2-kira info
  tpm2-kira nvram list

For detailed documentation, see README.md
`, cmd.DefaultPublicKeyPath)
}
