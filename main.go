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
	eventlogBased := fs.Bool("eventlog-based", false, "Calculate PCR values from eventlog instead of reading current values")

	fs.Parse(args)

	// Read optional password from stdin
	password, err := cmd.ReadOptionalPasswordFromStdin("fallback access")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(0)
	}

	if err := cmd.Seal(*tpm, *pcrs, uint32(*nvram), password, *debug, *eventlogBased); err != nil {
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

	fs.Parse(args)

	// Read required password from stdin for reseal
	password, err := cmd.ReadRequiredPasswordFromStdin("resealing")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(0)
	}

	if err := cmd.Reseal(*tpm, *pcrs, uint32(*nvram), password, *debug); err != nil {
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
	pcrs := fs.String("pcrs", pcrsStr, "PCR indices to use for policy")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	cmd.Reveal(*tpm, *pcrs, uint32(*nvram), *debug)
}

func runRevealPlain(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("reveal-plain", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", pcrsStr, "PCR indices to use for policy")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	cmd.RevealPlain(*tpm, *pcrs, uint32(*nvram), *debug)
}

func runRun(args []string, tpmPath, pcrsStr string, nvramIndex uint32, debugFlag bool) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)

	tpm := fs.String("tpm", tpmPath, "Path to TPM device")
	pcrs := fs.String("pcrs", pcrsStr, "PCR indices to use for policy")
	nvram := fs.Uint("nvram", uint(nvramIndex), "TPM NVRAM index")
	debug := fs.Bool("debug", debugFlag, "Enable debug output")

	fs.Parse(args)

	cmd.Run(*tpm, *pcrs, uint32(*nvram), *debug)
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
  reseal      Reseal secret with current PCR values
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
  --pcrs INDICES     PCR indices (default: 0,2,7)
  --eventlog-based   Calculate PCR values from TPM eventlog instead of current values
                     You will be prompted for an optional password

RESEAL OPTIONS:
  --pcrs INDICES     New PCR indices (optional, preserves original if omitted)
                     You will be prompted for the required password
                     Eventlog-based calculation is automatically preserved from original sealing

INFO OPTIONS:
  --json             Output as JSON
                     Password will be prompted if PCRs changed

NVRAM SUBCOMMANDS:
  list               List all NVRAM indices
  status             Show NVRAM index status
  delete             Delete NVRAM index

EXAMPLES:
  tpm2-kira seal
  tpm2-kira seal --eventlog-based
  tpm2-kira seal --pcrs "0,2,4,7" --eventlog-based
  tpm2-kira reveal
  tpm2-kira reveal-plain
  tpm2-kira run
  tpm2-kira reseal
  tpm2-kira reseal --pcrs "0,2,4,7"
  tpm2-kira info
  tpm2-kira nvram list

For detailed documentation, see README.md
`)
}
