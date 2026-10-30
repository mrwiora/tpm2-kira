// tpm2-kira-boot is what the boot image carries of tpm2-kira: the code
// screen and the parts the image's plan names, the cap, the Debian
// keyscript, the SSH server's unprivileged half and the phone's radio
// worker. Nothing of the administration (tpm2-kira) is in it.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/bootrun"
	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/journal"
	"github.com/mrwiora/tpm2-kira/internal/machineid"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
	"github.com/mrwiora/tpm2-kira/internal/totp"
	"github.com/mrwiora/tpm2-kira/internal/tpmdev"
)

// Version is set at build time (-X main.Version=...).
var Version = "dev"

const usage = `tpm2-kira-boot - tpm2-kira in the boot image (the initramfs units and
scripts run it; on the installed system it is 'tpm2-kira')

  run          The code screen: shows the codes, holds the boot until it is
               confirmed, and starts the parts the image's plan names - the
               phone's gate, the SSH server, the vault, the disk's key
  cap          Lock the codes until the next boot (when the initrd is left)
  close        Close the SSH CA's window (before a resume from hibernation)
  unlock-key   Debian's keyscript: the disk's key from run's socket, else askpass
  machine-id   Release the sealed machine-id before the network (slot 0's policy)
  reveal       The current code (reveal-plain: without colour)
  ssh-child    The SSH server's unprivileged half, started by run
  gate-child   The phone's radio worker, started by run
  version      The version

Options are the command's own (tpm2-kira-boot <command> -h).
`

func main() {
	nvslot.AppVersion = Version
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	command, args := os.Args[1], os.Args[2:]
	switch command {
	case "version", "-v", "--version":
		fmt.Printf("tpm2-kira-boot version %s\n", Version)
		return
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	case "ssh-child":
		// The SSH server's unprivileged half: started by 'run' as nobody.
		if err := sshscreen.SSHChildCommand(); err != nil {
			fmt.Fprintf(os.Stderr, "tpm2-kira-boot ssh-child: %v\n", err)
			os.Exit(1)
		}
		return
	case "gate-child":
		// The phone's radio worker: started by 'run' as nobody.
		fs := flag.NewFlagSet("gate-child", flag.ExitOnError)
		debug := fs.Bool("debug", false, "Narrate every step")
		fs.Parse(args)
		os.Exit(phonegate.RadioWorkerMain(*debug))
	}
	machineid.TestPaths()
	if os.Geteuid() != 0 && os.Getenv("TPM2_KIRA_UNPRIVILEGED") == "" {
		fmt.Fprintf(os.Stderr, "tpm2-kira-boot %s: root is needed\n", command)
		os.Exit(1)
	}
	switch command {
	case "run":
		runRun(args)
	case "cap":
		fs := flag.NewFlagSet("cap", flag.ExitOnError)
		tpm := fs.String("tpm", tpmdev.DefaultPath, "Path to TPM device")
		fs.Parse(args)
		if err := totp.CapCommand(*tpm); err != nil {
			fail(err)
		}
	case "close":
		fs := flag.NewFlagSet("close", flag.ExitOnError)
		tpm := fs.String("tpm", tpmdev.DefaultPath, "Path to TPM device")
		conf := fs.String("ssh-conf", sshscreen.DefaultConf, "aSSH's settings: the SSH CA and its window index")
		fs.Parse(args)
		// The one command whose failure is the boot's: the resume that
		// follows it must not go on with the window open.
		if err := sshscreen.Close(*tpm, *conf); err != nil {
			fmt.Fprintf(os.Stderr, "tpm2-kira-boot close: %v\n", err)
			os.Exit(1)
		}
	case "unlock-key":
		fs := flag.NewFlagSet("unlock-key", flag.ExitOnError)
		socket := fs.String("socket", diskkey.DefaultUnlockSocket, "The key socket of 'tpm2-kira-boot run --unlock'")
		wait := fs.Duration("wait", 5*time.Second, "How long to wait for the socket to appear")
		fs.Parse(args)
		volume := fs.Arg(0)
		if volume == "" {
			volume = os.Getenv("CRYPTTAB_NAME")
		}
		if err := diskkey.UnlockKeyCommand(*socket, volume, *wait); err != nil {
			fmt.Fprintf(os.Stderr, "tpm2-kira-boot: %v\n", err)
			os.Exit(1) // a keyscript's exit status is what cryptroot reads
		}
	case "machine-id":
		fs := flag.NewFlagSet("machine-id", flag.ExitOnError)
		tpm := fs.String("tpm", tpmdev.DefaultPath, "Path to TPM device")
		fs.Parse(args)
		// The boot never depends on it: what went wrong is said, the exit
		// status is 0.
		switch released, err := machineid.Boot(*tpm); {
		case err != nil:
			fmt.Fprintf(os.Stderr, "tpm2-kira: the machine-id is not released: %v\n", err)
		case released:
			journal.Narrate("tpm2-kira: the machine-id is released (slot 0's policy held)")
		default:
			journal.Narrate("tpm2-kira: no sealed machine-id")
		}
	case "reveal", "reveal-plain":
		fs := flag.NewFlagSet(command, flag.ExitOnError)
		tpm := fs.String("tpm", tpmdev.DefaultPath, "Path to TPM device")
		nvram := fs.Uint("nvram", 0, "A slot, 0-15, or a full NV index (default: every populated slot)")
		debug := fs.Bool("debug", false, "Enable debug output")
		fs.Parse(args)
		totp.RevealCommand(*tpm, slotIndex(fs, *nvram), *debug, command == "reveal-plain")
	default:
		fmt.Fprintf(os.Stderr, "tpm2-kira-boot: unknown command %q\n\n%s", command, usage)
		os.Exit(2)
	}
}

func runRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	tpm := fs.String("tpm", tpmdev.DefaultPath, "Path to TPM device")
	nvram := fs.Uint("nvram", 0, "A slot, 0-15, or a full NV index (default: every populated slot)")
	debug := fs.Bool("debug", false, "Enable debug output")
	hold := fs.Uint("hold", uint(bootrun.HoldDefault/time.Second), "Seconds to wait for Enter after showing the code before the boot continues on its own (0: at once)")
	unlock := fs.String("unlock", "", "Also answer the disk's key requests on this socket: Debian's boot script passes it; under systemd the socket unit hands its socket over instead")
	ssh := fs.Bool("ssh", false, "Also be the SSH server: the codes are shown and confirmed in an SSH session, the console says where to log in (set by the image's drop-in)")
	sshConf := fs.String("ssh-conf", sshscreen.DefaultConf, "With --ssh: aSSH's settings - the SSH CA, the address, the keys that may log in")
	sshHold := fs.Uint("ssh-hold", 0, "With --ssh: seconds to wait for a confirmation, in place of --hold (0: until one comes)")
	plan := fs.String("plan", "", "Start only the parts the boot image names in this directory; without it, all it finds (set by the initrd unit: "+imageplan.Dir+")")
	fs.Parse(args)

	planned := imageplan.All
	if *plan != "" {
		planned = imageplan.Read(*plan)
	}
	var remote sshscreen.Options
	if *ssh {
		var err error
		if remote, err = sshscreen.OptionsFrom(*sshConf, time.Duration(*sshHold)*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "tpm2-kira-boot: the SSH server is not started: %v - the code screen is at the console\n", err)
		}
	}
	bootrun.Run(*tpm, slotIndex(fs, *nvram), time.Duration(*hold)*time.Second, *unlock, remote, planned, *debug)
}

// slotIndex is the blob index of the slot --nvram names (0-15 or a full NV
// index); 0 without the option: every populated slot.
func slotIndex(fs *flag.FlagSet, v uint) uint32 {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "nvram" })
	if !given {
		return 0
	}
	return nvslot.ResolveNVRAMIndex(uint32(v))
}

// fail reports a failed command. The exit status is 0, as tpm2-kira's: a
// failure here must not break the boot chain.
func fail(err error) {
	fmt.Fprintf(os.Stderr, "tpm2-kira-boot: FAILED: %v\n", err)
	os.Exit(0)
}
