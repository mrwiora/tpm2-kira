package bootrun

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mrwiora/tpm2-kira/internal/diskkey"
	"github.com/mrwiora/tpm2-kira/internal/imageplan"
	"github.com/mrwiora/tpm2-kira/internal/phonegate"
	"github.com/mrwiora/tpm2-kira/internal/screen"
	"github.com/mrwiora/tpm2-kira/internal/sshscreen"
	"github.com/mrwiora/tpm2-kira/internal/vaultkey"
)

// A part is one part of the boot image that run starts when the image's
// plan names it (imageplan). Parts know nothing of each other: what one
// offers the others it puts on the board when it starts, and what it needs
// it takes from there. They start in the order of the layers - who checks
// the boot (the phone), where the screen is (SSH), the disk's key from a
// vault, then the disk's key itself, which takes from all of them - and
// end in the opposite order.
type part interface {
	// start starts the part; nothing it offers is on the board before.
	start(bd *board)
	// released is told that the hold has ended, and who confirmed the boot
	// (one of the confirmedBy values, or "" when the hold ran out).
	released(bd *board, by string)
	// end is told that run ends.
	end(bd *board)
}

// parts are the parts of one boot; nil is a part the plan does not name.
type parts struct {
	phone, ssh, vault, unlock, console part
}

// plannedParts is the parts the image's plan and the SSH settings name. The
// disk's key provider and the console are always there: the first serves
// nothing without a socket, the second is Enter.
func plannedParts(planned imageplan.Planned, remote sshscreen.Options, unlockSocket string) parts {
	ps := parts{unlock: &unlockPart{socket: unlockSocket}, console: &consolePart{}}
	if planned.Phone {
		ps.phone = &phonePart{}
	}
	if remote.On {
		ps.ssh = &sshPart{opts: remote}
	}
	if planned.Vault {
		ps.vault = &vaultPart{}
	}
	return ps
}

// inOrder is the parts there are, in the order they start.
func (ps parts) inOrder() []part {
	var out []part
	for _, p := range []part{ps.phone, ps.ssh, ps.vault, ps.unlock, ps.console} {
		if p != nil {
			out = append(out, p)
		}
	}
	return out
}

// Who confirmed the boot.
const (
	confirmedByConsole = "console" // Enter at the console
	confirmedBySSH     = "ssh"     // Enter in an SSH session
	confirmedByVault   = "vault"   // the vault's key was made
)

// board is what the parts give each other.
type board struct {
	tpmPath string
	debug   bool
	hold    time.Duration // how long the code screen holds the boot

	// confirm carries a part's confirmation of the boot: who confirmed.
	confirm chan string

	// ask is where a passphrase is asked: the console, or an SSH session.
	ask diskkey.Prompter
	// phone is the gate's state for the slot it serves; nil without a phone.
	phone func() (phonegate.GateStatus, bool)
	// salt is the salt the phone released, once it has; nil without a phone.
	salt func() []byte
	// expectRelease tells the gate that a salt is wanted after the receipt;
	// nil without a phone.
	expectRelease func(bool)
	// vaultKey is a volume's key from the vault; nil without one.
	vaultKey func(volume string) ([]byte, error)
	// remote shows the code screen in the SSH sessions, and hint says on the
	// console where they are; nil: the code screen is the console's.
	remote func(screen []byte)
	hint   func(remaining time.Duration)
	// remoteDone is closed once the SSH server has ended; nil without one.
	remoteDone <-chan struct{}
	// prompting says the passphrase prompt owns the console; promptMode is
	// the recipe of the volume asked next, for the screen's words.
	prompting  func() bool
	promptMode func() []diskkey.Recipe
}

// offer sends a confirmation unless the board has one waiting already, or
// stop is closed.
func (bd *board) offer(by string, stop <-chan struct{}) bool {
	select {
	case bd.confirm <- by:
		return true
	case <-stop:
		return false
	}
}

// phonePart is the coordinator of the phone's gate: the radio worker it
// starts (gate-child) asks it for quotes and hands it the receipt.
type phonePart struct {
	svc  *phonegate.GateService
	stop func()
}

func (p *phonePart) start(bd *board) {
	svc, stop := StartCoordinator(bd.tpmPath, phonegate.DefaultAttestSignerPath, bd.debug)
	if svc == nil {
		return
	}
	p.svc, p.stop = svc, stop
	bd.phone = svc.Status
	bd.expectRelease = svc.ExpectRelease
	bd.salt = func() []byte {
		// The phone's salt follows its receipt by one message: give it the
		// time, bounded (gate_service.go releaseWait).
		for {
			st, _ := svc.Status()
			if !st.Releasing {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		return svc.Salt()
	}
}

// The phone check ends with the hold, and the radio worker with it.
func (p *phonePart) released(*board, string) {
	if p.stop != nil {
		p.stop()
	}
}

func (p *phonePart) end(*board) {
	if p.svc != nil {
		p.svc.Forget()
	}
}

// sshPart is the SSH server: the code screen is shown and confirmed in an
// SSH session, the console says where, and the passphrase is asked in the
// session that confirmed.
type sshPart struct {
	opts sshscreen.Options
	srv  *sshscreen.Server
	hint *hintPrinter
	quit chan struct{}
}

func (p *sshPart) start(bd *board) {
	if p.opts.TPM == "" {
		p.opts.TPM = bd.tpmPath
	}
	srv, err := sshscreen.Start(p.opts, os.Stdout, diskkey.UnlockLogger(bd.debug))
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: the SSH server is not started: %v - the code screen is at the console\n", err)
		return
	}
	p.srv = srv
	stopRemoteOnSignal(srv)
	bd.ask = srv.Ask
	bd.hold = p.opts.Hold
	if bd.hold == 0 {
		bd.hold = holdUnlimited
	}
	p.hint = startHintPrinter(srv)
	bd.remote = srv.Show
	bd.hint = p.hint.print
	bd.remoteDone = srv.Done
	p.quit = make(chan struct{})
	go func() {
		for {
			select {
			case <-srv.Releases:
				if !bd.offer(confirmedBySSH, p.quit) {
					return
				}
			case <-p.quit:
				return
			}
		}
	}()
}

// Enter at the console stops the SSH server; otherwise the session that
// confirmed (or the newest one) has the prompt.
func (p *sshPart) released(_ *board, by string) {
	if p.srv == nil {
		return
	}
	close(p.quit)
	p.hint.stop()
	if p.srv.Release(by == confirmedByConsole) {
		fmt.Printf("%s Confirmed over SSH: the password is asked in the SSH session.\n", screen.Tag(screen.TagYellow))
	}
}

func (p *sshPart) end(*board) {}

// vaultPart makes the key of a slot enrolled with a vault while the code
// screen holds (the parts open only in the approved boot state, before the
// separator); a key made ends the hold on its own. The attempt lasts as
// long as the hold.
type vaultPart struct {
	cancel context.CancelFunc
	quit   chan struct{}
}

func (p *vaultPart) start(bd *board) {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.quit = cancel, make(chan struct{})
	keys := vaultkey.Start(ctx, bd.tpmPath, os.Stdout, diskkey.UnlockLogger(bd.debug), bd.debug)
	if keys == nil {
		return
	}
	bd.vaultKey = keys.ForVolume
	go func() {
		select {
		case <-keys.Ready():
			// Tried once; without a key the hold goes on.
			if keys.Made() {
				bd.offer(confirmedByVault, p.quit)
			}
		case <-p.quit:
		}
	}()
}

// Past the hold the parts no longer open.
func (p *vaultPart) released(*board, string) {
	p.cancel()
	close(p.quit)
}

func (p *vaultPart) end(*board) {}

// unlockPart is the key provider for systemd-cryptsetup (or Debian's
// keyscript): it answers the volumes' key requests once the hold has
// ended, and stays until it is stopped. How a key is made is read from
// the volume's LUKS2 header (diskkey): nothing is configured.
type unlockPart struct {
	socket string
	unlock *diskkey.UnlockServer
}

func (p *unlockPart) start(bd *board) {
	l, err := diskkey.ListenUnlock(p.socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm2-kira: the disk unlock is not served: %v\n", err)
		return
	}
	if l == nil {
		return
	}
	// What the next prompt is, for the code screen's words: the recipe of
	// the first routed volume, read from its LUKS2 header once it is
	// readable.
	bd.promptMode = diskkey.ScreenRecipe(diskkey.DefaultUnlockSocket)
	if bd.expectRelease != nil {
		// A slot whose enrolment holds a release key waits for the salt
		// that follows the phone's receipt.
		bd.expectRelease(true)
	}
	salt := bd.salt
	if salt == nil {
		salt = func() []byte { return nil }
	}
	recipes := &diskkey.UnlockRecipe{}
	p.unlock = diskkey.ServeUnlock(l, diskkey.DiskKey(salt, bd.vaultKey, recipes.ForVolume, bd.ask), diskkey.UnlockLogger(bd.debug))
	bd.prompting = p.unlock.Prompting
}

// From the hold's end on, systemd-cryptsetup's key requests are answered -
// once the units READY let loose have printed their lines, which would
// otherwise land in the prompt (waitPromptTurn).
func (p *unlockPart) released(*board, string) {
	if p.unlock == nil {
		return
	}
	go func() {
		waitPromptTurn()
		p.unlock.Release()
	}()
}

// The display is done; the key provider stays until systemd stops the
// service at switch-root.
func (p *unlockPart) end(bd *board) {
	if p.unlock == nil {
		return
	}
	waitForStop()
	if bd.remoteDone != nil {
		<-bd.remoteDone // its socket removed before the process ends
	}
	p.unlock.Close()
}

// consolePart is Enter at the console: it confirms the boot until the hold
// ends, and then the terminal is the passphrase prompt's.
type consolePart struct {
	enter *enterReader
	quit  chan struct{}
}

func (p *consolePart) start(bd *board) {
	p.enter, p.quit = startEnterReader(0), make(chan struct{})
	go func() {
		for {
			select {
			case <-p.enter.Presses:
				if !bd.offer(confirmedByConsole, p.quit) {
					return
				}
			case <-p.quit:
				return
			}
		}
	}()
}

func (p *consolePart) released(*board, string) {
	close(p.quit)
	p.enter.Stop()
}

func (p *consolePart) end(*board) {}
