package admin

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/mrwiora/tpm2-kira/internal/measure"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
)

// ChannelApproval says what an approval does with a phone channel sealed to another
// PCR 7 than the next boot's. The secrets are opened with the signing key, which a
// hook holds too, so following a moved PCR 7 unattended would hand them to whatever
// moved it: a person decides, having seen old, new and what moved it. Until then the
// gate does not start (the phone finds no machine), and status and control are red.
type ChannelApproval int

const (
	// ChannelLeave never seals it again, and says so: a hook, --if-moved, a run
	// without a terminal. The zero value: nothing follows PCR 7 by default.
	ChannelLeave ChannelApproval = iota
	// ChannelAsk shows the move and asks: a person at a terminal.
	ChannelAsk
	// ChannelSeal shows the move and seals it: --seal-channel, or a person who
	// answered control.
	ChannelSeal
)

// ChannelApprovalFor is the mode of a 'slot approve'. unattended is the hooks' flag
// (or --if-moved), seal is --seal-channel, terminal is whether stdin is one: without
// a flag only a terminal is a person.
func ChannelApprovalFor(unattended, seal, terminal bool) (ChannelApproval, error) {
	switch {
	case unattended && seal:
		return ChannelLeave, errors.New("--seal-channel is a person's decision: not with --unattended or --if-moved")
	case seal:
		return ChannelSeal, nil
	case !unattended && terminal:
		return ChannelAsk, nil
	}
	return ChannelLeave, nil
}

// StdinIsTerminal says whether a person can be asked.
func StdinIsTerminal() bool { return isTerminal(os.Stdin) }

// askChannel asks at the terminal; a var: the tests answer it. Anything but yes is no.
var askChannel = func(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

// channelEventsShown: this command has listed what PCR 7 is made of.
var channelEventsShown bool

// channelLeftWarning is the marker's line of the block a hook passes on.
func channelLeftWarning(slot int) string {
	return fmt.Sprintf("WARNING: slot %d's phone channel was left sealed to the old PCR %s: the phones find no machine at the next boot. A hook never follows a moved PCR %s; at a terminal, after looking at what moved it: sudo tpm2-kira slot approve --nvram %d",
		slot, nvslot.ChannelPCRList(), nvslot.ChannelPCRList(), slot)
}

// followChannel is the approval's turn with the slot's phone channel, by mode. It
// comes before the slot's generation is raised: a failure leaves the slot as it is.
func followChannel(t transport.TPM, nvramIndex uint32, blob *nvslot.SealedBlob, signer crypto.Signer, mode ChannelApproval) error {
	slot := nvslot.SlotNumber(nvramIndex)
	move, err := nvslot.ChannelMoves(t, blob)
	if err != nil {
		if mode == ChannelLeave {
			fmt.Printf("WARNING: slot %d's phone channel cannot be checked, and was left as it is: %v\n\n", slot, err)
			return nil
		}
		return fmt.Errorf("cannot seal the phone channel again (remove the slot's phones if it stays so): %w", err)
	}
	if move == nil {
		return nil
	}
	if mode == ChannelLeave {
		fmt.Println(channelLeftWarning(slot))
		printChannelMove(move)
		fmt.Println()
		return nil
	}
	fmt.Printf("Slot %d's phone channel is sealed to another PCR %s than the next boot's.\n", slot, nvslot.ChannelPCRList())
	printChannelMove(move)
	if mode == ChannelAsk && !askChannel(fmt.Sprintf("Seal slot %d's phone channel to the next boot's PCR %s?", slot, nvslot.ChannelPCRList())) {
		fmt.Println(channelLeftWarning(slot))
		fmt.Println()
		return nil
	}
	resealed, afterSeparator, err := nvslot.ResealChannelIfMoved(t, blob, signer)
	if err != nil {
		return fmt.Errorf("cannot seal the phone channel again (remove the slot's phones if it stays so): %w", err)
	}
	if resealed {
		fmt.Printf("The phone channel is sealed again, to PCR %s as the next boot will have it; the phones keep what they pinned.\n", nvslot.ChannelPCRList())
		warnChannelAfterSeparator(afterSeparator)
	}
	return nil
}

// printChannelMove shows old and new, and once in a command what the event log says
// the new value is made of. The events of the old one are kept nowhere, so this is
// no difference: it is what to compare with what you changed.
func printChannelMove(move *nvslot.ChannelMove) { printChannelMoveTo(os.Stdout, move) }

func printChannelMoveTo(w io.Writer, move *nvslot.ChannelMove) {
	for i, sealed := range move.Sealed {
		fmt.Fprintf(w, "  PCR %d sealed:    %s\n", sealed.Index, hex.EncodeToString(sealed.Digest))
		if i < len(move.NextBoot) {
			fmt.Fprintf(w, "  PCR %d next boot: %s\n", move.NextBoot[i].Index, hex.EncodeToString(move.NextBoot[i].Digest))
		}
	}
	if move.AfterSeparator != "" {
		fmt.Fprintf(w, "  (the registers as they are: %s)\n", move.AfterSeparator)
	}
	if channelEventsShown {
		return
	}
	channelEventsShown = true
	for _, pcr := range move.NextBoot {
		events, err := measure.PCREvents(measure.DefaultEventlogPath, pcr.Index, move.Bank)
		if err != nil {
			fmt.Fprintf(w, "  What moved it cannot be named: no event log to read (%v).\n", err)
			continue
		}
		fmt.Fprintf(w, "  What moved it: this boot's event log says PCR %d is made of these; the old value's events are kept nowhere, so compare with what you changed (a db or dbx update, Secure Boot switched, another signed system):\n", pcr.Index)
		for _, e := range events {
			fmt.Fprintf(w, "    %s\n", e)
		}
	}
}
