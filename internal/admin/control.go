// Package admin is everything tpm2-kira does on the installed system: control
// (the guided way), setup, slot add and approve, status, phone and phone salt
// enrolment, the LUKS keyslots, vault enrolment, the boot plan and the image
// build.
package admin

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/tpm2-trust/tpm2-kira/internal/measure"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/prompt"
	"github.com/tpm2-trust/tpm2-kira/internal/screen"
	"golang.org/x/sys/unix"
)

// 'tpm2-kira control' is the guided way through the protections, for a
// person rather than a script: it first looks at what the machine has (a
// TPM and its banks, the event log, how it booted, a Bluetooth adapter, the
// LUKS devices, the initramfs kind, the network interfaces), then at what
// is configured already (the keys, the slots, the phone, the keyslots, the
// route, the vault, the boot image's network and SSH server). It guides in
// two steps. Step 1, the boot chain (control_bootchain.go): the
// prerequisites, each judged, then the sd-tpm2-kira hook in the image and
// the key's route on the kernel command line. Step 2 (control_hub.go): what the machine combines, in submenus -
// the signing key with the TOTP codes, the phone, the ways the disk is
// unlocked, the network and SSH at boot - each option greyed with the
// reason while this machine cannot have it, and an option that needs
// another one control can set up offers it on the way. The image is built
// once, when control is left, after the person says yes. Everything control
// keeps is written by control itself, into control.conf and assh.conf
// (remote_assh.go). The steps run the
// same functions the expert commands use: nothing here is a third way of
// doing things.

// ControlOptions is what control takes.
type ControlOptions struct {
	TPMPath string
	Debug   bool
	Out     io.Writer // default stdout
	// Lines forces the numbered line menus instead of the full screen.
	Lines bool
	// HelpTopics are the pages of 'tpm2-kira help', for the Reference section.
	HelpTopics []string
}

// emptyPassSeen caches the empty-passphrase test of a keyslot for this
// run, by device and the keyslot's KDF salt - a new passphrase is a new
// salt - since each test is a full key derivation.
var emptyPassSeen = map[string]bool{}

// A line of a screen: a step, an option of a submenu, or a submenu's
// line on step 2 (Menu). Every populated slot is a line of its own, and
// picking it removes the slot whole (SelfConfirm: the step asks before it
// acts, so no "run it again?" stands in front).
type controlStep struct {
	Key         string
	Title       string
	Explain     string // one or two lines on what it does
	Done        string // "" when not done; else how it is
	Blocked     string // "" when it can be done; else why not
	Dirty       string // "" when nothing is half-gone; else what and where
	Optional    bool   // not a protection: never the recommendation on its own
	Check       bool   // a wiring check: pickable only while it is open
	SelfConfirm bool   // Run confirms by itself; picked straight even when Done
	Menu        string // picking opens this screen instead of running anything
	Run         func(c *controller) error
	// Danger is how much it can break (dangerChange, dangerView, dangerDestroy);
	// Destroys says what a destroying step removes. Command is what the step equals
	// on the command line (annotate).
	Danger   int
	Destroys string
	Command  string
}

// The one colour language of the overview: green is good and done, orange
// is open - possible and still to do - and red is dirty, a half-gone slot.
// Blocked stays grey.
func (s controlStep) marker() string {
	switch {
	case s.Dirty != "":
		return "\033[0;31m[!]\033[0m"
	case s.Done != "":
		return "\033[0;32m[x]\033[0m"
	case s.Blocked != "":
		return "\033[0;90m[-]\033[0m"
	}
	return "\033[0;33m[ ]\033[0m"
}

// controller holds one run of the control command.
type controller struct {
	o     ControlOptions
	out   io.Writer
	p     *prompt.Prompter
	tty   bool
	facts machineFacts
	// screen is what the overview shows: "chain" (step 1), "hub" (step 2)
	// or one of step 2's submenus (controlMenus).
	screen string
}

// ControlNeedsRoot is control's answer when it is not root: its screen,
// or a line without a terminal.
func ControlNeedsRoot() {
	text := "Everything control looks at and sets is root's: the TPM, the keys in /etc/tpm2-kira, the LUKS headers, the initramfs.\n\n    sudo tpm2-kira control"
	if !isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "tpm2-kira control: root is needed - sudo tpm2-kira control")
		return
	}
	c := &controller{out: os.Stdout}
	fmt.Fprint(c.out, clearScreen)
	c.ask().Note("[ KIRA ] control needs root", text)
}

// header is the one line on top of every overview: the tag, the version,
// what this is.
func (c *controller) header() string {
	v := nvslot.AppVersion
	if v == "" {
		v = "unknown"
	}
	return fmt.Sprintf("%s control %s - the protections of this machine, step by step", screen.Tag(screen.TagYellow), v)
}

// Control runs the guided workflow: step 1 until the boot chain is in
// place, then step 2 and its submenus.
func Control(o ControlOptions) error {
	c := &controller{o: o, out: o.Out}
	if c.out == nil {
		c.out = os.Stdout
	}
	c.p = prompt.New(os.Stdin, c.out)
	c.out = c.p.Writer()
	c.tty = isTerminal(os.Stdin)
	// The configuration file first: control writes it, and a step taken
	// on a file that does not load would be taken on defaults it never
	// chose (a network setting read as off). Everything wrong with it, then quit.
	if problems := controlConfigProblemsText(controlConfigPath()); problems != "" {
		fmt.Fprintf(c.out, "\n%s\n\n%s", c.header(), problems)
		return fmt.Errorf("%s does not load: fix it as shown, then start control again", controlConfigPath())
	}
	// The overview judges the risks itself, in red on the status, so the
	// steps run without the commands' advisory warnings: nothing is said
	// twice. Run by hand, seal and reseal keep them.
	defer func(old bool) { measure.AdvisoryWarnings = old }(measure.AdvisoryWarnings)
	measure.AdvisoryWarnings = false
	for {
		if c.tty { // the overview is a page of its own: what the last step printed was read before "Continue"
			fmt.Fprint(c.out, clearScreen+"\n\033[2mLooking at this machine ...\033[0m\n")
		}
		c.facts = collectFacts(o.TPMPath, o.Debug)
		if c.screen == "" { // the start: step 1 until the boot chain is in place
			c.screen = "hub"
			if !chainDone(&c.facts) {
				c.screen = "chain"
			}
		}
		if !c.tty {
			c.show()
			return nil // the analysis and the recommendation, for a script
		}
		steps := c.screenSteps()
		fmt.Fprint(c.out, clearScreen+"\n"+c.header()+"\n  "+c.screenTitle()+"\n\n")
		key, err := c.pick(steps)
		// A submenu, or step 1 once the boot chain is in place (opened
		// from step 2): Esc goes back to step 2. Elsewhere it leaves.
		sub := c.screen != "hub" && (c.screen != "chain" || chainDone(&c.facts))
		if err != nil && sub { // Esc: back to step 2
			c.screen = "hub"
			continue
		}
		if err != nil || key == "" {
			c.leave()
			return nil
		}
		var s controlStep
		for _, st := range steps {
			if st.Key == key {
				s = st
			}
		}
		if s.Menu != "" {
			c.screen = s.Menu
			continue
		}
		if s.Done != "" && !s.SelfConfirm {
			again, err := c.confirm(s.Title+" is done: "+s.Done+". Run it again?", "")
			if err != nil || !again {
				continue
			}
		}
		fmt.Fprintf(c.out, "\n\033[1m%s\033[0m\n%s\n\n", s.Title, s.Explain)
		if err := s.Run(c); err != nil {
			fmt.Fprintf(c.out, "\n\033[0;31mNot done:\033[0m %v\n", err)
		}
		// Whatever happened, the screen follows once it was read (Esc leaves).
		if err := c.ask().Wait("Back to "+c.screenTitle(), "", "OK"); err != nil {
			c.leave()
			return nil
		}
	}
}

// screenSteps are the lines of the screen shown: step 1, step 2, or a
// submenu of step 2 with its way back.
func (c *controller) screenSteps() []controlStep {
	switch c.screen {
	case "chain":
		return c.annotated(c.chainSteps())
	case "hub":
		return c.annotated(c.hubSteps())
	}
	return append(c.annotated(c.menuSteps(c.screen)), controlStep{Key: "back", Title: "Back to step 2", Optional: true, Menu: "hub"})
}

// screenTitle names the screen, under the header.
func (c *controller) screenTitle() string {
	switch c.screen {
	case "chain":
		return "Step 1 of 2: the boot chain"
	case "hub":
		return "Step 2 of 2: what this machine combines"
	}
	return "Step 2 of 2 > " + menuByKey(c.screen).title
}

// clearScreen is the terminal cleared, the cursor at the top.
const clearScreen = "\033[H\033[2J"

// ask is what control asks with (internal/prompt): the overview with the step to
// pick, a yes/no, a device. What a step prints stays on the screen above the next
// question. Ctrl-C, Ctrl-D or Esc leaves.
func (c *controller) ask() *prompt.Prompter {
	if c.p == nil {
		c.p = prompt.New(os.Stdin, c.out)
	}
	return c.p
}

// pick is the overview: the facts as a note, the steps as a menu with their
// state, the recommendation in the text. A blocked step cannot be picked; the
// reason is shown instead. "" is leave.
func (c *controller) pick(steps []controlStep) (string, error) {
	var opts []prompt.Option[string]
	for _, s := range steps {
		o := prompt.Option[string]{Label: stepLabel(s), Value: s.Key}
		switch {
		case s.Dirty != "":
		case s.Done != "" && s.Check:
			o.Blocked = "in place: " + s.Done
		case s.Done == "" && s.Blocked != "":
			o.Blocked = s.Blocked
		}
		opts = append(opts, o)
	}
	if c.screen == "chain" || c.screen == "hub" {
		opts = append(opts, prompt.Option[string]{Label: "  Quit", Value: ""})
	}
	// Quit (in a submenu: Back) is what Enter alone takes, on entering and on every
	// return: Enter alone never runs a step, the recommendation is named in the
	// text and picked by hand.
	def := ""
	if c.screen != "chain" && c.screen != "hub" {
		def = "back"
	}
	return prompt.Select(c.ask(), "", c.screenNote(steps), opts, def)
}

// stepLabel is a step's line in the menu. The same colours as the status:
// red the dirty, green the done, orange the open; the menu greys the blocked.
// Only the mark is coloured.
func stepLabel(s controlStep) string {
	indent := ""
	switch {
	case s.Dirty != "":
		return indent + bad("!") + " " + s.Title + "  - " + s.Dirty
	case s.Done != "" && s.Danger == dangerDestroy:
		return indent + good("✓") + " " + s.Title + "  - " + s.Done + "  " + bad("(picking it destroys it)")
	case s.Done != "":
		return indent + good("✓") + " " + s.Title + "  - " + s.Done
	case s.Blocked != "":
		return indent + "- " + s.Title + "  - " + s.Blocked
	case s.Key == "back":
		return "  " + s.Title
	case s.Menu != "":
		return indent + amber("•") + " " + s.Title + "  >"
	case s.Danger == dangerView:
		return indent + "  " + s.Title
	}
	return indent + amber("•") + " " + s.Title
}

// screenNote is the text above the menu: on step 1 the prerequisites,
// on step 2 the machine's status, in a submenu what it is about; then the
// recommendation, and on step 2 the status' notes.
func (c *controller) screenNote(steps []controlStep) string {
	head := c.headline(steps)
	switch c.screen {
	case "chain":
		return heading("Prerequisites") + "\n" + c.prereqText() + "\n" + heading("The boot chain") + "\n" + head
	case "hub":
		if notes := c.facts.Status.Notes; len(notes) > 0 {
			head += "\n\nNotes:"
			for _, n := range notes {
				head += "\n- " + n
			}
		}
		return c.noteDescription() + "\n" + heading("Step 2") + "\n" + head
	}
	return menuByKey(c.screen).intro + "\n\n" + head
}

// headline is the recommendation of a screen, or what the screen offers
// when nothing is recommended.
func (c *controller) headline(steps []controlStep) string {
	if n := recommended(steps); n >= 0 {
		return "Recommended next: " + steps[n].Title + "\n" + steps[n].Explain
	}
	switch c.screen {
	case "chain":
		if chainDone(&c.facts) {
			return "The boot chain is in place."
		}
		return "Nothing of the boot chain can be done yet: the prerequisites in red say what is missing."
	case "hub":
		return "Combine what fits this machine: each entry says what it needs, and what this machine cannot have is greyed with the reason."
	}
	return "Pick what to add or change; what is not possible here says why."
}

func (c *controller) confirm(title, description string) (bool, error) {
	return c.ask().Confirm(title, description, false)
}

func (c *controller) choose(title string, items []string) (int, error) {
	var opts []prompt.Option[int]
	for i, it := range items {
		opts = append(opts, prompt.Option[int]{Label: it, Value: i})
	}
	return prompt.Select(c.ask(), title, "", opts, 0)
}

// noteDescription is the overview note: the status, judged line by line.
func (c *controller) noteDescription() string {
	return heading("What this machine has") + "\n" + c.factsText()
}

// heading is a heading in a screen's text.
func heading(s string) string { return "\033[1m" + s + "\033[0m" }

// The status is judged line by line: green is good, red is not good and
// says why - the risk in brackets, orange a warning with nothing better on
// this machine. What is none of them (plain information) stays uncoloured.
func good(s string) string { return "\033[0;32m" + s + "\033[0m" }
func bad(s string) string  { return "\033[0;31m" + s + "\033[0m" }

// warn is orange: not a risk, but nothing to leave as it is.
func warn(s string) string  { return "\033[0;33m" + s + "\033[0m" }
func amber(s string) string { return "\033[0;33m" + s + "\033[0m" }

// recommended is the index of a dirty step - a half-gone slot comes before
// everything, since the protections around it cannot be judged - else of
// the first protection that can be done, or -1.
func recommended(steps []controlStep) int {
	for i, s := range steps {
		if s.Dirty != "" {
			return i
		}
	}
	for i, s := range steps {
		if !s.Optional && s.Done == "" && s.Blocked == "" {
			return i
		}
	}
	return -1
}

// show draws both steps in plain text, the submenus' options under their
// line of step 2: the prerequisites, the boot chain, the status, what
// the machine combines, the recommendation (a script's look, and the
// tests').
func (c *controller) show() {
	f := &c.facts
	w := c.out
	line := func(s controlStep, indent string) {
		fmt.Fprintf(w, "  %s %s%s", s.marker(), indent, s.Title)
		switch {
		case s.Dirty != "":
			fmt.Fprintf(w, "  - %s", s.Dirty)
		case s.Done != "":
			fmt.Fprintf(w, "  - %s", s.Done)
		case s.Blocked != "":
			fmt.Fprintf(w, "  - %s", s.Blocked)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "\n%s\n\n", c.header())
	fmt.Fprintln(w, "\033[1mStep 1 of 2: the boot chain\033[0m")
	fmt.Fprint(w, c.prereqText())
	fmt.Fprintln(w)
	chain := c.chainSteps()
	for _, s := range chain {
		if s.Menu == "hub" {
			continue // the way to step 2 on the screen; step 2 follows here
		}
		line(s, "")
	}

	fmt.Fprintln(w, "\n\033[1mWhat this machine has\033[0m")
	fmt.Fprint(w, c.factsText())
	fmt.Fprintln(w, "\n\033[1mStep 2 of 2: what this machine combines\033[0m")
	hub := c.hubSteps()
	for _, s := range hub {
		line(s, "")
		if s.Menu != "" && s.Menu != "chain" {
			for _, o := range c.menuSteps(s.Menu) {
				line(o, "    ")
			}
		}
	}

	rec, why := "", ""
	if n := recommended(chain); !chainDone(f) && n >= 0 {
		rec, why = "Step 1 > "+chain[n].Title, chain[n].Explain
	} else if !chainDone(f) {
		rec, why = "Step 1", "Nothing of the boot chain can be done yet: the prerequisites in red say what is missing."
	} else if n := recommended(hub); n >= 0 {
		rec, why = hub[n].Title, hub[n].Explain
		if m := hub[n].Menu; m != "" && m != "chain" {
			if sub := c.menuSteps(m); recommended(sub) >= 0 {
				o := sub[recommended(sub)]
				rec, why = hub[n].Title+" > "+o.Title, o.Explain
			}
		}
	}
	if rec != "" {
		fmt.Fprintf(w, "\n\033[1mRecommended next:\033[0m %s\n  %s\n", rec, why)
	} else {
		fmt.Fprintln(w, "\n\033[1mNothing is recommended: the rest is what this machine may combine.\033[0m")
	}
	if notes := f.Status.Notes; len(notes) > 0 {
		fmt.Fprintln(w, "\n\033[1mNotes\033[0m")
		for _, n := range notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
}

// leave is the end of control: the boot image is rebuilt here, once,
// when it is out of date - after everything is set up, as a build takes
// its time - then what is left to do by hand is said: the route.
func (c *controller) leave() {
	c.leaveWith(func() machineFacts { return collectFacts(c.o.TPMPath, c.o.Debug) })
}

// leaveWith is leave with look, the fresh look at the machine. The image comes
// before the SSH CA's approval: PCR 4 and PCR 11 are the image's, its hook
// approves what it built, and a slot that takes PCR 11 signed cannot be
// approved for an image that does not carry the signature.
func (c *controller) leaveWith(look func() machineFacts) {
	fmt.Fprintln(c.out)
	// What changed since the image was built is looked at, not which
	// steps ran: a fresh look, as the last step may have changed it.
	f := look()
	// The CA's slots are assh.conf's from here on: one taken away there
	// goes now, one added is approved below.
	if f.SSHCA.CA != nil && f.Remote.SSH.On {
		if changed, err := syncSSHCASlots(f.Remote.SSH.Assh); err != nil {
			fmt.Fprintf(c.out, "\033[0;31mThe SSH CA's slots:\033[0m %v\n", err)
		} else if changed {
			fmt.Fprintf(c.out, "The SSH CA's slots are %s's now.\n", sshConfPath(controlConfigPath()))
		}
	}
	c.facts = f
	if len(f.Pending) > 0 {
		if c.tty {
			if err := c.offerRebuild(); err != nil {
				// A build hook of the machine's own (fsck without its
				// helper, say) fails the command after the image is
				// written: what counts is whether the image is new.
				if g := look(); len(g.Pending) == 0 {
					fmt.Fprintf(c.out, "\033[0;33mThe image is built\033[0m, and carries what control set up; %v - an error of the build's own, above.\n", err)
				} else {
					fmt.Fprintf(c.out, "\033[0;31mNot rebuilt:\033[0m %v\n", err)
				}
			}
			f = look()
			c.facts = f
		} else {
			fmt.Fprintf(c.out, "Rebuild the initramfs for the next boot (%s): %s\n", rebuildCommand(f.Initramfs), strings.Join(f.Pending, "; "))
		}
	}
	// What the image's hook did not approve: the image stayed as it is.
	if f.SSHCA.CA != nil && f.SSHCA.Values != nil && len(f.SSHCA.Unapproved()) > 0 {
		switch {
		case f.caWaitsForImage():
			fmt.Fprintf(c.out, "The SSH CA's slots take PCR 11 signed and the image carries no such signature: build it (%s), whose hook approves it; until then the next boot serves a temporary host key.\n", rebuildCommand(f.Initramfs))
		case !c.tty:
			fmt.Fprintln(c.out, "The SSH CA needs the signing key's approval of the PCRs at the next boot: run tpm2-kira control at a terminal.")
		default:
			if err := c.approveSSHCA(); err != nil {
				fmt.Fprintf(c.out, "\033[0;31mNot approved:\033[0m %v - the next boot serves a temporary host key\n", err)
			}
		}
	}
	for _, d := range c.facts.Status.Devices {
		if d.Error != "" || c.facts.Routed[d.Device] {
			continue
		}
		for _, ks := range d.Keyslots {
			if ks.Token != nil {
				fmt.Fprintf(c.out, "%s has a keyslot of tpm2-kira's but is not routed through it: tpm2-kira luks route\n", d.Device)
				break
			}
		}
	}
}

// The steps' actions: the expert commands' functions, with the defaults
// the analysis settled.

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// rebootNow asks systemd to reboot; a var for the tests.
var rebootNow = func() error { return exec.Command("systemctl", "reboot").Run() }
