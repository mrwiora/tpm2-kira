package admin

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
	"github.com/tpm2-trust/tpm2-kira/internal/tui"
)

// control's full screen: the sections on the left, the selected section's steps and
// the selected step's detail on the right - what it does, its state, the command it
// equals, what it destroys - and the keys at the bottom. It draws the same model as
// the line menus (control_model.go). A step runs in the terminal as the line menus run
// it: the screen is given back for it, its questions are prompt's, and the screen comes
// back when it is read. The facts come in the background: the screen is up at once.

// Where the focus is.
const (
	focusSections = iota
	focusSteps
)

// screenState is what the screen shows, apart from the facts: pure, so keys can be
// tested without a terminal.
type screenState struct {
	section, step int // the selected section and its selected step
	focus         int
	scroll        int  // the detail pane's first row
	help          bool // the keys' help in place of the detail
	searching     bool
	query         string
	hit           int    // the selected search result
	message       string // the status row's last word
}

// screenCmd is what a key asks of the loop.
type screenCmd int

const (
	cmdNone screenCmd = iota
	cmdRun
	cmdQuit
	cmdRefresh
	cmdRedraw
)

// controlModel is every section's steps, as the screen draws them.
type controlModel [][]controlStep

func (c *controller) model() controlModel {
	m := make(controlModel, len(controlSections))
	for i, sec := range controlSections {
		m[i] = c.annotated(c.sectionSteps(sec.key))
	}
	return m
}

// searchHit is a step a search found: its section and its place there.
type searchHit struct{ section, step int }

// search is every step whose title, state, command or explanation holds q.
func (m controlModel) search(q string) []searchHit {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	// The steps whose title holds it first, then those whose command, state or
	// explanation does.
	var titles, rest []searchHit
	for i, steps := range m {
		for j, s := range steps {
			text := strings.ToLower(tui.StripSGR(strings.Join([]string{s.Done, s.Blocked, s.Dirty, s.Command, s.Explain}, " ")))
			switch {
			case strings.Contains(strings.ToLower(tui.StripSGR(s.Title)), q):
				titles = append(titles, searchHit{i, j})
			case strings.Contains(text, q):
				rest = append(rest, searchHit{i, j})
			}
		}
	}
	return append(titles, rest...)
}

// selected is the step under the cursor, or nil.
func (st *screenState) selected(m controlModel) *controlStep {
	if st.section >= len(m) || st.step >= len(m[st.section]) {
		return nil
	}
	return &m[st.section][st.step]
}

// clamp keeps the selection inside the model, which changes after every refresh.
func (st *screenState) clamp(m controlModel) {
	st.section = min(max(st.section, 0), len(m)-1)
	n := len(m[st.section])
	if n == 0 {
		st.step = 0
		if st.focus == focusSteps {
			st.focus = focusSections
		}
		return
	}
	st.step = min(max(st.step, 0), n-1)
}

// key takes one key; what it asks of the loop comes back.
func (st *screenState) key(k tui.Key, m controlModel, page int) screenCmd {
	if st.searching {
		return st.searchKey(k, m)
	}
	st.message = ""
	switch k.Name {
	case tui.KeyCtrlC, tui.KeyCtrlD:
		return cmdQuit
	case tui.KeyCtrlL:
		return cmdRedraw
	case tui.KeyUp:
		st.move(-1, m)
	case tui.KeyDown:
		st.move(1, m)
	case tui.KeyPgUp:
		st.scroll = max(st.scroll-page, 0)
	case tui.KeyPgDn:
		st.scroll += page
	case tui.KeyHome:
		st.move(-1000, m)
	case tui.KeyEnd:
		st.move(1000, m)
	case tui.KeyRight, tui.KeyTab:
		if st.focus == focusSections && len(m[st.section]) > 0 {
			st.focus, st.scroll = focusSteps, 0
		}
	case tui.KeyLeft, tui.KeyBackTab:
		st.focus, st.scroll = focusSections, 0
	case tui.KeyEsc:
		switch {
		case st.help:
			st.help = false
		case st.focus == focusSteps:
			st.focus, st.scroll = focusSections, 0
		default:
			return cmdQuit
		}
	case tui.KeyEnter:
		return st.enter(m)
	case tui.KeyRune:
		switch k.Rune {
		case 'q':
			return cmdQuit
		case 'k':
			st.move(-1, m)
		case 'j':
			st.move(1, m)
		case 'h':
			st.focus, st.scroll = focusSections, 0
		case 'l':
			if len(m[st.section]) > 0 {
				st.focus, st.scroll = focusSteps, 0
			}
		case 'r':
			return cmdRefresh
		case '?':
			st.help = !st.help
		case '/':
			st.searching, st.query, st.hit = true, "", 0
		}
	}
	return cmdNone
}

func (st *screenState) move(by int, m controlModel) {
	st.scroll = 0
	if st.focus == focusSections {
		st.section = min(max(st.section+by, 0), len(m)-1)
		st.step = 0
		return
	}
	if n := len(m[st.section]); n > 0 {
		st.step = min(max(st.step+by, 0), n-1)
	}
}

// enter acts on the selection: a section opens, a step that opens a section jumps
// there, a blocked one says why, any other runs.
func (st *screenState) enter(m controlModel) screenCmd {
	if st.focus == focusSections {
		if len(m[st.section]) > 0 {
			st.focus, st.step, st.scroll = focusSteps, 0, 0
		}
		return cmdNone
	}
	s := st.selected(m)
	if s == nil {
		return cmdNone
	}
	switch {
	case s.Menu != "":
		for i, sec := range controlSections {
			if sec.key == sectionOf(s.Menu) {
				st.section, st.step, st.scroll = i, 0, 0
			}
		}
		return cmdNone
	case s.Dirty != "":
		return cmdRun
	case s.Done != "" && s.Check:
		st.message = "In place: " + s.Done
		return cmdNone
	case s.Done == "" && s.Blocked != "":
		st.message = "Not possible here: " + s.Blocked
		return cmdNone
	case s.Run == nil:
		return cmdNone
	}
	return cmdRun
}

func (st *screenState) searchKey(k tui.Key, m controlModel) screenCmd {
	hits := m.search(st.query)
	switch k.Name {
	case tui.KeyEsc, tui.KeyCtrlC:
		st.searching = false
	case tui.KeyEnter:
		st.searching = false
		if st.hit < len(hits) {
			h := hits[st.hit]
			st.section, st.step, st.focus, st.scroll = h.section, h.step, focusSteps, 0
		}
	case tui.KeyBackspace:
		if r := []rune(st.query); len(r) > 0 {
			st.query, st.hit = string(r[:len(r)-1]), 0
		}
	case tui.KeyUp:
		st.hit = max(st.hit-1, 0)
	case tui.KeyDown:
		st.hit = min(st.hit+1, max(len(hits)-1, 0))
	case tui.KeyRune:
		st.query, st.hit = st.query+string(k.Rune), 0
	}
	return cmdNone
}

// frameView is what a frame is drawn from: the facts' texts come with it, as they are
// the controller's.
type frameView struct {
	header   string
	status   string // the overview's facts, judged
	prereqs  string // the boot chain's prerequisites
	loading  bool   // no facts yet
	checking bool   // the slow facts are still coming
}

// frame draws the screen: cols by rows, the glyphs g.
func (st *screenState) frame(m controlModel, v frameView, cols, rows int, g tui.Glyphs) []string {
	out := make([]string, 0, rows)
	out = append(out, tui.Fit(v.header, cols, g.Ellipsis), "\033[2m"+strings.Repeat(g.Horiz, cols)+"\033[0m")
	body := rows - 4
	var main []string
	if cols >= 72 {
		side := 22
		width := cols - side - 3
		left := st.sidebar(m, g, side)
		right := st.mainPane(m, v, width, body, g)
		main = tui.Columns(" "+"\033[2m"+g.Vert+"\033[0m"+" ", []int{side, width}, pad(left, body), pad(right, body))
	} else if st.focus == focusSections && !st.searching {
		main = pad(st.sidebar(m, g, cols), body)
	} else {
		main = pad(st.mainPane(m, v, cols, body, g), body)
	}
	out = append(out, main[:body]...)
	out = append(out, "\033[2m"+strings.Repeat(g.Horiz, cols)+"\033[0m", st.statusRow(m, v, cols))
	return out
}

func pad(rows []string, n int) []string {
	for len(rows) < n {
		rows = append(rows, "")
	}
	return rows[:n]
}

// sidebar is the sections, each with a mark of how it stands.
func (st *screenState) sidebar(m controlModel, g tui.Glyphs, width int) []string {
	var out []string
	for i, sec := range controlSections {
		mark := " "
		for _, s := range m[i] {
			if s.Dirty != "" {
				mark = bad(g.Bad)
				break
			}
		}
		label := mark + " " + sec.title
		if i == st.section {
			if st.focus == focusSections {
				label = "\033[7m" + tui.Fit(label, width, g.Ellipsis) + "\033[0m"
			} else {
				label = "\033[1m" + label + "\033[0m"
			}
		}
		out = append(out, label)
	}
	return out
}

// stepRow is a step's row in the list: its mark, its title, how it stands.
func stepRow(s controlStep, g tui.Glyphs) string {
	var mark, state string
	switch {
	case s.Dirty != "":
		mark, state = bad(g.Bad), bad(s.Dirty)
	case s.Done != "":
		mark, state = good(g.Good), s.Done
	case s.Blocked != "":
		mark, state = "\033[2m"+g.Blocked+"\033[0m", "\033[2m"+s.Blocked+"\033[0m"
	case s.Danger == dangerView:
		mark = " "
	default:
		mark = amber(g.Open)
	}
	title := s.Title
	if s.Blocked != "" && s.Done == "" && s.Dirty == "" {
		title = "\033[2m" + title + "\033[0m"
	}
	if s.Danger == dangerDestroy {
		title += " " + bad(g.Warn)
	}
	if s.Menu != "" {
		title += " " + g.More
	}
	if state != "" {
		return mark + " " + title + "  \033[2m-\033[0m " + state
	}
	return mark + " " + title
}

// mainPane is the section's intro and steps, and below them the selection's detail.
func (st *screenState) mainPane(m controlModel, v frameView, width, height int, g tui.Glyphs) []string {
	if st.searching {
		return st.searchPane(m, width, height, g)
	}
	sec := controlSections[st.section]
	out := []string{"\033[1m" + sec.title + "\033[0m"}
	if v.loading {
		return append(out, "", "\033[2mLooking at this machine ...\033[0m")
	}
	steps := m[st.section]
	listRoom := min(len(steps), max(height/2-2, 3))
	first := 0
	if st.step >= listRoom {
		first = st.step - listRoom + 1
	}
	for i := first; i < len(steps) && i < first+listRoom; i++ {
		row := stepRow(steps[i], g)
		if i == st.step && st.focus == focusSteps {
			row = "\033[7m" + tui.Fit(tui.StripSGR(row), width, g.Ellipsis) + "\033[0m"
		}
		out = append(out, row)
	}
	if len(steps) > listRoom {
		out = append(out, fmt.Sprintf("\033[2m  (%d of %d)\033[0m", st.step+1, len(steps)))
	}
	out = append(out, "\033[2m"+strings.Repeat(g.Horiz, width)+"\033[0m")
	detail := st.detail(m, v, width, g)
	if st.scroll > max(len(detail)-1, 0) {
		st.scroll = max(len(detail)-1, 0)
	}
	return append(out, detail[st.scroll:]...)
}

// detail is the selected step's: what it does and how it stands - or, on the sections,
// the section's intro with, for the overview and the boot chain, the machine's facts.
func (st *screenState) detail(m controlModel, v frameView, width int, g tui.Glyphs) []string {
	text := ""
	switch {
	case st.help:
		text = screenHelp
	case st.focus == focusSections:
		sec := controlSections[st.section]
		text = sec.intro
		switch sec.key {
		case "overview":
			text += "\n\n" + heading("What this machine has") + "\n" + v.status
		case "chain":
			text += "\n\n" + heading("Prerequisites") + "\n" + v.prereqs
		}
	default:
		s := st.selected(m)
		if s == nil {
			break
		}
		var b strings.Builder
		b.WriteString(heading(s.Title) + "\n")
		switch {
		case s.Dirty != "":
			b.WriteString(bad("Needs attention: "+s.Dirty) + "\n")
		case s.Done != "":
			b.WriteString(good("Done: ") + s.Done + "\n")
		case s.Blocked != "":
			b.WriteString("\033[2mNot possible here: " + s.Blocked + "\033[0m\n")
		}
		if s.Explain != "" {
			b.WriteString("\n" + s.Explain + "\n")
		}
		if s.Danger == dangerDestroy && s.Destroys != "" {
			b.WriteString("\n" + bad(g.Warn+" Destroys: ") + s.Destroys + "\n")
		}
		if s.Command != "" {
			b.WriteString("\n\033[2mThe command:\033[0m " + s.Command + "\n")
		}
		text = b.String()
	}
	return tui.Layout(strings.TrimRight(text, "\n"), width, 0)
}

func (st *screenState) searchPane(m controlModel, width, height int, g tui.Glyphs) []string {
	out := []string{"\033[1mSearch:\033[0m " + st.query + "_", ""}
	hits := m.search(st.query)
	for i, h := range hits {
		if len(out) >= height {
			break
		}
		row := controlSections[h.section].title + " " + g.More + " " + tui.StripSGR(m[h.section][h.step].Title)
		if i == st.hit {
			row = "\033[7m" + tui.Fit(row, width, g.Ellipsis) + "\033[0m"
		}
		out = append(out, row)
	}
	if st.query != "" && len(hits) == 0 {
		out = append(out, "\033[2mNothing found.\033[0m")
	}
	return out
}

// statusRow is the keys, or the last message.
func (st *screenState) statusRow(m controlModel, v frameView, cols int) string {
	switch {
	case st.searching:
		return "\033[2mtype to search  ↑↓ pick  Enter go there  Esc back\033[0m"
	case st.message != "":
		return amber(st.message)
	}
	keys := "↑↓ move  ←→ in/out  Enter run  / search  ? keys  r again  q quit"
	if v.checking {
		keys += "  · checking ..."
	}
	return "\033[2m" + keys + "\033[0m"
}

// screenHelp is the keys, on '?'.
const screenHelp = `Keys

  Up, Down, j, k     move in the sections, or in a section's steps
  Right, Tab, l      from the sections into the steps
  Left, h, Esc       back to the sections
  Enter              open a section; run a step (a blocked one says why)
  PgUp, PgDn         scroll the detail
  /                  search every step of every section
  r                  look at the machine again
  Ctrl-L             draw the screen again
  ?                  this help, again to close it
  q, Esc, Ctrl-C     leave: the boot image is built then, when it is out of date

A step that changes the machine runs in the terminal below the screen, asks what it
needs, and comes back here. One that destroys (marked) asks for its word: the slot's
or keyslot's number, or "delete".`

// fullScreen says whether control draws its full screen: a terminal with a size, not
// dumb, not --lines, not --debug (whose output would run through the frame).
func (c *controller) fullScreen() bool {
	if c.o.Lines || c.o.Debug || !c.tty || !tui.IsTerminal(os.Stdout) || os.Getenv("TERM") == "dumb" {
		return false
	}
	cols, rows, ok := tui.Open(c.input(), c.out).Size()
	return ok && cols >= 40 && rows >= 12
}

// header is the full screen's top row: the version, the host, Secure Boot, the image.
func (c *controller) screenHeader(loading bool) string {
	v := nvslot.AppVersion
	if v == "" {
		v = "unknown"
	}
	host, _ := os.Hostname()
	h := fmt.Sprintf("[ \033[1;33mKIRA\033[0m ] control %s · %s", v, host)
	if loading {
		return h
	}
	f := &c.facts
	switch {
	case !f.SecureBoot.Known:
		h += " · " + bad("Secure Boot unknown")
	case f.SecureBoot.SetupMode:
		h += " · " + bad("Secure Boot: Setup Mode")
	case f.SecureBoot.Enabled:
		h += " · " + good("Secure Boot on")
	default:
		h += " · " + bad("Secure Boot off")
	}
	if n := len(f.Pending); n > 0 {
		h += " · " + amber(fmt.Sprintf("image out of date (%d)", n))
	}
	return h
}

// screenLoop is control on its full screen, until it is left.
func (c *controller) screenLoop() error {
	term := tui.Open(c.input(), c.out)
	g := tui.GlyphsFor(tui.UTF8Locale())
	scr := tui.NewScreen(c.out, tui.Colour(), g)
	keys := tui.NewReader(term.FD())
	st := &screenState{}

	// The facts, in the background: the fast ones first, the slow ones after.
	type facts struct {
		f    machineFacts
		slow bool
	}
	got := make(chan facts, 2)
	collecting := false
	collect := func() {
		collecting = true
		go func() {
			f := c.fastFacts()
			got <- facts{f, false}
			c.slowFacts(&f)
			got <- facts{f, true}
		}()
	}
	loading := true
	collect()

	if err := term.Enter(); err != nil {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			term.Leave()
			panic(r)
		}
	}()
	var m controlModel
	draw := func() {
		cols, rows, ok := term.Size()
		if !ok {
			cols, rows = 80, 24
		}
		if !loading {
			m = c.model()
			st.clamp(m)
		} else {
			m = make(controlModel, len(controlSections))
		}
		v := frameView{header: c.screenHeader(loading), loading: loading, checking: !loading && c.facts.Checking}
		if !loading {
			v.status = c.factsText()
			if notes := c.facts.Status.Notes; len(notes) > 0 {
				v.status += "\n" + heading("Notes")
				for _, n := range notes {
					v.status += "\n- " + n
				}
			}
			v.prereqs = c.prereqText()
		}
		scr.Draw(st.frame(m, v, cols, rows, g), cols)
	}
	draw()
	for {
		select {
		case fs := <-got:
			c.facts, loading = fs.f, false
			if fs.slow {
				collecting = false
			}
			draw()
			continue
		case <-term.Resized():
			scr.Invalidate()
			draw()
			continue
		default:
		}
		k, ok, err := keys.Read(200 * time.Millisecond)
		if err != nil {
			term.Leave()
			return err
		}
		if !ok {
			continue
		}
		_, rows, _ := term.Size()
		switch st.key(k, m, max(rows/2, 5)) {
		case cmdQuit:
			term.Leave()
			for collecting { // the slow facts finish first: leave looks again anyway
				fs := <-got
				collecting = !fs.slow
			}
			c.leave()
			return nil
		case cmdRefresh:
			if !collecting {
				st.message = "Looking at this machine again ..."
				collect()
			}
		case cmdRedraw:
			scr.Invalidate()
		case cmdRun:
			if s := st.selected(m); s != nil && !loading {
				for collecting { // a step works on the whole facts
					fs := <-got
					c.facts, collecting = fs.f, !fs.slow
				}
				step := *s
				term.Leave()
				c.runStep(step)
				if err := term.Enter(); err != nil {
					return err
				}
				scr.Invalidate()
				loading = true
				collect()
			}
		}
		draw()
	}
}

// runStep runs a step in the terminal, below the screen: its title, what it does, its
// questions, its result, and a key before the screen comes back.
func (c *controller) runStep(s controlStep) {
	fmt.Fprint(c.out, clearScreen)
	if s.Done != "" && !s.SelfConfirm {
		again, err := c.confirm(s.Title+" is done: "+s.Done+". Run it again?", "")
		if err != nil || !again {
			return
		}
	}
	fmt.Fprintf(c.out, "\n\033[1m%s\033[0m\n%s\n\n", s.Title, s.Explain)
	if err := s.Run(c); err != nil {
		fmt.Fprintf(c.out, "\n\033[0;31mNot done:\033[0m %v\n", err)
	}
	c.ask().Wait("Back to control", "", "OK")
}
