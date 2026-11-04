// Package screen is the [ KIRA ] tag of the boot's lines.
package screen

// Tag is the "[ KIRA ]" tag in a colour: yellow for the screen and its
// lines, blue for the prompt, purple for the phone's code.
func Tag(colour string) string { return "[ \033[1;" + colour + "mKIRA\033[0m ]" }

// The tag's colours.
const (
	TagYellow = "33"
	TagBlue   = "34"
	TagPurple = "35"
)
