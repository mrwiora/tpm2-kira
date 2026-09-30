package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// The PIN for the unattended reseal lives in /etc/mkinitcpio.conf, as
// 'export TPM2_KIRA_PIN=...'. mkinitcpio sources the file in its own shell
// and runs the post hook as a child process, so only an exported variable
// reaches the hook. A manual seal or reseal reads the same line, so the PIN
// is not asked for twice.

// mkinitcpioPIN is what /etc/mkinitcpio.conf provides to the post hook.
type mkinitcpioPIN int

const (
	mkinitcpioNotUsed       mkinitcpioPIN = iota // no mkinitcpio, or file unreadable
	mkinitcpioPINMissing                         // no TPM2_KIRA_PIN assignment
	mkinitcpioPINUnexported                      // assigned, but not exported
	mkinitcpioPINExported                        // reaches the post hook
)

// mkinitcpioPINInfo is the result of reading mkinitcpio.conf.
type mkinitcpioPINInfo struct {
	State mkinitcpioPIN
	// PIN is the value of the last assignment. It is empty when the value
	// cannot be known without running the shell ($VAR, $(...), `...`).
	PIN string
	// Loose is true when group or others may read the file.
	Loose bool
}

// readMkinitcpioPIN reads the TPM2_KIRA_PIN assignments of a mkinitcpio.conf.
// It understands what a PIN line looks like — NAME=value, export NAME=value,
// export NAME, with '...', "..." and backslash quoting — and nothing more;
// anything it cannot evaluate statically yields no PIN rather than a guess.
func readMkinitcpioPIN(path string) mkinitcpioPINInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return mkinitcpioPINInfo{State: mkinitcpioNotUsed}
	}
	info := mkinitcpioPINInfo{State: mkinitcpioPINMissing}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		info.Loose = true
	}

	assigned, exported := false, false
	for _, line := range strings.Split(string(data), "\n") {
		words := shellWords(line)
		if len(words) == 0 {
			continue
		}
		isExport := words[0] == "export"
		if isExport {
			words = words[1:]
		}
		for _, w := range words {
			switch {
			case strings.HasPrefix(w, PINEnvVar+"="):
				assigned = true
				pin, static := shellUnquote(strings.TrimPrefix(w, PINEnvVar+"="))
				info.PIN = ""
				if static {
					info.PIN = pin
				}
				if isExport {
					exported = true
				}
			case isExport && w == PINEnvVar:
				exported = true
			}
			if !isExport && !strings.Contains(w, "=") {
				break // a command, not an assignment
			}
		}
	}
	switch {
	case assigned && exported:
		info.State = mkinitcpioPINExported
	case assigned:
		info.State = mkinitcpioPINUnexported
	}
	return info
}

// shellWords splits one line into raw shell words, quotes kept, stopping at
// a comment or a ';'.
func shellWords(line string) []string {
	var words []string
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) || line[i] == '#' || line[i] == ';' {
			break
		}
		start := i
		for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != ';' {
			switch line[i] {
			case '\\':
				i += 2
				continue
			case '\'':
				if j := strings.IndexByte(line[i+1:], '\''); j >= 0 {
					i += j + 2
					continue
				}
				i = len(line)
				continue
			case '"':
				j := i + 1
				for j < len(line) && line[j] != '"' {
					if line[j] == '\\' {
						j++
					}
					j++
				}
				i = j + 1
				continue
			}
			i++
		}
		if i > len(line) {
			i = len(line)
		}
		words = append(words, line[start:i])
	}
	return words
}

// shellUnquote evaluates a shell word the way bash would, as long as that
// needs no expansion. static is false when the word contains $ or ` outside
// single quotes.
func shellUnquote(w string) (value string, static bool) {
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		switch c := w[i]; c {
		case '\'':
			j := strings.IndexByte(w[i+1:], '\'')
			if j < 0 {
				return "", false
			}
			b.WriteString(w[i+1 : i+1+j])
			i += j + 1
		case '"':
			i++
			for ; i < len(w) && w[i] != '"'; i++ {
				switch w[i] {
				case '$', '`':
					return "", false
				case '\\':
					if i+1 < len(w) && strings.IndexByte("\"\\$`", w[i+1]) >= 0 {
						i++
					}
				}
				b.WriteByte(w[i])
			}
			if i >= len(w) {
				return "", false
			}
		case '\\':
			if i+1 < len(w) {
				i++
				b.WriteByte(w[i])
			}
		case '$', '`':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// checkMkinitcpioPIN reports whether the post hook will get the PIN.
func checkMkinitcpioPIN(path string) mkinitcpioPIN {
	return readMkinitcpioPIN(path).State
}

// warnIfNoUnattendedPIN tells the user, right after the PIN was accepted for
// a manual seal or reseal, when the automatic reseal after an initramfs
// rebuild will not have it. Silent when mkinitcpio.conf exports the PIN, and
// on systems without mkinitcpio.
func warnIfNoUnattendedPIN(w io.Writer) {
	info := readMkinitcpioPIN(mkinitcpioConfPath)
	var problem, fix string
	switch info.State {
	case mkinitcpioPINMissing:
		problem = fmt.Sprintf("%s has no %s line", mkinitcpioConfPath, PINEnvVar)
		fix = "add the line"
	case mkinitcpioPINUnexported:
		problem = fmt.Sprintf("%s sets %s without 'export'; mkinitcpio passes\n"+
			"         only exported variables to its hooks", mkinitcpioConfPath, PINEnvVar)
		fix = "put 'export' in front of it, so it reads"
	default:
		return
	}
	fmt.Fprintf(w, "WARNING: %s.\n", problem)
	fmt.Fprintln(w, "         The automatic reseal after kernel and initramfs updates will therefore")
	fmt.Fprintln(w, "         have no PIN: it will be SKIPPED, and the next boot will show a PCR")
	fmt.Fprintf(w, "         mismatch until you reseal by hand. To make it work, %s\n", fix)
	fmt.Fprintf(w, "             export %s='<your PIN>'\n", PINEnvVar)
	fmt.Fprintf(w, "         and make the file readable by root only: chmod 600 %s\n", mkinitcpioConfPath)
}

// pinFromMkinitcpio returns the PIN set in mkinitcpio.conf, if it can be read
// there, and warns when the file lets others read it.
func pinFromMkinitcpio(w io.Writer) (string, bool) {
	info := readMkinitcpioPIN(mkinitcpioConfPath)
	if info.PIN == "" {
		return "", false
	}
	if info.Loose {
		fmt.Fprintf(w, "WARNING: %s holds the YubiKey PIN but can be read by other users.\n", mkinitcpioConfPath)
		fmt.Fprintf(w, "         Make it readable by root only: chmod 600 %s\n", mkinitcpioConfPath)
	}
	return info.PIN, true
}
