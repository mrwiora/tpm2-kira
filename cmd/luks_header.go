package cmd

// How a volume's key is made is written in its own LUKS2 header: the
// tpm2-kira token carries the mode and the slot (luks.go). At boot the key
// provider reads the header of the volume that asks - there is no
// configured unlock mode, nothing to copy into the initramfs and nothing
// to rebuild after an enrolment. The initrd has no cryptsetup binary to
// ask, so the header is read directly: the primary binary header names the
// JSON area, and the JSON area holds the tokens, exactly what
// 'cryptsetup luksDump --dump-json-metadata' would print.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// luks2Magic opens every LUKS2 primary header.
var luks2Magic = []byte("LUKS\xba\xbe")

// maxLuks2Header caps the JSON area read: the specification's largest
// header size is 4 MiB.
const maxLuks2Header = 4 << 20

// ReadLuks2Tokens reads the tpm2-kira tokens of a LUKS2 device straight
// from its header, without cryptsetup: for the initrd, where there is
// none. Keyslot numbers are not resolved here; the tokens alone say how a
// key is made and which slot it is bound to.
func ReadLuks2Tokens(device string) ([]LuksToken, error) {
	f, err := os.Open(device)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bin := make([]byte, 4096)
	if _, err := f.ReadAt(bin, 0); err != nil {
		return nil, fmt.Errorf("%s: reading the LUKS header: %w", device, err)
	}
	// The primary binary header: magic[6], version be16, hdr_size be64.
	if string(bin[:6]) != string(luks2Magic) {
		return nil, fmt.Errorf("%s holds no LUKS2 header", device)
	}
	if v := binary.BigEndian.Uint16(bin[6:8]); v != 2 {
		return nil, fmt.Errorf("%s: LUKS version %d, not 2", device, v)
	}
	hdrSize := binary.BigEndian.Uint64(bin[8:16])
	if hdrSize <= 4096 || hdrSize > maxLuks2Header {
		return nil, fmt.Errorf("%s: implausible LUKS2 header size %d", device, hdrSize)
	}
	area := make([]byte, hdrSize-4096)
	if _, err := f.ReadAt(area, 4096); err != nil {
		return nil, fmt.Errorf("%s: reading the LUKS2 JSON area: %w", device, err)
	}
	if i := strings.IndexByte(string(area), 0); i >= 0 {
		area = area[:i]
	}
	var md struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(area, &md); err != nil {
		return nil, fmt.Errorf("%s: the LUKS2 JSON area does not parse: %w", device, err)
	}
	var out []LuksToken
	for _, raw := range md.Tokens {
		if tok, ok := parseKiraToken(raw); ok {
			out = append(out, tok)
		}
	}
	return out, nil
}

// The files a volume's device is found through at boot; vars for the tests.
var (
	bootCmdlinePath   = "/proc/cmdline"
	bootCrypttabPaths = []string{"/etc/crypttab", "/cryptroot/crypttab", "/conf/conf.d/cryptroot"}
	bootByUUIDDir     = "/dev/disk/by-uuid"
)

// volumeDevice finds the block device behind a crypttab volume name, the
// way the initrd names it: rd.luks.name=<UUID>=<name> (or luks.name=) on
// the kernel command line, a crypttab line (systemd's /etc/crypttab in the
// initrd), or cryptsetup-initramfs's target=/source= lines on Debian.
func volumeDevice(volume string) (string, error) {
	// TPM2_KIRA_CRYPTTAB names an extra crypttab, for the integration
	// tests, whose volumes live on no kernel command line.
	if extra := os.Getenv("TPM2_KIRA_CRYPTTAB"); extra != "" {
		if data, err := os.ReadFile(extra); err == nil {
			if dev := crypttabDevice(string(data), volume); dev != "" {
				return dev, nil
			}
		}
	}
	if data, err := os.ReadFile(bootCmdlinePath); err == nil {
		for _, word := range strings.Fields(string(data)) {
			for _, key := range []string{"rd.luks.name=", "luks.name="} {
				if v, ok := strings.CutPrefix(word, key); ok {
					if uuid, name, ok := strings.Cut(v, "="); ok && name == volume {
						return bootByUUIDDir + "/" + strings.ToLower(uuid), nil
					}
				}
			}
		}
	}
	for _, path := range bootCrypttabPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if dev := crypttabDevice(string(data), volume); dev != "" {
			return dev, nil
		}
	}
	return "", fmt.Errorf("no device found for volume %q on the kernel command line or in a crypttab", volume)
}

// crypttabDevice finds volume's source in a crypttab: the systemd form
// ("name source ..."), or cryptsetup-initramfs's key=value lines
// ("target=name,source=...").
func crypttabDevice(data, volume string) string {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "target=") {
			var name, source string
			for _, kv := range strings.Split(line, ",") {
				if v, ok := strings.CutPrefix(kv, "target="); ok {
					name = v
				}
				if v, ok := strings.CutPrefix(kv, "source="); ok {
					source = v
				}
			}
			if name == volume {
				return sourceDevice(source)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == volume {
			return sourceDevice(fields[1])
		}
	}
	return ""
}

// sourceDevice turns a crypttab source field into a device path.
func sourceDevice(source string) string {
	if v, ok := strings.CutPrefix(source, "UUID="); ok {
		return bootByUUIDDir + "/" + strings.ToLower(v)
	}
	return source
}

// unlockRecipe says how the key of a volume is made, read from its LUKS2
// header the moment it asks: the remote salt's recipe when a keyslot is
// bound to it, else the typed salt's, else "" - not tpm2-kira's to answer,
// and why says so for the journal. Cached per volume: the header does not
// change while the initrd runs.
type unlockRecipe struct {
	mu    sync.Mutex
	cache map[string]string
}

func (r *unlockRecipe) forVolume(volume string) (mode, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mode, ok := r.cache[volume]; ok {
		return mode, ""
	}
	dev, err := volumeDevice(volume)
	if err != nil {
		return "", err.Error()
	}
	toks, err := ReadLuks2Tokens(dev)
	if err != nil {
		return "", err.Error()
	}
	mode = recipeOfTokens(toks)
	if r.cache == nil {
		r.cache = map[string]string{}
	}
	r.cache[volume] = mode
	if mode == "" {
		return "", dev + " has no keyslot of tpm2-kira's"
	}
	return mode, ""
}

// recipeOfTokens is the mode the tokens call for: the phone's salt wins
// over the typed one (a typed-salt keyslot next to it is the fallback).
func recipeOfTokens(toks []LuksToken) string {
	mode := ""
	for _, t := range toks {
		if t.Obsolete {
			continue // the old one-type form: re-marked, never acted on
		}
		switch t.Mode {
		case LuksModePasswordRemoteSalt:
			return LuksModePasswordRemoteSalt
		case LuksModePasswordSalt:
			mode = LuksModePasswordSalt
		}
	}
	return mode
}

// routedUUIDs are the volumes the kernel command line routes to the
// unlock socket (rd.luks.key=<UUID>=<socket>), for the code screen's
// words before any volume has asked.
func routedUUIDs(cmdline, socket string) []string {
	var uuids []string
	for _, word := range strings.Fields(cmdline) {
		for _, key := range []string{"rd.luks.key=", "luks.key="} {
			v, ok := strings.CutPrefix(word, key)
			if !ok {
				continue
			}
			if uuid, sock, ok := strings.Cut(v, "="); ok && sock == socket {
				uuids = append(uuids, strings.ToLower(uuid))
			}
		}
	}
	return uuids
}

// screenRecipe is the recipe of the first routed volume, for the code
// screen's words ("continue to ..."): resolved lazily, cached once known,
// "" while no routed header is readable yet (the prompt then names
// cryptsetup's).
func screenRecipe(socket string) func() string {
	var mu sync.Mutex
	known := ""
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if known != "" {
			return known
		}
		data, err := os.ReadFile(bootCmdlinePath)
		if err != nil {
			return ""
		}
		for _, uuid := range routedUUIDs(string(data), socket) {
			if toks, err := ReadLuks2Tokens(bootByUUIDDir + "/" + uuid); err == nil {
				if mode := recipeOfTokens(toks); mode != "" {
					known = mode
					return known
				}
			}
		}
		return ""
	}
}
