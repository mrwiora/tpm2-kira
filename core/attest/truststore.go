package attest

// Pinned trust stores: certificate roots (and helper intermediates) embedded
// in the core, each file listed with its SHA-256 in the directory's
// vendors.json. Used for TPM endorsement keys (ekroots/, checked by the
// phone) and for Android key attestation (phoneroots/, checked by the
// machine). See ekroots/README.md for the rules.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// trustVendor is one entry of a trust store's vendors.json (ekroots/,
// phoneroots/), with its certificates read and their pinned fingerprints checked.
type trustVendor struct {
	Name          string       `json:"name"`
	Roots         []trustEntry `json:"roots"`         // trust anchors
	Intermediates []trustEntry `json:"intermediates"` // helpers, never anchors

	roots, inter [][]byte
}

type trustEntry struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// parseTrustStore reads vendors.json from fsys. A vendor whose files do not
// match their pinned SHA-256 is left out: its TPMs then show as "not
// verified", which is safe, rather than trusted on an unchecked anchor.
func parseTrustStore(fsys fs.FS) ([]*trustVendor, []error) {
	var errs []error
	raw, err := fs.ReadFile(fsys, "vendors.json")
	if err != nil {
		return nil, []error{err}
	}
	var m struct {
		Vendors []*trustVendor `json:"vendors"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, []error{fmt.Errorf("vendors.json: %w", err)}
	}
	read := func(e trustEntry) ([]byte, error) {
		b, err := fs.ReadFile(fsys, e.File)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != strings.ToLower(e.SHA256) {
			return nil, fmt.Errorf("%s does not match its pinned SHA-256", e.File)
		}
		if _, err := x509.ParseCertificate(b); err != nil {
			return nil, fmt.Errorf("%s: %w", e.File, err)
		}
		return b, nil
	}
	var out []*trustVendor
vendors:
	for _, v := range m.Vendors {
		if v.Name == "" || len(v.Roots) == 0 {
			errs = append(errs, fmt.Errorf("vendor %q has no name or no roots", v.Name))
			continue
		}
		for _, e := range v.Roots {
			b, err := read(e)
			if err != nil {
				errs = append(errs, fmt.Errorf("vendor %s: %w", v.Name, err))
				continue vendors
			}
			v.roots = append(v.roots, b)
		}
		for _, e := range v.Intermediates {
			b, err := read(e)
			if err != nil {
				errs = append(errs, fmt.Errorf("vendor %s: %w", v.Name, err))
				continue vendors
			}
			v.inter = append(v.inter, b)
		}
		out = append(out, v)
	}
	return out, errs
}
