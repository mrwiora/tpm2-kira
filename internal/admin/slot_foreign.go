package admin

// An index of another shape at one of tpm2-kira's own places: an earlier
// build's or another program's. Only a person can tell, so it goes on a
// person's word, having seen it (nvslot.TakeForeign).

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/mrwiora/tpm2-kira/internal/nvslot"
	"github.com/mrwiora/tpm2-kira/internal/prompt"
)

// nvAttributeWords is an NV index's attributes in words, the TPM's own names.
func nvAttributeWords(a tpm2.TPMANV) string {
	kinds := map[tpm2.TPMNT]string{tpm2.TPMNTOrdinary: "ordinary", tpm2.TPMNTCounter: "counter", tpm2.TPMNTBits: "bits",
		tpm2.TPMNTExtend: "extend", tpm2.TPMNTPinFail: "pin_fail", tpm2.TPMNTPinPass: "pin_pass"}
	kind, ok := kinds[a.NT]
	if !ok {
		kind = fmt.Sprintf("type 0x%X", uint8(a.NT))
	}
	words := []string{kind}
	for _, f := range []struct {
		on   bool
		word string
	}{
		{a.PPWrite, "ppwrite"}, {a.OwnerWrite, "ownerwrite"}, {a.AuthWrite, "authwrite"}, {a.PolicyWrite, "policywrite"},
		{a.PolicyDelete, "policy_delete"}, {a.WriteLocked, "writelocked"}, {a.WriteAll, "writeall"}, {a.WriteDefine, "writedefine"},
		{a.WriteSTClear, "write_stclear"}, {a.GlobalLock, "globallock"}, {a.PPRead, "ppread"}, {a.OwnerRead, "ownerread"},
		{a.AuthRead, "authread"}, {a.PolicyRead, "policyread"}, {a.NoDA, "no_da"}, {a.Orderly, "orderly"},
		{a.ClearSTClear, "clear_stclear"}, {a.ReadLocked, "readlocked"}, {a.Written, "written"},
		{a.PlatformCreate, "platformcreate"}, {a.ReadSTClear, "read_stclear"},
	} {
		if f.on {
			words = append(words, f.word)
		}
	}
	return strings.Join(words, ", ")
}

// nameAlgWord is an index's name algorithm in words.
func nameAlgWord(alg tpm2.TPMIAlgHash) string {
	switch alg {
	case tpm2.TPMAlgSHA1:
		return "SHA-1"
	case tpm2.TPMAlgSHA256:
		return "SHA-256"
	case tpm2.TPMAlgSHA384:
		return "SHA-384"
	case tpm2.TPMAlgSHA512:
		return "SHA-512"
	}
	return fmt.Sprintf("0x%04X", uint16(alg))
}

// foreignText shows the index's public area, and why it may not be
// tpm2-kira's.
func foreignText(f nvslot.Foreign) string {
	policy := "none"
	if n := len(f.Public.AuthPolicy.Buffer); n > 0 {
		policy = fmt.Sprintf("yes, %d bytes", n)
	}
	return fmt.Sprintf(`
At the %s: an NV index of another shape than tpm2-kira defines there.
  handle          0x%08X
  attributes      %s
  defined here    %s
  name algorithm  %s
  size            %d bytes
  auth policy     %s
It may not be tpm2-kira's: an earlier build defined it otherwise, or another program put it here, and that program's data would go with it. The place is tpm2-kira's own, and sealing a slot would replace it as well.
`, kiraIndexRole(f.Index), f.Index, nvAttributeWords(f.Public.Attributes), nvAttributeWords(f.Want.Attributes),
		nameAlgWord(f.Public.NameAlg), f.Public.DataSize, policy)
}

// foreignAsk shows the index, then takes confirm's word on it.
func foreignAsk(out io.Writer, confirm func(title, description string) (bool, error)) nvslot.TakeForeign {
	return func(f nvslot.Foreign) (bool, error) {
		fmt.Fprint(out, foreignText(f))
		return confirm(fmt.Sprintf("Remove the NV index 0x%08X?", f.Index), "No leaves it, and what it belongs to dirty.")
	}
}

// slotDeleteForeign is slot delete's word on an index of another shape: force
// says yes; yes is the answer to another question and says no; a terminal asks;
// without one it is no. Every way shows the index.
func slotDeleteForeign(out io.Writer, yes, force bool) nvslot.TakeForeign {
	answer := func(a bool) func(string, string) (bool, error) {
		return func(string, string) (bool, error) { return a, nil }
	}
	switch {
	case force:
		return foreignAsk(out, answer(true))
	case yes:
		return foreignAsk(out, answer(false))
	}
	tty := setupTerminal()
	if tty == nil {
		return foreignAsk(out, answer(false))
	}
	p := prompt.New(tty, out)
	return foreignAsk(out, func(title, description string) (bool, error) { return p.Confirm(title, description, false) })
}

// foreignRemedy says what to do now about an index left at nvram: a slot's, or
// a place named by itself.
func foreignRemedy(nvram uint32) string {
	if nvslot.ValidateBlobIndex(nvram) != nil && !nvslot.OwnPlace(nvram) {
		return fmt.Sprintf("0x%08X is not one of tpm2-kira's own places, and nothing here removes what is there, --force neither.", nvram)
	}
	arg := fmt.Sprintf("0x%08X", nvram)
	if nvslot.ValidateBlobIndex(nvram) == nil {
		arg = fmt.Sprint(nvslot.SlotNumber(nvram))
	}
	return fmt.Sprintf("An index of another shape stays until a person says so: 'tpm2-kira control' (the slot's line) or 'tpm2-kira slot delete --nvram %s' at a terminal shows it and asks; 'tpm2-kira slot delete --nvram %s --force' removes it without asking.", arg, arg)
}

// foreignCause is why a slot is dirty when an index of it has another shape.
func foreignCause(foreign []nvslot.Foreign) string {
	var at []string
	for _, f := range foreign {
		at = append(at, fmt.Sprintf("%s (0x%08X)", kiraIndexRole(f.Index), f.Index))
	}
	return "at the " + strings.Join(at, " and the ") + " is an index of another shape than tpm2-kira defines there: an earlier build's, or another program's"
}
