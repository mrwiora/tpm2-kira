//go:build kira_test_fast_kdf

package diskkey

// A test build's cost, for test boots alone (tools/vmtest.py --fast-kdf). The
// build tag is the one thing that selects this file: no release recipe passes
// it, and packaging/release-binary-check.sh refuses a binary built with a tag.
// A keyslot enrolled by this build does not open with a release build's key,
// nor the other way round.
const (
	combineMemoryKiB   uint32 = 16 * 1024
	combineIterations  uint32 = 1
	combineParallelism uint8  = 4
)

// TestBuildNote is what this build says of itself, in its version and its
// status: it must not protect a disk.
const TestBuildNote = "TEST BUILD (kira_test_fast_kdf): Argon2id at 16 MiB and 1 pass, not 1 GiB and 16; not for a real disk, and no final proof"
