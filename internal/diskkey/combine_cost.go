//go:build !kira_test_fast_kdf

package diskkey

// The cost Combine uses: the production cost, in every build but a test build.
const (
	combineMemoryKiB   = productionMemoryKiB
	combineIterations  = productionIterations
	combineParallelism = productionParallelism
)

// TestBuildNote is what a test build says of itself; empty in this build.
const TestBuildNote = ""
