//go:build race

package terraform_test

// raceSlowdown scales wall-clock limits in tests: the race detector slows evaluation several
// times, and parallel tests share the machine.
const raceSlowdown = 10
