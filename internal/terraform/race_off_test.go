//go:build !race

package terraform

// raceEnabled reports that tests run under the race detector.
const raceEnabled = false

// raceSlowdown scales wall-clock limits in tests: the race detector slows evaluation several
// times, and parallel tests share the machine.
const raceSlowdown = 1
