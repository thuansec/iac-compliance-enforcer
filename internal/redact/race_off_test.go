//go:build !race

package redact_test

// raceSlowdown scales wall-clock limits in tests: without the race detector, they apply as
// written.
const raceSlowdown = 1
