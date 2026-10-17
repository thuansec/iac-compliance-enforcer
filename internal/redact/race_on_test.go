//go:build race

package redact_test

// raceSlowdown scales wall-clock limits in tests: the race detector slows the walk several times
// (see internal/terraform's race_ext_on_test.go for why scaling keeps the same margin).
const raceSlowdown = 10
