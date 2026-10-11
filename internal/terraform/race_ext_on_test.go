//go:build race

package terraform_test

// raceSlowdown scales wall-clock limits in tests: the race detector slows evaluation several
// times, and parallel tests share the machine. This is not a weakening: the race detector slows
// the bounded path and a regressed one by about the same factor, so the scaled limit keeps the
// same margin over the bounded time and below the regression (5 s against 50 ms without -race,
// 50 s against about 0.6 s with it). Without -race the limits apply as written, which the quick
// gate (go test -short) enforces; the full gate and CI run only with -race. Wall-clock limits
// are scaled by it, except caps already sized for -race (20 s and 120 s). T-0123: fixed 2 s and
// 5 s limits failed under the race detector at 1.02 to 1.24 times their value.
const raceSlowdown = 10
