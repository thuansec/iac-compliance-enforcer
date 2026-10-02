package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/thuansec/iac-compliance-enforcer/internal/cli"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){"iace": cli.Main})
}

func TestScripts(t *testing.T) {
	t.Parallel()

	testscript.Run(t, testscript.Params{Dir: "testdata/script", RequireExplicitExec: true})
}

// TestLdflagsInjection builds the real binary the way releases do. The -X linker flag silently
// ignores a variable path that does not exist, so only a real build proves the injection works.
func TestLdflagsInjection(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("builds the iace binary; runs without -short (T-0003)")
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain not found: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "iace")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	const pkg = "github.com/thuansec/iac-compliance-enforcer/internal/version"
	ldflags := "-X " + pkg + ".Version=v9.8.7 -X " + pkg + ".Commit=0123abc -X " + pkg + ".Date=2026-10-02T00:00:00Z"
	build := exec.CommandContext(t.Context(), goBin, "build", "-trimpath", "-ldflags", ldflags, "-o", bin, ".")
	// go build needs the caller's environment (module and build caches).
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	out, err := exec.CommandContext(t.Context(), bin, "version", "--json").Output()
	if err != nil {
		t.Fatalf("iace version --json: %v", err)
	}
	var got struct{ Version, Commit, Date string }
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if got.Version != "v9.8.7" || got.Commit != "0123abc" || got.Date != "2026-10-02T00:00:00Z" {
		t.Errorf("version --json = %+v, want the injected v9.8.7, 0123abc, 2026-10-02T00:00:00Z", got)
	}
}
