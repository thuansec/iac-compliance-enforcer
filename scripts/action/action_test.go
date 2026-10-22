// Package action_test checks the composite GitHub Action (action.yml at the repository root) and
// the helper scripts it runs. GitHub runs the action itself only on a runner (selftest, T-0503);
// these tests cover its contract and run the helpers on fixtures, offline.
package action_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type actionStep struct {
	ID    string            `yaml:"id"`
	Name  string            `yaml:"name"`
	If    string            `yaml:"if"`
	Uses  string            `yaml:"uses"`
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
	Env   map[string]string `yaml:"env"`
	With  map[string]string `yaml:"with"`
	Dir   string            `yaml:"working-directory"`
}

type actionFile struct {
	Name    string                       `yaml:"name"`
	Inputs  map[string]map[string]string `yaml:"inputs"`
	Outputs map[string]map[string]string `yaml:"outputs"`
	Runs    struct {
		Using string       `yaml:"using"`
		Steps []actionStep `yaml:"steps"`
	} `yaml:"runs"`
}

func loadAction(t *testing.T) actionFile {
	t.Helper()
	data, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var a actionFile
	if err := yaml.Unmarshal(data, &a); err != nil {
		t.Fatalf("action.yml: %v", err)
	}
	return a
}

func stepIndex(t *testing.T, a actionFile, id string) int {
	t.Helper()
	i := slices.IndexFunc(a.Runs.Steps, func(s actionStep) bool { return s.ID == id })
	if i < 0 {
		t.Fatalf("action.yml has no step with id %q", id)
	}
	return i
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// The inputs are the consumer-workflow reference's, minus config, org-config and fail-on, which
// T-0506 adds; an input that does nothing must not exist.
func TestActionInputsAndOutputs(t *testing.T) {
	t.Parallel()
	a := loadAction(t)
	if a.Runs.Using != "composite" {
		t.Errorf("runs.using = %q, want composite", a.Runs.Using)
	}
	wantInputs := []string{"ai-fix", "annotations", "category", "path", "sarif-file", "upload-sarif", "version"}
	if got := sortedKeys(a.Inputs); !slices.Equal(got, wantInputs) {
		t.Errorf("inputs = %v, want %v", got, wantInputs)
	}
	defaults := map[string]string{
		"version": "", "path": ".", "sarif-file": "iace.sarif", "upload-sarif": "true",
		"category": "iace", "annotations": "true", "ai-fix": "false",
	}
	for name, want := range defaults {
		if got := a.Inputs[name]["default"]; got != want {
			t.Errorf("input %s default = %q, want %q", name, got, want)
		}
		if a.Inputs[name]["description"] == "" {
			t.Errorf("input %s has no description", name)
		}
	}
	wantOutputs := []string{"blocking-count", "exit-code", "sarif-file"}
	if got := sortedKeys(a.Outputs); !slices.Equal(got, wantOutputs) {
		t.Errorf("outputs = %v, want %v", got, wantOutputs)
	}
}

var pinnedUse = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)

// Every action is pinned to a full commit SHA, and no input or event value is expanded inside a
// script: run steps read them from env (script injection).
func TestActionStepsAreHardened(t *testing.T) {
	t.Parallel()
	a := loadAction(t)
	for _, s := range a.Runs.Steps {
		if s.Uses != "" && !pinnedUse.MatchString(s.Uses) {
			t.Errorf("step %q uses %q, not pinned to a commit SHA", s.Name, s.Uses)
		}
		if s.Run != "" {
			if strings.Contains(s.Run, "${{") {
				t.Errorf("step %q expands an expression inside run; pass it through env", s.Name)
			}
			if s.Shell != "bash" {
				t.Errorf("step %q shell = %q, want bash", s.Name, s.Shell)
			}
		}
	}
}

// The scan runs from the repository root, its result is published even when it found issues,
// and the job fails on the scan's exit code only after the summary and the SARIF upload.
func TestActionPublishesBeforeFailing(t *testing.T) {
	t.Parallel()
	a := loadAction(t)
	scan, report, upload, exit := stepIndex(t, a, "scan"), stepIndex(t, a, "report"),
		stepIndex(t, a, "upload"), stepIndex(t, a, "exit")
	if scan >= report || report >= upload || upload >= exit || exit != len(a.Runs.Steps)-1 {
		t.Fatalf("step order scan=%d report=%d upload=%d exit=%d of %d; want scan, report, upload, then exit last",
			scan, report, upload, exit, len(a.Runs.Steps))
	}
	steps := a.Runs.Steps
	if steps[scan].Dir != "${{ github.workspace }}" {
		t.Errorf("scan working-directory = %q, want the repository root", steps[scan].Dir)
	}
	for _, i := range []int{report, upload, exit} {
		if !strings.Contains(steps[i].If, "always()") {
			t.Errorf("step %q if = %q, want it to run after a failed scan (always())", steps[i].Name, steps[i].If)
		}
	}
	up := steps[upload]
	if !strings.HasPrefix(up.Uses, "github/codeql-action/upload-sarif@") {
		t.Errorf("upload step uses %q", up.Uses)
	}
	if up.With["category"] != "${{ inputs.category }}" {
		t.Errorf("upload category = %q, want the category input", up.With["category"])
	}
	if !strings.Contains(up.If, "steps.scan.outputs.upload == 'true'") {
		t.Errorf("upload if = %q, want it gated on a completed scan (exit code 0 or 1)", up.If)
	}
	if !strings.Contains(up.If, "inputs.upload-sarif == 'true'") {
		t.Errorf("upload if = %q, want it gated on the upload-sarif input", up.If)
	}
	if !strings.Contains(steps[exit].Run, "exit") || steps[exit].Env["IACE_EXIT_CODE"] != "${{ steps.scan.outputs.exit-code }}" {
		t.Errorf("exit step does not exit with the scan's code: env %v", steps[exit].Env)
	}
}

func python(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Fatal("python3 is required to test scripts/action/report.py")
	return ""
}

type reportRun struct {
	stdout, summary, output string
	err                     error
}

func runReport(t *testing.T, sarifFile, annotations, exitCode string) reportRun {
	t.Helper()
	dir := t.TempDir()
	summary, output := filepath.Join(dir, "summary.md"), filepath.Join(dir, "output")
	cmd := exec.CommandContext(t.Context(), python(t), "-I", "report.py", sarifFile)
	cmd.Env = append(os.Environ(),
		"GITHUB_STEP_SUMMARY="+summary, "GITHUB_OUTPUT="+output,
		"IACE_ANNOTATIONS="+annotations, "IACE_EXIT_CODE="+exitCode)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	s, _ := os.ReadFile(summary)
	o, _ := os.ReadFile(output)
	return reportRun{stdout: stdout.String(), summary: string(s), output: string(o), err: err}
}

func TestReportSummarizesTheGoldenSARIF(t *testing.T) {
	t.Parallel()
	r := runReport(t, "../../internal/report/sarif/testdata/report.golden.sarif", "true", "1")
	if r.err != nil {
		t.Fatalf("report.py: %v", r.err)
	}
	// Open error-level results block at the action's fixed fail-on (high); excepted ones do not.
	if !strings.Contains(r.output, "blocking-count=") {
		t.Fatalf("no blocking-count output: %q", r.output)
	}
	for _, want := range []string{"## iace", "exit code 1", "IACE-AWS-S3-002", "coverage gap in infra"} {
		if !strings.Contains(r.summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, r.summary)
		}
	}
	if !strings.Contains(r.stdout, "::error file=infra/main.tf,line=3,title=IACE-AWS-S3-002::aws_s3_bucket.a is not compliant") {
		t.Errorf("annotations lack the S3-002 error:\n%s", r.stdout)
	}
}

const hostileSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"iace","rules":[]}},"results":[
 {"ruleId":"IACE-AWS-S3-002","level":"error","message":{"text":"bad\n::error::injected 100% | <b>x</b>"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"infra/a%2Cb%3Ac/m%C3%A4in.tf"},"region":{"startLine":7}}}]},
 {"ruleId":"IACE-AWS-S3-003","level":"warning","message":{"text":"w"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.tf"},"region":{"startLine":1}}}]},
 {"ruleId":"IACE-AWS-S3-009","level":"note","message":{"text":"n"},"locations":[]},
 {"ruleId":"IACE-AWS-S3-009","level":"note","message":{"text":"a\\|b"},"locations":[]},
 {"ruleId":"IACE-AWS-S3-002","level":"error","message":{"text":"excepted"},
  "suppressions":[{"kind":"external","status":"accepted"}],
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.tf"},"region":{"startLine":2}}}]}
],"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[]}]}]}`

// Finding messages and paths come from scanned Terraform: they cannot start a workflow command or
// break the summary table.
func TestReportEscapesUntrustedText(t *testing.T) {
	t.Parallel()
	f := filepath.Join(t.TempDir(), "hostile.sarif")
	if err := os.WriteFile(f, []byte(hostileSARIF), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runReport(t, f, "true", "1")
	if r.err != nil {
		t.Fatalf("report.py: %v", r.err)
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	want := []string{
		"::error file=infra/a%2Cb%3Ac/mäin.tf,line=7,title=IACE-AWS-S3-002::bad%0A::error::injected 100%25 | <b>x</b>",
		"::warning file=main.tf,line=1,title=IACE-AWS-S3-003::w",
		"::notice title=IACE-AWS-S3-009::n",
		`::notice title=IACE-AWS-S3-009::a\|b`,
	}
	if !slices.Equal(lines, want) {
		t.Errorf("annotations:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(r.output, "blocking-count=1\n") {
		t.Errorf("output = %q, want blocking-count=1 (the excepted error does not block)", r.output)
	}
	if strings.Contains(r.summary, "<b>") || strings.Contains(r.summary, "bad\n") {
		t.Errorf("summary carries raw markup or a line break from a message:\n%s", r.summary)
	}
	if !strings.Contains(r.summary, `a\\\|b`) {
		t.Errorf("summary does not escape a backslash before a pipe:\n%s", r.summary)
	}
	if !strings.Contains(r.summary, "1 excepted") {
		t.Errorf("summary does not count the excepted finding:\n%s", r.summary)
	}
}

func TestReportWithoutAnnotations(t *testing.T) {
	t.Parallel()
	r := runReport(t, "../../internal/report/sarif/testdata/report.golden.sarif", "false", "1")
	if r.err != nil {
		t.Fatalf("report.py: %v", r.err)
	}
	if r.stdout != "" {
		t.Errorf("annotations printed with annotations=false:\n%s", r.stdout)
	}
}

// A scan that exits 2 may leave no SARIF: the summary says the scan failed, and nothing counts
// as zero blocking findings.
func TestReportOnAFailedScan(t *testing.T) {
	t.Parallel()
	r := runReport(t, filepath.Join(t.TempDir(), "missing.sarif"), "true", "2")
	if r.err != nil {
		t.Fatalf("report.py: %v", r.err)
	}
	if !strings.Contains(r.summary, "could not be trusted") || !strings.Contains(r.summary, "exit code 2") {
		t.Errorf("summary does not report the failed scan:\n%s", r.summary)
	}
	if strings.Contains(r.output, "blocking-count") {
		t.Errorf("blocking-count set without a report: %q", r.output)
	}
}

// When the scan never ran, a SARIF file in the workspace is stale or came with the pull request:
// it is not reported.
func TestReportWhenTheScanDidNotRun(t *testing.T) {
	t.Parallel()
	r := runReport(t, "../../internal/report/sarif/testdata/report.golden.sarif", "true", "")
	if r.err != nil {
		t.Fatalf("report.py: %v", r.err)
	}
	if !strings.Contains(r.summary, "did not run") || strings.Contains(r.summary, "IACE-AWS") {
		t.Errorf("summary:\n%s", r.summary)
	}
	if r.stdout != "" || r.output != "" {
		t.Errorf("annotations %q or outputs %q from a scan that did not run", r.stdout, r.output)
	}
}

func TestReportRejectsMalformedSARIF(t *testing.T) {
	t.Parallel()
	f := filepath.Join(t.TempDir(), "bad.sarif")
	if err := os.WriteFile(f, []byte(`{"runs": "nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runReport(t, f, "true", "1"); r.err == nil {
		t.Errorf("report.py accepted malformed SARIF; summary:\n%s", r.summary)
	}
}

// releaseDir builds the assets of a fake release: a tar.gz holding an iace binary, and
// checksums.txt naming it.
func releaseDir(t *testing.T, version string, tamper bool) string {
	t.Helper()
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\necho fake iace\n")
	for _, f := range []struct{ name string }{{"LICENSE"}, {"iace"}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := "iace_" + strings.TrimPrefix(version, "v") + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	sum := sha256.Sum256(buf.Bytes())
	if tamper {
		buf.WriteByte(0)
	}
	if err := os.WriteFile(filepath.Join(dir, archive), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	checksums := hex.EncodeToString(sum[:]) + "  " + archive + "\n" + strings.Repeat("0", 64) + "  other.tar.gz\n"
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(checksums), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runInstall(t *testing.T, version, assets string) (string, string, error) {
	t.Helper()
	dest := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "bash", "install-release.sh", version, dest)
	cmd.Env = append(os.Environ(), "IACE_RELEASE_ASSETS="+assets, "RUNNER_OS=", "RUNNER_ARCH=")
	out, err := cmd.CombinedOutput()
	return dest, string(out), err
}

func TestInstallReleaseVerifiesTheChecksum(t *testing.T) {
	t.Parallel()
	dest, out, err := runInstall(t, "v1.2.3", releaseDir(t, "v1.2.3", false))
	if err != nil {
		t.Fatalf("install-release.sh: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(dest, "iace"))
	if err != nil || !strings.Contains(string(got), "fake iace") {
		t.Fatalf("installed binary: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "LICENSE")); err == nil {
		t.Error("install-release.sh extracted more than the binary")
	}
}

func TestInstallReleaseFailsClosed(t *testing.T) {
	t.Parallel()
	noEntry := releaseDir(t, "v1.2.3", false)
	if err := os.WriteFile(filepath.Join(noEntry, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  other.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ version, assets, want string }{
		"tampered archive":    {"v1.2.3", releaseDir(t, "v1.2.3", true), "checksum"},
		"no checksum entry":   {"v1.2.3", noEntry, "checksum"},
		"version with a path": {"v1.2.3/../../x", releaseDir(t, "v1.2.3", false), "version"},
		"empty version":       {"", releaseDir(t, "v1.2.3", false), "version"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dest, out, err := runInstall(t, c.version, c.assets)
			if err == nil {
				t.Fatalf("install-release.sh succeeded:\n%s", out)
			}
			if !strings.Contains(strings.ToLower(out), c.want) {
				t.Errorf("error does not mention %q:\n%s", c.want, out)
			}
			if _, err := os.Stat(filepath.Join(dest, "iace")); err == nil {
				t.Error("a binary was installed despite the failure")
			}
		})
	}
}

// fakeIace writes an iace stand-in that records its arguments, prints a SARIF-like body and
// exits with code.
func fakeIace(t *testing.T, code int) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin, argsFile = filepath.Join(dir, "iace"), filepath.Join(dir, "args")
	script := "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >" + argsFile + "\necho '{\"runs\":[]}'\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

type scanRun struct {
	args, output string
}

func runScan(t *testing.T, workspace, bin, paths, sarif string) scanRun {
	t.Helper()
	script, err := filepath.Abs("scan.sh")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "output")
	cmd := exec.CommandContext(t.Context(), "bash", script)
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(), "IACE_BIN="+bin, "IACE_PATHS="+paths, "IACE_SARIF="+sarif, "GITHUB_OUTPUT="+output)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scan.sh: %v\n%s", err, out)
	}
	o, _ := os.ReadFile(output)
	a, _ := os.ReadFile(filepath.Join(filepath.Dir(bin), "args"))
	return scanRun{args: string(a), output: string(o)}
}

func TestScanSplitsPathsOnAnyWhitespace(t *testing.T) {
	t.Parallel()
	ws := t.TempDir()
	bin, _ := fakeIace(t, 1)
	r := runScan(t, ws, bin, "infra/a\ninfra/b  infra/c\n", "out/iace.sarif")
	if want := "scan\n-o\nsarif\n--\ninfra/a\ninfra/b\ninfra/c\n"; r.args != want {
		t.Errorf("iace args = %q, want %q", r.args, want)
	}
	if r.output != "exit-code=1\nupload=true\n" {
		t.Errorf("outputs = %q", r.output)
	}
	if data, err := os.ReadFile(filepath.Join(ws, "out", "iace.sarif")); err != nil || !strings.Contains(string(data), "runs") {
		t.Errorf("SARIF not written: %q, %v", data, err)
	}
}

// Exit 2 may still write a report (parse errors), but an untrusted analysis must not replace the
// code-scanning alerts, which would close the ones it misses.
func TestScanUploadsOnlyACompletedScan(t *testing.T) {
	t.Parallel()
	bin, _ := fakeIace(t, 2)
	if r := runScan(t, t.TempDir(), bin, ".", "iace.sarif"); r.output != "exit-code=2\n" {
		t.Errorf("outputs = %q, want exit-code=2 and no upload", r.output)
	}
}

func TestScanRefusesUnsafeInputs(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		paths, sarif string
		setup        func(t *testing.T, ws, outside string)
	}{
		"single non-root path": {paths: "infra", sarif: "iace.sarif"},
		"one path given twice": {paths: "infra ./infra/", sarif: "iace.sarif"},
		"absolute sarif-file":  {paths: ".", sarif: "/tmp/iace.sarif"},
		"sarif-file with ..":   {paths: ".", sarif: "a/../../iace.sarif"},
		"symlinked directory": {paths: ".", sarif: "out/iace.sarif", setup: func(t *testing.T, ws, outside string) {
			t.Helper()
			if err := os.Symlink(outside, filepath.Join(ws, "out")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ws, outside := t.TempDir(), t.TempDir()
			if c.setup != nil {
				c.setup(t, ws, outside)
			}
			bin, argsFile := fakeIace(t, 0)
			r := runScan(t, ws, bin, c.paths, c.sarif)
			if r.output != "" {
				t.Errorf("outputs = %q, want none: iace did not run", r.output)
			}
			if _, err := os.Stat(argsFile); err == nil {
				t.Error("iace ran despite the refused input")
			}
			if entries, _ := os.ReadDir(outside); len(entries) != 0 {
				t.Errorf("wrote outside the workspace: %v", entries)
			}
		})
	}
}

// A pull request that commits iace.sarif as a symlink gets the link replaced, not its target
// overwritten.
func TestScanReplacesASymlinkedSARIFFile(t *testing.T) {
	t.Parallel()
	ws := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(ws, "iace.sarif")); err != nil {
		t.Fatal(err)
	}
	bin, _ := fakeIace(t, 0)
	runScan(t, ws, bin, ".", "iace.sarif")
	if data, _ := os.ReadFile(target); string(data) != "keep" {
		t.Errorf("symlink target overwritten: %q", data)
	}
	if fi, err := os.Lstat(filepath.Join(ws, "iace.sarif")); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("iace.sarif is not a regular file: %v", err)
	}
}
