package cli

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the inspect golden files")

const e2eDir = "../../testdata/terraform/e2e"

// inspect runs `iace inspect` with args and returns its exit code, stdout and stderr.
func inspect(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), append([]string{"inspect"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// writeTree writes files under a new temporary directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestInspectGolden compares `iace inspect --json` on every e2e fixture with its golden file;
// run with -update to rewrite them, then review the diff.
func TestInspectGolden(t *testing.T) {
	entries, err := os.ReadDir(e2eDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no e2e fixtures")
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			dir := filepath.Join(e2eDir, e.Name())
			golden := filepath.Join("testdata", "inspect", e.Name()+".golden.json")
			code, stdout, stderr := inspect(t, dir, "--json")
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if _, again, _ := inspect(t, dir, "--json"); again != stdout {
				t.Fatal("output differs between runs")
			}
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(stdout), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if stdout != string(want) {
				t.Errorf("output differs from %s (run with -update and review the diff):\n%s", golden, stdout)
			}
		})
	}
}

func TestInspectShowsTheOverriddenValue(t *testing.T) {
	_, stdout, _ := inspect(t, filepath.Join(e2eDir, "override"), "--json")
	if !strings.Contains(stdout, `"acl": "public-read"`) || strings.Contains(stdout, `"acl": "private"`) {
		t.Errorf("the override's acl is not the one shown:\n%s", stdout)
	}
}

func TestInspectNeverPrintsSecrets(t *testing.T) {
	code, stdout, stderr := inspect(t, filepath.Join(e2eDir, "secrets"), "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// "fake-" marks the sensitive default, the backend key and the credential-named literal;
	// "fakekeymaterial" and the PEM header mark the pattern-shaped literal under a neutral name.
	for _, out := range []string{stdout, stderr} {
		for _, marker := range []string{"fake-", "fakekeymaterial", "PRIVATE KEY"} {
			if strings.Contains(out, marker) {
				t.Errorf("a fake secret (%q) reached the output:\n%s", marker, out)
			}
		}
	}
	for _, want := range []string{`"password": "<redacted>"`, `"access_key": "<redacted>"`, `"master_password": "<redacted>"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected %s:\n%s", want, stdout)
		}
	}
}

func TestInspectTextSummary(t *testing.T) {
	code, stdout, _ := inspect(t, filepath.Join(e2eDir, "basic"))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"root module .", "resources: 3", "coverage gaps: 0"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("summary lacks %q:\n%s", want, stdout)
		}
	}
}

// TestInspectPrintsEveryRootInOrder covers several roots and an orphan: one document each, in
// order, the orphan with its uninstantiated_module gap.
func TestInspectPrintsEveryRootInOrder(t *testing.T) {
	code, stdout, stderr := inspect(t, filepath.Join(e2eDir, "multi"), "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var roots []string
	for _, line := range strings.Split(stdout, "\n") {
		if r, ok := strings.CutPrefix(strings.TrimSpace(line), `"root_module": `); ok {
			roots = append(roots, strings.Trim(r, `",`))
		}
	}
	if got := strings.Join(roots, " "); got != "envs/dev envs/prod modules/shared" {
		t.Errorf("roots %q, want envs/dev envs/prod modules/shared", got)
	}
	if !strings.Contains(stdout, "uninstantiated_module") {
		t.Errorf("the orphan's uninstantiated_module gap is missing:\n%s", stdout)
	}
}

func TestInspectWithoutTerraform(t *testing.T) {
	dir := writeTree(t, map[string]string{"README.md": "no Terraform here\n"})
	if code, stdout, _ := inspect(t, dir); code != 0 || !strings.Contains(stdout, "no Terraform root modules") {
		t.Errorf("exit %d, stdout %q; want 0 and a line saying there is no Terraform", code, stdout)
	}
	if _, stdout, _ := inspect(t, dir, "--json"); stdout != "[]\n" {
		t.Errorf("--json printed %q, want []", stdout)
	}
}

func TestInspectExitsTwoOnParseErrors(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.tf": "resource \"aws_s3_bucket\" \"b\" {\n"})
	code, stdout, stderr := inspect(t, dir, "--json")
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(stdout, `"kind": "parse_error"`) {
		t.Errorf("the document with its parse_error gap is not printed:\n%s", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, "parse error") {
		t.Errorf("stderr %q, want one line naming the parse error", stderr)
	}
}

func TestInspectUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no path":         {},
		"two paths":       {"a", "b"},
		"missing path":    {filepath.Join(t.TempDir(), "nope")},
		"malformed --var": {filepath.Join(e2eDir, "basic"), "--var", "no-equals-sign"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := inspect(t, args...)
			if code != 2 || stdout != "" || strings.Count(stderr, "\n") != 1 {
				t.Errorf("exit %d, stdout %q, stderr %q; want 2, nothing, one line", code, stdout, stderr)
			}
		})
	}
}

// remoteModuleTree is a scan root with a remote module call and a committed module manifest
// that resolves it.
var remoteModuleTree = map[string]string{
	"main.tf":                        "module \"vpc\" {\n  source  = \"terraform-aws-modules/vpc/aws\"\n  version = \"5.0.0\"\n}\n",
	".terraform/modules/vpc/main.tf": "resource \"aws_vpc\" \"this\" {\n  cidr_block = \"10.0.0.0/16\"\n}\n",
	".terraform/modules/modules.json": `{"Modules":[{"Key":"","Source":"","Dir":"."},` +
		`{"Key":"vpc","Source":"registry.terraform.io/terraform-aws-modules/vpc/aws","Version":"5.0.0","Dir":".terraform/modules/vpc"}]}`,
}

func TestInspectTrustsTheModuleManifestOnlyWhenAsked(t *testing.T) {
	dir := writeTree(t, remoteModuleTree)
	_, untrusted, _ := inspect(t, dir, "--json")
	if strings.Contains(untrusted, "module.vpc.aws_vpc.this") || !strings.Contains(untrusted, `"reason": "remote_source"`) {
		t.Errorf("without trust the remote module must stay unresolved:\n%s", untrusted)
	}
	_, trusted, _ := inspect(t, dir, "--json", "--trust-module-manifest")
	if !strings.Contains(trusted, "module.vpc.aws_vpc.this") {
		t.Errorf("--trust-module-manifest did not resolve the module:\n%s", trusted)
	}
}

// TestInspectTrustFromTheEnvironment cannot run in parallel: it sets an environment variable.
func TestInspectTrustFromTheEnvironment(t *testing.T) {
	dir := writeTree(t, remoteModuleTree)
	t.Setenv("IACE_TRUST_MODULE_MANIFEST", "true")
	if _, out, _ := inspect(t, dir, "--json"); !strings.Contains(out, "module.vpc.aws_vpc.this") {
		t.Errorf("IACE_TRUST_MODULE_MANIFEST=true did not resolve the module:\n%s", out)
	}
	// The flag beats the environment.
	if _, out, _ := inspect(t, dir, "--json", "--trust-module-manifest=false"); strings.Contains(out, "module.vpc.aws_vpc.this") {
		t.Errorf("--trust-module-manifest=false did not override IACE_TRUST_MODULE_MANIFEST=true:\n%s", out)
	}
	t.Setenv("IACE_TRUST_MODULE_MANIFEST", "maybe")
	if code, _, stderr := inspect(t, dir, "--json"); code != 2 || !strings.Contains(stderr, "IACE_TRUST_MODULE_MANIFEST") {
		t.Errorf("an invalid IACE_TRUST_MODULE_MANIFEST: exit %d, stderr %q", code, stderr)
	}
}

func TestInspectHelpWarnsAboutCommittedTerraformDirectories(t *testing.T) {
	code, stdout, _ := func() (int, string, string) {
		var out, errOut bytes.Buffer
		c := Run(context.Background(), []string{"inspect", "--help"}, &out, &errOut)
		return c, out.String(), errOut.String()
	}()
	if code != 0 || !strings.Contains(stdout, "remove any committed .terraform") {
		t.Errorf("help (exit %d) does not tell a trusted step to remove a committed .terraform:\n%s", code, stdout)
	}
}
