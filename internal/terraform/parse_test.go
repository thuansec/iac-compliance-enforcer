package terraform_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// parse writes the files into a temp dir and parses them as the module in dir.
func parse(t *testing.T, dir string, contents map[string]string) *terraform.ParsedModule {
	t.Helper()
	root := files(t, contents)
	r, err := fsutil.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var names []string
	for name := range contents {
		names = append(names, name)
	}
	m, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: dir, Files: sorted(names)}, terraform.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	return m
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// blockSummary is what the tests compare: type, labels, file and line span.
type blockSummary struct {
	Type      string
	Labels    []string
	File      string
	StartLine int
	EndLine   int
}

func summarize(m *terraform.ParsedModule) []blockSummary {
	var out []blockSummary
	for _, b := range m.Blocks {
		out = append(out, blockSummary{b.Type, b.Labels, b.File, b.Range.Start.Line, b.Range.End.Line})
	}
	return out
}

func TestParseModuleBlocksAndRanges(t *testing.T) {
	t.Parallel()
	m := parse(t, ".", map[string]string{
		"main.tf": `terraform {
  required_version = ">= 1.6"
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"

  versioning {
    enabled = true
  }
}

module "net" {
  source = "./net"
}
`,
		"vars.tf.json": `{
  "variable": {
    "env": {
      "default": "prod"
    }
  },
  "data": {
    "aws_caller_identity": {
      "current": {}
    }
  },
  "//": "comments are allowed"
}
`,
	})
	want := []blockSummary{
		{"terraform", nil, "main.tf", 1, 3},
		{"resource", []string{"aws_s3_bucket", "logs"}, "main.tf", 5, 11},
		{"module", []string{"net"}, "main.tf", 13, 15},
		{"variable", []string{"env"}, "vars.tf.json", 3, 5},
		{"data", []string{"aws_caller_identity", "current"}, "vars.tf.json", 9, 9},
	}
	if diff := cmp.Diff(want, summarize(m)); diff != "" {
		t.Errorf("blocks (-want +got):\n%s", diff)
	}
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics = %v, want none", m.Diagnostics)
	}
	if m.Dir != "." {
		t.Errorf("Dir = %q, want .", m.Dir)
	}
	// The body is kept for decoding: the resource's attribute is reachable.
	attrs, _ := m.Blocks[1].Body.JustAttributes()
	if _, ok := attrs["bucket"]; !ok {
		t.Errorf("resource body lacks the bucket attribute: %v", attrs)
	}
}

func TestParseModuleDiagnostics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		files      map[string]string
		wantBlocks []blockSummary
		wantDiags  []terraform.Diagnostic // Summary and Detail are not compared
		hasErrors  bool
	}{
		{
			name: "syntax error is an error with file and line; other files still parse",
			files: map[string]string{
				"a.tf": "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n",
				"b.tf": "variable \"env\" {}\n",
			},
			wantBlocks: []blockSummary{{"variable", []string{"env"}, "b.tf", 1, 1}},
			wantDiags:  []terraform.Diagnostic{{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "a.tf", Line: 1, Column: 30}},
			hasErrors:  true,
		},
		{
			name:  "json syntax error",
			files: map[string]string{"a.tf.json": "{\"variable\": {\n  \"env\": \n}"},
			// "Unclosed object" and "Root value must be object" at 1:1, "Missing JSON value" at 3:1.
			wantDiags: []terraform.Diagnostic{
				{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "a.tf.json", Line: 1, Column: 1},
				{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "a.tf.json", Line: 1, Column: 1},
				{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "a.tf.json", Line: 3, Column: 1},
			},
			hasErrors: true,
		},
		{
			name: "unknown top-level block is a warning, not a failure",
			files: map[string]string{
				"main.tf": "future_feature \"x\" {\n  a = 1\n}\n\nvariable \"env\" {}\n",
			},
			wantBlocks: []blockSummary{{"variable", []string{"env"}, "main.tf", 5, 5}},
			wantDiags:  []terraform.Diagnostic{{Severity: terraform.SeverityWarning, Code: terraform.DiagUnsupportedBlock, File: "main.tf", Line: 1, Column: 1}},
		},
		{
			name:      "unknown top-level key in json is a warning",
			files:     map[string]string{"main.tf.json": "{\n  \"future_feature\": {}\n}\n"},
			wantDiags: []terraform.Diagnostic{{Severity: terraform.SeverityWarning, Code: terraform.DiagUnsupportedBlock, File: "main.tf.json", Line: 2, Column: 3}},
		},
		{
			name:      "top-level attribute is an error",
			files:     map[string]string{"main.tf": "region = \"eu-west-1\"\n"},
			wantDiags: []terraform.Diagnostic{{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "main.tf", Line: 1, Column: 1}},
			hasErrors: true,
		},
		{
			name:      "wrong number of labels is an error",
			files:     map[string]string{"main.tf": "resource \"aws_s3_bucket\" {}\n"},
			wantDiags: []terraform.Diagnostic{{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "main.tf", Line: 1, Column: 26}},
			hasErrors: true,
		},
		{
			name: "override files are reported and not merged",
			files: map[string]string{
				"main.tf":          "resource \"aws_s3_bucket\" \"b\" {}\n",
				"main_override.tf": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
				"override.tf.json": "{}",
				"notoverride.tf":   "variable \"v\" {}\n",
			},
			wantBlocks: []blockSummary{
				{"resource", []string{"aws_s3_bucket", "b"}, "main.tf", 1, 1},
				{"variable", []string{"v"}, "notoverride.tf", 1, 1},
			},
			wantDiags: []terraform.Diagnostic{
				{Severity: terraform.SeverityWarning, Code: terraform.DiagOverrideNotMerged, File: "main_override.tf", Line: 0, Column: 0},
				{Severity: terraform.SeverityWarning, Code: terraform.DiagOverrideNotMerged, File: "override.tf.json", Line: 0, Column: 0},
			},
		},
		{
			name: "override files are still checked for syntax errors and nesting",
			files: map[string]string{
				"a_override.tf":      "resource \"aws_s3_bucket\" \"b\" {\n",
				"b_override.tf":      "a = " + strings.Repeat("(", 5000) + "x" + strings.Repeat(")", 5000) + "\n",
				"c_override.tf.json": "{\"resource\": {\"aws_s3_bucket\": {\"b\": {}}}}",
			},
			wantDiags: []terraform.Diagnostic{
				{Severity: terraform.SeverityWarning, Code: terraform.DiagOverrideNotMerged, File: "a_override.tf"},
				{Severity: terraform.SeverityError, Code: terraform.DiagSyntax, File: "a_override.tf", Line: 1, Column: 30},
				{Severity: terraform.SeverityWarning, Code: terraform.DiagOverrideNotMerged, File: "b_override.tf"},
				{Severity: terraform.SeverityError, Code: terraform.DiagNestingTooDeep, File: "b_override.tf", Line: 1},
				{Severity: terraform.SeverityWarning, Code: terraform.DiagOverrideNotMerged, File: "c_override.tf.json"},
			},
			hasErrors: true,
		},
		{
			name: "action blocks are known (Terraform 1.14)",
			files: map[string]string{
				"main.tf": "action \"aws_lambda_invoke\" \"notify\" {\n  config {\n    function_name = \"example\"\n  }\n}\n",
			},
			wantBlocks: []blockSummary{{"action", []string{"aws_lambda_invoke", "notify"}, "main.tf", 1, 5}},
		},
		{
			name: "a nesting bomb is an error and is not parsed",
			files: map[string]string{
				"bomb.tf": "a = " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n",
				"ok.tf":   "variable \"v\" {}\n",
			},
			wantBlocks: []blockSummary{{"variable", []string{"v"}, "ok.tf", 1, 1}},
			wantDiags:  []terraform.Diagnostic{{Severity: terraform.SeverityError, Code: terraform.DiagNestingTooDeep, File: "bomb.tf", Line: 1, Column: 0}},
			hasErrors:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := parse(t, ".", tc.files)
			if diff := cmp.Diff(tc.wantBlocks, summarize(m)); diff != "" {
				t.Errorf("blocks (-want +got):\n%s", diff)
			}
			var got []terraform.Diagnostic
			for _, d := range m.Diagnostics {
				if d.Summary == "" {
					t.Errorf("diagnostic without a summary: %+v", d)
				}
				d.Summary, d.Detail = "", ""
				got = append(got, d)
			}
			if diff := cmp.Diff(tc.wantDiags, got); diff != "" {
				t.Errorf("diagnostics (-want +got):\n%s", diff)
			}
			if m.HasErrors() != tc.hasErrors {
				t.Errorf("HasErrors() = %v, want %v", m.HasErrors(), tc.hasErrors)
			}
		})
	}
}

// TestParseDiagnosticsNeverQuoteValues: hcl's diagnostic details quote source text, such as an
// unquoted JSON value or a template keyword, which may be a secret. None of it may reach a
// Diagnostic. The values below are obviously fake.
func TestParseDiagnosticsNeverQuoteValues(t *testing.T) {
	t.Parallel()
	const fake = "FakeSecretValue"
	tests := map[string]string{
		"json.tf.json":       `{"variable": {"v": {"default": ` + fake + `123}}}`,
		"json_js.tf.json":    `{"variable": {"v": {"default": ` + fake + `.prop}}}`,
		"template.tf":        "variable \"v\" {\n  default = \"%{ " + fake + " }\"\n}\n",
		"escape.tf":          "variable \"v\" {\n  default = \"\\q" + fake + "\"\n}\n",
		"heredoc.tf":         "variable \"v\" {\n  default = <<EOT\n%{ " + fake + " }\nEOT\n}\n",
		"bad_override.tf":    "variable \"v\" {\n  default = \"%{ " + fake + " }\"\n}\n",
		"unknown_key.tf":     "variable \"v\" {\n  " + fake + " = 1\n}\n" + fake + " = 2\n",
		"unknown_block.tf":   fake + " \"x\" {}\n",
		"label_count.tf":     "resource \"" + fake + "\" {}\n",
		"missing_value.tf":   "variable \"v\" {\n  default = \n}\n",
		"invalid_char.tf":    "variable \"v\" {\n  default = " + fake + "\x01\n}\n",
		"unterminated.tf":    "variable \"v\" {\n  default = \"" + fake + "\n}\n",
		"json_trailing.json": `{"variable": {}} ` + fake,
	}
	for name, src := range tests {
		m := parse(t, ".", map[string]string{name: src})
		if len(m.Diagnostics) == 0 && name != "unknown_key.tf" {
			t.Errorf("%s: no diagnostics, want at least one", name)
		}
		for _, d := range m.Diagnostics {
			for field, text := range map[string]string{"Summary": d.Summary, "Detail": d.Detail, "String": d.String()} {
				// Block types, labels and argument names are identifiers, not values; Terraform
				// reports them too.
				if name == "unknown_block.tf" || name == "label_count.tf" || name == "unknown_key.tf" {
					continue
				}
				if strings.Contains(text, fake) {
					t.Errorf("%s: %s quotes source text: %q", name, field, text)
				}
			}
		}
	}
}

func TestParseModuleInSubdirectory(t *testing.T) {
	t.Parallel()
	m := parse(t, "modules/net", map[string]string{"modules/net/main.tf": "resource \"aws_vpc\" \"v\" {\n"})
	if len(m.Diagnostics) != 1 || m.Diagnostics[0].File != "modules/net/main.tf" {
		t.Errorf("diagnostics = %+v, want one naming modules/net/main.tf", m.Diagnostics)
	}
}

func TestDiagnosticString(t *testing.T) {
	t.Parallel()
	d := terraform.Diagnostic{
		Severity: terraform.SeverityError, Code: terraform.DiagSyntax,
		Summary: "Unclosed configuration block", File: "infra/main.tf", Line: 3, Column: 7,
	}
	if got, want := d.String(), `"infra/main.tf":3:7: error: Unclosed configuration block`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	forged := terraform.Diagnostic{Severity: terraform.SeverityError, Summary: "s", File: "a\n::error::x.tf"}.String()
	if strings.Contains(forged, "\n") {
		t.Errorf("String() passes a newline from the file name through: %q", forged)
	}
}

func TestParseModuleFailsClosed(t *testing.T) {
	t.Parallel()
	dir := files(t, map[string]string{"main.tf": "variable \"v\" {}\n"})
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	limits := terraform.DefaultLimits()

	missing := terraform.Dir{Path: ".", Files: []string{"main.tf", "gone.tf"}}
	if _, err := terraform.ParseModule(context.Background(), r, missing, limits); err == nil {
		t.Error("ParseModule with a missing file succeeded, want an error")
	}

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Repeat("#", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	small := terraform.Limits{MaxFileSize: 10, MaxFiles: 10}
	if _, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: ".", Files: []string{"main.tf"}}, small); err == nil {
		t.Error("ParseModule of a file over the size limit succeeded, want an error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := terraform.ParseModule(ctx, r, terraform.Dir{Path: ".", Files: []string{"main.tf"}}, limits); err == nil {
		t.Error("ParseModule with a cancelled context succeeded, want an error")
	}
}
