package terraform_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// evalVars writes the files, parses the module in dir (its .tf files only) and evaluates its
// variables with opts.
func evalVars(t *testing.T, dir string, contents map[string]string, opts terraform.VarOptions) (*terraform.ParsedModule, map[string]terraform.Variable, error) {
	t.Helper()
	root := files(t, contents)
	r, err := fsutil.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var tf []string
	for name := range contents {
		if (strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json")) && parentDir(name) == dir {
			tf = append(tf, name)
		}
	}
	limits := terraform.DefaultLimits()
	m, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: dir, Files: sorted(tf)}, limits)
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	vars, err := m.EvaluateVariables(context.Background(), r, opts, limits)
	return m, vars, err
}

func parentDir(name string) string {
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return "."
	}
	return name[:i]
}

const declare = `
variable "env" {
  default = "dev"
}
variable "size" {
  type    = number
  default = 1
}
variable "tags" {
  type = map(string)
}
variable "db_password" {
  type      = string
  sensitive = true
}
`

func TestEvaluateVariablesPrecedence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]string
		opts  terraform.VarOptions
		want  cty.Value // of "env"
	}{
		{"default", map[string]string{}, terraform.VarOptions{}, cty.StringVal("dev")},
		{"terraform.tfvars over default", map[string]string{
			"terraform.tfvars": `env = "tfvars"`,
		}, terraform.VarOptions{}, cty.StringVal("tfvars")},
		{"terraform.tfvars.json over terraform.tfvars", map[string]string{
			"terraform.tfvars":      `env = "tfvars"`,
			"terraform.tfvars.json": `{"env": "tfvars-json"}`,
		}, terraform.VarOptions{}, cty.StringVal("tfvars-json")},
		{"auto files in lexical order over terraform.tfvars", map[string]string{
			"terraform.tfvars":    `env = "tfvars"`,
			"b.auto.tfvars":       `env = "auto-b"`,
			"a.auto.tfvars":       `env = "auto-a"`,
			"a.auto.tfvars.json":  `{"env": "auto-a-json"}`,
			"other/c.auto.tfvars": `env = "other-dir"`,
		}, terraform.VarOptions{}, cty.StringVal("auto-b")},
		{"var files in order over auto files", map[string]string{
			"z.auto.tfvars":   `env = "auto"`,
			"vars/one.tfvars": `env = "file-one"`,
			"vars/two.tfvars": `env = "file-two"`,
		}, terraform.VarOptions{VarFiles: []string{"vars/two.tfvars", "vars/one.tfvars"}}, cty.StringVal("file-one")},
		{"--var over var files, last one wins", map[string]string{
			"vars/one.tfvars": `env = "file-one"`,
		}, terraform.VarOptions{VarFiles: []string{"vars/one.tfvars"}, Vars: []string{"env=flag-1", "env=flag-2"}}, cty.StringVal("flag-2")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			contents := map[string]string{"main.tf": declare}
			for k, v := range tc.files {
				contents[k] = v
			}
			m, vars, err := evalVars(t, ".", contents, tc.opts)
			if err != nil {
				t.Fatalf("EvaluateVariables: %v", err)
			}
			if got := vars["env"].Value; !got.RawEquals(tc.want) {
				t.Errorf("env = %#v, want %#v", got, tc.want)
			}
			if len(m.Diagnostics) != 0 {
				t.Errorf("diagnostics = %v, want none", m.Diagnostics)
			}
		})
	}
}

func TestEvaluateVariablesDeclarations(t *testing.T) {
	t.Parallel()
	_, vars, err := evalVars(t, ".", map[string]string{
		"main.tf":          declare,
		"terraform.tfvars": "size = \"5\"\ndb_password = \"fake-password-for-tests\"\n",
	}, terraform.VarOptions{})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}

	if got := vars["size"].Value; !got.RawEquals(cty.NumberIntVal(5)) {
		t.Errorf("size = %#v, want 5 converted to number", got)
	}
	if v := vars["size"]; v.Type != "number" || !v.HasDefault || v.Sensitive {
		t.Errorf("size = %+v, want type number, a default, not sensitive", v)
	}

	tags := vars["tags"]
	if tags.Value.IsKnown() || !tags.Value.Type().Equals(cty.Map(cty.String)) {
		t.Errorf("tags = %#v, want an unknown map(string): no value is unknown, not an error", tags.Value)
	}
	if tags.HasDefault {
		t.Error("tags.HasDefault = true, want false")
	}

	pw := vars["db_password"]
	if !pw.Sensitive || !pw.Value.HasMark(terraform.SensitiveMark) {
		t.Errorf("db_password = %+v (marks %v), want sensitive and marked", pw, pw.Value.Marks())
	}
	if env := vars["env"]; env.Type != "any" {
		t.Errorf("env.Type = %q, want any", env.Type)
	}
	if len(vars) != 4 {
		t.Errorf("got %d variables, want 4", len(vars))
	}
}

func TestEvaluateVariablesCommandLineValues(t *testing.T) {
	t.Parallel()
	src := `
variable "name" {
  type = string
}
variable "zones" {
  type = list(string)
}
variable "anything" {
  type = any
}
variable "untyped" {}
`
	_, vars, err := evalVars(t, ".", map[string]string{"main.tf": src}, terraform.VarOptions{
		Vars: []string{"name=a=b", `zones=["eu-west-1a", "eu-west-1b"]`, `anything={ k = 1 }`, "untyped={ k = 1 }"},
	})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	if got := vars["name"].Value; !got.RawEquals(cty.StringVal("a=b")) {
		t.Errorf("name = %#v, want the literal string a=b (primitive types are not parsed)", got)
	}
	wantZones := cty.ListVal([]cty.Value{cty.StringVal("eu-west-1a"), cty.StringVal("eu-west-1b")})
	if got := vars["zones"].Value; !got.RawEquals(wantZones) {
		t.Errorf("zones = %#v, want %#v", got, wantZones)
	}
	if got := vars["anything"].Value; !got.Type().IsObjectType() {
		t.Errorf("anything = %#v, want an object parsed as an expression", got)
	}
	if got := vars["untyped"].Value; !got.RawEquals(cty.StringVal("{ k = 1 }")) {
		t.Errorf("untyped = %#v, want the literal string (no type means literal, as in Terraform)", got)
	}
}

func TestEvaluateVariablesDiagnostics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		files    map[string]string
		wantCode terraform.DiagCode
		wantSev  terraform.Severity
		wantFile string
		check    func(t *testing.T, vars map[string]terraform.Variable)
	}{
		{
			name:     "a value that does not convert is kept with a warning",
			files:    map[string]string{"terraform.tfvars": `size = ["not", "a", "number"]`},
			wantCode: terraform.DiagVariableType, wantSev: terraform.SeverityWarning, wantFile: "terraform.tfvars",
			check: func(t *testing.T, vars map[string]terraform.Variable) {
				t.Helper()
				if !vars["size"].Value.Type().IsTupleType() {
					t.Errorf("size = %#v, want the unconverted tuple", vars["size"].Value)
				}
			},
		},
		{
			name:     "an undeclared variable in a tfvars file is a warning",
			files:    map[string]string{"x.auto.tfvars": "nope = 1\n"},
			wantCode: terraform.DiagUndeclaredVariable, wantSev: terraform.SeverityWarning, wantFile: "x.auto.tfvars",
		},
		{
			name:     "a syntax error in a tfvars file is an error",
			files:    map[string]string{"terraform.tfvars": "env = \n"},
			wantCode: terraform.DiagSyntax, wantSev: terraform.SeverityError, wantFile: "terraform.tfvars",
		},
		{
			name:     "a reference in a tfvars file is an error, like in Terraform",
			files:    map[string]string{"terraform.tfvars": "env = var.size\n"},
			wantCode: terraform.DiagSyntax, wantSev: terraform.SeverityError, wantFile: "terraform.tfvars",
			check: func(t *testing.T, vars map[string]terraform.Variable) {
				t.Helper()
				if vars["env"].Value.IsKnown() {
					t.Errorf("env = %#v, want unknown", vars["env"].Value)
				}
			},
		},
		{
			name:     "a tfvars expression over the limits is unknown",
			files:    map[string]string{"terraform.tfvars": "size = " + strings.Repeat("1 + ", 2000) + "1\n"},
			wantCode: terraform.DiagExpressionTooComplex, wantSev: terraform.SeverityWarning, wantFile: "terraform.tfvars",
			check: func(t *testing.T, vars map[string]terraform.Variable) {
				t.Helper()
				if vars["size"].Value.IsKnown() {
					t.Errorf("size = %#v, want unknown", vars["size"].Value)
				}
			},
		},
		{
			name:     "a tfvars file nested too deeply is not parsed",
			files:    map[string]string{"terraform.tfvars": "env = " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n"},
			wantCode: terraform.DiagNestingTooDeep, wantSev: terraform.SeverityError, wantFile: "terraform.tfvars",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			contents := map[string]string{"main.tf": declare}
			for k, v := range tc.files {
				contents[k] = v
			}
			m, vars, err := evalVars(t, ".", contents, terraform.VarOptions{})
			if err != nil {
				t.Fatalf("EvaluateVariables: %v", err)
			}
			var found bool
			for _, d := range m.Diagnostics {
				if d.Code == tc.wantCode && d.Severity == tc.wantSev && d.File == tc.wantFile {
					found = true
				}
			}
			if !found {
				t.Errorf("want a %s %s in %s; got %v", tc.wantSev, tc.wantCode, tc.wantFile, m.Diagnostics)
			}
			if tc.check != nil {
				tc.check(t, vars)
			}
		})
	}
}

func TestEvaluateVariablesRejectsBadCommandLineInput(t *testing.T) {
	t.Parallel()
	tests := map[string]terraform.VarOptions{
		"var file outside the scan root": {VarFiles: []string{"../outside.tfvars"}},
		"absolute var file":              {VarFiles: []string{"/etc/passwd"}},
		"missing var file":               {VarFiles: []string{"missing.tfvars"}},
		"var without =":                  {Vars: []string{"env"}},
		"undeclared --var":               {Vars: []string{"nope=1"}},
		"--var that does not parse":      {Vars: []string{"tags={"}},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := evalVars(t, ".", map[string]string{"main.tf": declare}, opts)
			if err == nil {
				t.Errorf("EvaluateVariables(%+v) succeeded, want an error", opts)
			}
		})
	}
}

func TestEvaluateVariablesInSubdirectoryRoot(t *testing.T) {
	t.Parallel()
	_, vars, err := evalVars(t, "envs/prod", map[string]string{
		"envs/prod/main.tf":          declare,
		"envs/prod/terraform.tfvars": `env = "prod"`,
		"terraform.tfvars":           `env = "scan-root"`,
	}, terraform.VarOptions{})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	if got := vars["env"].Value; !got.RawEquals(cty.StringVal("prod")) {
		t.Errorf("env = %#v, want the value from the module's own terraform.tfvars", got)
	}
}

func TestEvaluateVariablesJSONDeclarations(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("list(", 2000) + "string" + strings.Repeat(")", 2000)
	m, vars, err := evalVars(t, ".", map[string]string{
		"main.tf.json": `{"variable": {
  "zones": {"type": "list(string)", "default": ["a"]},
  "deep": {"type": "` + deep + `"},
  "secret": {"type": "string", "sensitive": true}
}}`,
	}, terraform.VarOptions{Vars: []string{`zones=["b", "c"]`}})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	want := cty.ListVal([]cty.Value{cty.StringVal("b"), cty.StringVal("c")})
	if got := vars["zones"].Value; !got.RawEquals(want) || vars["zones"].Type != "list(string)" {
		t.Errorf("zones = %#v (%s), want %#v (list(string))", got, vars["zones"].Type, want)
	}
	if vars["deep"].Type != "any" {
		t.Errorf("deep.Type = %q, want any: a type nested too deeply is not read", vars["deep"].Type)
	}
	var found bool
	for _, d := range m.Diagnostics {
		found = found || (d.Code == terraform.DiagExpressionTooComplex && d.File == "main.tf.json")
	}
	if !found {
		t.Errorf("want an %s diagnostic for the deep type; got %v", terraform.DiagExpressionTooComplex, m.Diagnostics)
	}
	if !vars["secret"].Sensitive {
		t.Error("secret.Sensitive = false, want true")
	}
}

func TestEvaluateVariablesRejectsBadExpressionFlags(t *testing.T) {
	t.Parallel()
	src := "variable \"zones\" {\n  type = list(string)\n}\n"
	for name, kv := range map[string]string{
		"nested too deeply":  "zones=" + strings.Repeat("[", 2000) + strings.Repeat("]", 2000),
		"too many operators": "zones=[" + strings.Repeat("1 + ", 2000) + "1]",
		"a reference":        "zones=[var.other]",
	} {
		_, _, err := evalVars(t, ".", map[string]string{"main.tf": src}, terraform.VarOptions{Vars: []string{kv}})
		if err == nil {
			t.Errorf("%s: EvaluateVariables succeeded, want an error", name)
		}
	}
}

func TestEvaluateVariablesHonoursCancellation(t *testing.T) {
	t.Parallel()
	root := files(t, map[string]string{"main.tf": declare, "terraform.tfvars": `env = "x"`})
	r, err := fsutil.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	limits := terraform.DefaultLimits()
	m, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: ".", Files: []string{"main.tf"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.EvaluateVariables(ctx, r, terraform.VarOptions{}, limits); err == nil {
		t.Error("EvaluateVariables with a cancelled context succeeded, want an error")
	}
}

func TestEvaluateVariablesOptionalAttributes(t *testing.T) {
	t.Parallel()
	src := `
variable "cfg" {
  type = object({
    encrypted = optional(bool, true)
    name      = optional(string)
  })
  default = {}
}
variable "from_tfvars" {
  type = object({
    encrypted = optional(bool, true)
    name      = string
  })
}
`
	m, vars, err := evalVars(t, ".", map[string]string{
		"main.tf":          src,
		"terraform.tfvars": `from_tfvars = { name = "x" }`,
	}, terraform.VarOptions{})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics = %v, want none: optional(T, default) is valid Terraform", m.Diagnostics)
	}
	wantCfg := cty.ObjectVal(map[string]cty.Value{"encrypted": cty.True, "name": cty.NullVal(cty.String)})
	if got := vars["cfg"].Value; !got.RawEquals(wantCfg) {
		t.Errorf("cfg = %#v, want %#v (defaults applied)", got, wantCfg)
	}
	wantTF := cty.ObjectVal(map[string]cty.Value{"encrypted": cty.True, "name": cty.StringVal("x")})
	if got := vars["from_tfvars"].Value; !got.RawEquals(wantTF) {
		t.Errorf("from_tfvars = %#v, want %#v", got, wantTF)
	}
}

func TestEvaluateVariablesSensitivityFailsClosed(t *testing.T) {
	t.Parallel()
	src := `
variable "as_string" {
  sensitive = "true"
}
variable "unevaluable" {
  sensitive = var.flag
}
variable "plain" {
  sensitive = false
}
variable "dup" {
  sensitive = true
}
variable "dup" {
  default = "second"
}
`
	m, vars, err := evalVars(t, ".", map[string]string{"main.tf": src}, terraform.VarOptions{})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	for _, name := range []string{"as_string", "unevaluable", "dup"} {
		if !vars[name].Sensitive || !vars[name].Value.HasMark(terraform.SensitiveMark) {
			t.Errorf("%s: Sensitive = %v, want true and a marked value", name, vars[name].Sensitive)
		}
	}
	if vars["plain"].Sensitive {
		t.Error("plain: Sensitive = true, want false")
	}
	var dupErr bool
	for _, d := range m.Diagnostics {
		dupErr = dupErr || (d.Code == terraform.DiagDuplicateVariable && d.Severity == terraform.SeverityError && d.Line == 14)
	}
	if !dupErr {
		t.Errorf("want a duplicate_variable error at line 14; got %v", m.Diagnostics)
	}
	if vars["dup"].HasDefault {
		t.Error("dup: the first declaration should be kept, without the second one's default")
	}
}

func TestEvaluateVariablesNullable(t *testing.T) {
	t.Parallel()
	src := `
variable "strict" {
  type     = number
  default  = 3
  nullable = false
}
variable "loose" {
  type    = number
  default = 3
}
`
	_, vars, err := evalVars(t, ".", map[string]string{
		"main.tf":          src,
		"terraform.tfvars": "strict = null\nloose = null\n",
	}, terraform.VarOptions{})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	if got := vars["strict"].Value; !got.RawEquals(cty.NumberIntVal(3)) {
		t.Errorf("strict = %#v, want the default 3 (nullable = false)", got)
	}
	if got := vars["loose"].Value; !got.RawEquals(cty.NullVal(cty.Number)) {
		t.Errorf("loose = %#v, want null", got)
	}
}

func TestEvaluateVariablesTfvarsFileLimit(t *testing.T) {
	t.Parallel()
	root := files(t, map[string]string{
		"main.tf":       declare,
		"a.auto.tfvars": `env = "a"`,
		"b.auto.tfvars": `env = "b"`,
		"c.auto.tfvars": `env = "c"`,
	})
	r, err := fsutil.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	limits := terraform.Limits{MaxFileSize: 1 << 20, MaxFiles: 2}
	m, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: ".", Files: []string{"main.tf"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	vars, err := m.EvaluateVariables(context.Background(), r, terraform.VarOptions{}, limits)
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	if !m.HasErrors() || m.Diagnostics[0].Code != terraform.DiagFileLimit {
		t.Errorf("diagnostics = %v, want a file_limit error", m.Diagnostics)
	}
	if got := vars["env"].Value; !got.RawEquals(cty.StringVal("dev")) {
		t.Errorf("env = %#v, want the default: no tfvars file is applied past the limit", got)
	}
}

func TestEvaluateVariablesTfvarsAtTheFileLimit(t *testing.T) {
	t.Parallel()
	root := files(t, map[string]string{
		"main.tf":       declare,
		"a.auto.tfvars": `env = "a"`,
		"b.auto.tfvars": `env = "b"`,
	})
	r, err := fsutil.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	limits := terraform.Limits{MaxFileSize: 1 << 20, MaxFiles: 2}
	m, err := terraform.ParseModule(context.Background(), r, terraform.Dir{Path: ".", Files: []string{"main.tf"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	vars, err := m.EvaluateVariables(context.Background(), r, terraform.VarOptions{}, limits)
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics = %v, want none at exactly the limit", m.Diagnostics)
	}
	if got := vars["env"].Value; !got.RawEquals(cty.StringVal("b")) {
		t.Errorf("env = %#v, want b: both files are applied at exactly the limit", got)
	}
}

func TestEvaluateVariablesFlagErrors(t *testing.T) {
	t.Parallel()
	src := "variable \"n\" {\n  type = number\n}\n"
	contents := map[string]string{"main.tf": src, "d/x.tfvars": "n = 1\n"}
	tests := map[string]terraform.VarOptions{
		"--var that does not convert": {Vars: []string{"n=abc"}},
		"backslash var file":          {VarFiles: []string{`d\x.tfvars`}},
		"drive-letter var file":       {VarFiles: []string{"C:x.tfvars"}},
		"empty var file":              {VarFiles: []string{""}},
		"directory as var file":       {VarFiles: []string{"d"}},
	}
	for name, opts := range tests {
		if _, _, err := evalVars(t, ".", contents, opts); err == nil {
			t.Errorf("%s: EvaluateVariables succeeded, want an error", name)
		}
	}
	_, _, err := evalVars(t, ".", contents, terraform.VarOptions{Vars: []string{"fake-secret-value"}})
	if err == nil || strings.Contains(err.Error(), "fake-secret-value") {
		t.Errorf("error = %v, want an error that does not echo the argument", err)
	}
}
