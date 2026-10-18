package engine

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/thuansec/iac-compliance-enforcer/policies"
)

// rule builds a rule module with the given METADATA lines in place of the defaults named in
// replace (a key mapped to "" drops the line).
func rule(pkg string, replace map[string]string, body string) string {
	lines := []struct{ key, line string }{
		{"title", "# title: Buckets must block public access"},
		{"description", "# description: Public buckets expose data."},
		{"scope", "# scope: package"},
		{"related_resources", "# related_resources:\n#   - ref: https://docs.aws.amazon.com/s3/\n#     description: S3 docs"},
		{"custom", "# custom:"},
		{"id", "#   id: IACE-AWS-S3-001"},
		{"severity", "#   severity: high"},
		{"csp", "#   csp: aws"},
		{"service", "#   service: s3"},
		{"resource_types", "#   resource_types: [aws_s3_bucket]"},
		{"remediation", "#   remediation: Set block_public_acls = true."},
	}
	var meta []string
	for _, l := range lines {
		line := l.line
		if r, ok := replace[l.key]; ok {
			line = r
		}
		if line != "" {
			meta = append(meta, line)
		}
	}
	if extra, ok := replace["extra"]; ok {
		meta = append(meta, extra)
	}
	var b strings.Builder
	if len(meta) > 0 {
		b.WriteString("# METADATA\n" + strings.Join(meta, "\n") + "\n")
	}
	b.WriteString("package " + pkg + "\n\n")
	if body == "" {
		body = "deny contains v if {\n\tsome r in input.resources\n\tv := {\"address\": r.address, \"message\": \"x\"}\n}\n"
	}
	b.WriteString(body)
	return b.String()
}

const s3pkg = "iace.rules.aws.s3.public_access"

func loadOne(t *testing.T, src string) (*Library, error) {
	t.Helper()
	return Load(fstest.MapFS{"iace/rules/aws/s3/public_access/rule.rego": {Data: []byte(src)}}, BuiltIn)
}

func TestLoadValidRule(t *testing.T) {
	lib, err := loadOne(t, rule(s3pkg, nil, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(lib.Rules) != 1 {
		t.Fatalf("%d rules, want 1", len(lib.Rules))
	}
	r := lib.Rules[0]
	if r.ID != "IACE-AWS-S3-001" || r.Severity != "high" || r.CSP != "aws" || r.Service != "s3" ||
		r.Package != s3pkg || r.File != "iace/rules/aws/s3/public_access/rule.rego" ||
		len(r.ResourceTypes) != 1 || r.Remediation == "" || len(r.RelatedResources) != 1 {
		t.Errorf("rule %+v", r)
	}
}

// TestLoadRejects covers every metadata rule of iace-rego-policies' metadata schema: each case
// is a load error that names the file.
func TestLoadRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		replace map[string]string
		pkg     string
		body    string
		want    string
	}{
		"missing title":        {replace: map[string]string{"title": ""}, want: "title is required"},
		"long title":           {replace: map[string]string{"title": "# title: " + strings.Repeat("x", 81)}, want: "longer than 80"},
		"missing description":  {replace: map[string]string{"description": ""}, want: "description"},
		"no related resources": {replace: map[string]string{"related_resources": ""}, want: "related_resources"},
		"related resource not https": {
			replace: map[string]string{"related_resources": "# related_resources:\n#   - ref: http://example.com/\n#     description: x"},
			want:    "https",
		},
		"missing custom":                  {replace: map[string]string{"custom": "", "id": "", "severity": "", "csp": "", "service": "", "resource_types": "", "remediation": ""}, want: "custom"},
		"missing id":                      {replace: map[string]string{"id": ""}, want: "custom.id is required"},
		"malformed id":                    {replace: map[string]string{"id": "#   id: IACE-AWS-S3-1"}, want: "custom.id \"IACE-AWS-S3-1\""},
		"external prefix in built-in":     {replace: map[string]string{"id": "#   id: ACME-S3-001"}, want: "custom.id \"ACME-S3-001\""},
		"id does not match csp":           {replace: map[string]string{"id": "#   id: IACE-AZURE-S3-001"}, want: "different CSP"},
		"bad severity":                    {replace: map[string]string{"severity": "#   severity: urgent"}, want: "severity"},
		"missing severity":                {replace: map[string]string{"severity": ""}, want: "severity"},
		"bad csp":                         {replace: map[string]string{"csp": "#   csp: gcp"}, want: "csp"},
		"service not the package segment": {replace: map[string]string{"service": "#   service: ec2"}, want: "service"},
		"no resource types":               {replace: map[string]string{"resource_types": "#   resource_types: []"}, want: "resource_types"},
		"missing remediation":             {replace: map[string]string{"remediation": ""}, want: "remediation"},
		"unknown custom key":              {replace: map[string]string{"extra": "#   severty: high"}, want: "severty"},
		"framework not a list":            {replace: map[string]string{"extra": "#   frameworks:\n#     aws-securityhub: S3.1"}, want: "frameworks"},
		"no METADATA":                     {body: "deny contains v if { v := 1 }\n", replace: map[string]string{"title": "", "description": "", "scope": "", "related_resources": "", "custom": "", "id": "", "severity": "", "csp": "", "service": "", "resource_types": "", "remediation": ""}, want: "METADATA"},
		"missing deny":                    {body: "allow if { true }\n", want: "deny"},
		"bare rule namespace": {
			pkg:  "iace.rules",
			body: "aws.s3.evil.deny contains v if {\n\tsome r in input.resources\n\tv := r.address\n}\n",
			want: "deny only at its root",
		},
		"deny written from outside a rule package": {
			pkg:  "iace",
			body: "rules.aws.s3.public_access.deny contains v if {\n\tsome r in input.resources\n\tv := r.address\n}\n",
			want: "not a rule package",
		},
		"deny below the rule package": {
			body: "deny contains 1 if { true }\n\nsub.deny contains v if {\n\tsome r in input.resources\n\tv := r.address\n}\n",
			want: "deny only at its root",
		},
		"deny not a partial set": {body: "deny := set()\n", want: "partial set rule deny"},
		"id not a string":        {replace: map[string]string{"id": "#   id: 123"}, want: "custom.id must be a string"},
		"resource_types not a list": {
			replace: map[string]string{"resource_types": "#   resource_types: aws_s3_bucket"},
			want:    "custom.resource_types must be a list",
		},
		"frameworks not a map":        {replace: map[string]string{"extra": "#   frameworks: [S3.1]"}, want: "custom.frameworks must map"},
		"params not an object":        {replace: map[string]string{"extra": "#   params: 1"}, want: "custom.params must be"},
		"deprecated not a bool":       {replace: map[string]string{"extra": "#   deprecated: \"no\""}, want: "custom.deprecated must be"},
		"package outside a rule path": {pkg: "iace.rules.aws.s3", want: "is not iace.rules.<csp>"},
	} {
		t.Run(name, func(t *testing.T) {
			pkg := tc.pkg
			if pkg == "" {
				pkg = s3pkg
			}
			_, err := loadOne(t, rule(pkg, tc.replace, tc.body))
			var pe *PolicyError
			if !errors.As(err, &pe) {
				t.Fatalf("error %v, want a *PolicyError", err)
			}
			if pe.File != "iace/rules/aws/s3/public_access/rule.rego" {
				t.Errorf("error names %q, want the rule file", pe.File)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadAllowsOptionalAndExtensionKeys(t *testing.T) {
	extra := "#   frameworks:\n#     aws-securityhub: [S3.1, S3.8]\n#   params: {type: object}\n#   deprecated: false\n#   replaced_by: \"\"\n#   x_owner: platform"
	lib, err := loadOne(t, rule(s3pkg, map[string]string{"extra": extra}, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := lib.Rules[0].Frameworks["aws-securityhub"]; len(got) != 2 {
		t.Errorf("frameworks %v", lib.Rules[0].Frameworks)
	}
}

func TestLoadRejectsDuplicateIDs(t *testing.T) {
	fsys := fstest.MapFS{
		"iace/rules/aws/s3/a/rule.rego": {Data: []byte(rule("iace.rules.aws.s3.a", nil, ""))},
		"iace/rules/aws/s3/b/rule.rego": {Data: []byte(rule("iace.rules.aws.s3.b", nil, ""))},
	}
	_, err := Load(fsys, BuiltIn)
	var pe *PolicyError
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "IACE-AWS-S3-001") ||
		!strings.Contains(err.Error(), "iace/rules/aws/s3/a/rule.rego") || pe.File != "iace/rules/aws/s3/b/rule.rego" {
		t.Errorf("error %v, want a duplicate-ID error naming both files", err)
	}
}

func TestLoadRejectsTwoFilesInOneRulePackage(t *testing.T) {
	fsys := fstest.MapFS{
		"iace/rules/aws/s3/public_access/a.rego": {Data: []byte(rule(s3pkg, nil, ""))},
		"iace/rules/aws/s3/public_access/b.rego": {Data: []byte(rule(s3pkg, map[string]string{"id": "#   id: IACE-AWS-S3-002"}, ""))},
	}
	_, err := Load(fsys, BuiltIn)
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.File != "iace/rules/aws/s3/public_access/b.rego" ||
		!strings.Contains(err.Error(), "iace/rules/aws/s3/public_access/a.rego") {
		t.Errorf("error %v, want a duplicate-package error naming both files", err)
	}
}

func TestLoadRejectsASourceWithoutRules(t *testing.T) {
	fsys := fstest.MapFS{"iace/lib/x/x.rego": {Data: []byte("package iace.lib.x\n\nf(v) := v\n")}}
	var pe *PolicyError
	if _, err := Load(fsys, External); !errors.As(err, &pe) || !strings.Contains(err.Error(), "no rule packages") {
		t.Errorf("error %v, want a no-rules error: a scan never runs without rules", err)
	}
}

func TestLoadRejectsParseErrors(t *testing.T) {
	_, err := loadOne(t, "package iace.rules.aws.s3.public_access\n\ndeny contains v if {\n")
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.File != "iace/rules/aws/s3/public_access/rule.rego" {
		t.Errorf("error %v, want a parse error naming the file", err)
	}
}

func TestLoadExternalRules(t *testing.T) {
	src := rule("iace.rules.aws.s3.public_access", map[string]string{"id": "#   id: ACME-S3-001"}, "")
	fsys := fstest.MapFS{"iace/rules/aws/s3/public_access/rule.rego": {Data: []byte(src)}}
	if _, err := Load(fsys, External); err != nil {
		t.Errorf("external rule with its own prefix: %v", err)
	}
	src = rule("iace.rules.aws.s3.public_access", nil, "")
	fsys = fstest.MapFS{"iace/rules/aws/s3/public_access/rule.rego": {Data: []byte(src)}}
	if _, err := Load(fsys, External); err == nil {
		t.Error("an external rule may not use the IACE- prefix")
	}
}

func TestLoadSkipsTestsAndKeepsLibraries(t *testing.T) {
	fsys := fstest.MapFS{
		"iace/lib/x/x.rego":                              {Data: []byte("# METADATA\n# title: helpers\npackage iace.lib.x\n\nf(v) := v\n")},
		"iace/rules/aws/s3/public_access/rule.rego":      {Data: []byte(rule(s3pkg, nil, ""))},
		"iace/rules/aws/s3/public_access/rule_test.rego": {Data: []byte("package broken {")},
	}
	lib, err := Load(fsys, BuiltIn)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(lib.Modules) != 2 || len(lib.Rules) != 1 {
		t.Errorf("%d modules, %d rules; want the library and the rule, tests skipped", len(lib.Modules), len(lib.Rules))
	}
}

func TestLoadBuiltInPolicies(t *testing.T) {
	lib, err := Load(policies.FS, BuiltIn)
	if err != nil {
		t.Fatalf("Load(policies.FS): %v", err)
	}
	if len(lib.Rules) == 0 {
		t.Fatal("no built-in rules")
	}
}

var opaRequire = regexp.MustCompile(`(?m)^\s*github\.com/open-policy-agent/opa (v\S+)`)

// TestOPAVersionsMatch keeps the OPA library the engine links equal to the opa CLI that checks
// and tests the policies (ADR 0002): a bump moves both, as dependabot's opa group does.
func TestOPAVersionsMatch(t *testing.T) {
	version := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := opaRequire.FindSubmatch(data)
		if m == nil {
			t.Fatalf("%s does not require github.com/open-policy-agent/opa", path)
		}
		return string(m[1])
	}
	if lib, cli := version("../../go.mod"), version("../../tools/opa/go.mod"); lib != cli {
		t.Errorf("go.mod has OPA %s, tools/opa/go.mod %s: bump them together", lib, cli)
	}
}
