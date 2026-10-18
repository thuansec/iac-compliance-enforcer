package policies

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCapabilitiesDenylist checks the embedded capabilities: no builtin that reaches the network
// or the host, or that is non-deterministic, and no allowed network host.
func TestCapabilitiesDenylist(t *testing.T) {
	data, err := FS.ReadFile("capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var caps struct {
		Builtins []struct {
			Name string `json:"name"`
		} `json:"builtins"`
		AllowNet *[]string `json:"allow_net"`
	}
	if err := json.Unmarshal(data, &caps); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, b := range caps.Builtins {
		names[b.Name] = true
	}
	for _, denied := range []string{"http.send", "net.lookup_ip_addr", "opa.runtime", "time.now_ns", "rand.intn", "uuid.rfc4122"} {
		if names[denied] {
			t.Errorf("capabilities allow %s", denied)
		}
	}
	if caps.AllowNet == nil || len(*caps.AllowNet) != 0 {
		t.Errorf("allow_net = %v, want an empty list", caps.AllowNet)
	}
	// Pure CIDR math is kept despite the net. prefix: security group rules need it.
	if !names["net.cidr_contains"] || len(names) < 100 {
		t.Errorf("capabilities lost deterministic builtins (%d left)", len(names))
	}
}

// rawBlockAccess finds rule code that reads a nested block's entries from values directly. A
// block written as one JSON object in .tf.json stays an object (ADR 0006), so `[0]`, `[_]` or
// `some … in` over it misses the block: rules must use tf.blocks, tf.value_or and tf.is_unknown.
var rawBlockAccess = []*regexp.Regexp{
	// values.x[0], values["x"][_], values[name][0].
	regexp.MustCompile(`\bvalues(\.[A-Za-z_]\w*|\[[^\]]*\])*\[(0|_)\]`),
	// some or every … in r.values.x, input.resources[0].values.x.
	regexp.MustCompile(`\b(some|every)\b[^\n]*\bin\s+(?:[A-Za-z_]\w*(\[[^\]]*\])*\.)*values\b`),
	// object.get(r.values, [..., 0, ...], d): the same read through a path argument.
	regexp.MustCompile(`\bobject\.get\(\s*[^,]*\bvalues\b[^,]*,\s*\[[^\]]*(^|[\[,\s])0\s*[,\]]`),
}

// TestRulesUseThePathHelpers rejects rule files that index values with a literal [0] or
// iterate it with [_] or `some … in` instead of the iace.lib.tf helpers.
func TestRulesUseThePathHelpers(t *testing.T) {
	checked := 0
	err := fs.WalkDir(FS, "iace/rules", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
			return err
		}
		src, err := FS.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for i, line := range strings.Split(string(src), "\n") {
			code := stripComment(line)
			for _, re := range rawBlockAccess {
				if re.MatchString(code) {
					t.Errorf("%s:%d reads values directly; use tf.blocks, tf.value_or or tf.is_unknown: %s", path, i+1, strings.TrimSpace(code))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no rule files checked")
	}
}

// stripComment removes a # comment, but not a # inside a string literal.
func stripComment(line string) string {
	inString, escaped := false, false
	for i, c := range line {
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case c == '#' && !inString:
			return line[:i]
		}
	}
	return line
}

// TestEveryRegoFileIsEmbedded guards the embed pattern: files whose names start with _ or .
// would otherwise be left out of the binary silently.
func TestEveryRegoFileIsEmbedded(t *testing.T) {
	onDisk := 0
	err := filepath.WalkDir("iace", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return err
		}
		onDisk++
		if _, err := FS.ReadFile(filepath.ToSlash(path)); err != nil {
			t.Errorf("%s is not embedded", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if onDisk == 0 {
		t.Fatal("no Rego files found")
	}
}

func TestRawBlockAccessPatterns(t *testing.T) {
	for line, want := range map[string]bool{
		`r.values.metadata_options[0].http_tokens == "required"`:           true,
		`some rule in r.values.ingress[_]`:                                 true,
		`r.values["ingress"][0]`:                                           true,
		`some ing in r.values.ingress`:                                     true,
		`some ing in tf.blocks(r.values, "ingress")`:                       false,
		`blocks := tf.blocks(r.values, "ingress")`:                         false,
		`tf.value_or(r, ["metadata_options", 0, "http_tokens"], "")`:       false,
		`r.values[name][0].http_tokens`:                                    true,
		`r.values[name][_]`:                                                true,
		`every b in r.values.ingress {`:                                    true,
		`some b in input.resources[0].values.ingress`:                      true,
		`object.get(r.values, ["metadata_options", 0, "http_tokens"], "")`: true,
		`object.get(r.values, ["tags", "Name"], "")`:                       false,
		`x := "#"; r.values.a[0]`:                                          true,
	} {
		got := false
		for _, re := range rawBlockAccess {
			got = got || re.MatchString(stripComment(line))
		}
		if got != want {
			t.Errorf("%q: flagged %v, want %v", line, got, want)
		}
	}
}
