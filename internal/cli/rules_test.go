package cli

import (
	"strings"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
)

func TestShowRule(t *testing.T) {
	r := engine.Rule{
		ID: "IACE-GEN-X-001", Title: "Title\nFORGED\x1b[2J line", Severity: "low", CSP: "generic",
		Service: "x", ResourceTypes: []string{"a", "b"}, Remediation: "Fix\nit.", Description: "Why.",
		Deprecated: true, ReplacedBy: "IACE-GEN-X-002\nFORGED", Package: "iace.rules.generic.x.y",
		Params:           map[string]any{"type": "object"},
		RelatedResources: []engine.RelatedResource{{Ref: "https://example.com/doc", Description: "Doc"}},
	}
	want := `IACE-GEN-X-001 · Title FORGED [2J line
severity:        low
csp:             generic
service:         x
resource types:  a, b
frameworks:      none
source:          builtin
package:         iace.rules.generic.x.y
deprecated:      replaced by IACE-GEN-X-002 FORGED
params:          declared (JSON Schema; set through the repository configuration)
description:     Why.
remediation:     Fix it.
references:
  https://example.com/doc (Doc)
`
	if got := string(showRule(r)); got != want {
		t.Errorf("showRule:\n%s\nwant:\n%s", got, want)
	}
	if strings.ContainsRune(string(showRule(r)), 0x1b) {
		t.Error("an escape character reached the output")
	}
}
