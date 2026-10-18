// Package text writes a report for people in a terminal: findings grouped by severity as
// `file:line  RULE-ID  address  message` with a remediation line, coverage gaps, a summary and
// the scanned root modules. It renders no attribute values.
package text

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// Write writes r to w. r's findings are already sorted.
func Write(w io.Writer, r *model.Report) error {
	var b bytes.Buffer
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
	}
	var group model.Severity
	for _, f := range r.Findings {
		if f.Severity != group {
			if group != "" {
				b.WriteByte('\n')
			}
			group = f.Severity
			b.WriteString(strings.ToUpper(string(group)) + "\n")
		}
		fmt.Fprintf(&b, "  %s:%d  %s  %s  %s\n", oneLine(f.Location.File), f.Location.StartLine, oneLine(f.RuleID), oneLine(f.Resource.Address), oneLine(f.Message))
		fmt.Fprintf(&b, "    fix: %s\n", oneLine(f.Remediation))
	}
	b.WriteByte('\n')
	if len(r.CoverageGaps) > 0 {
		fmt.Fprintf(&b, "Coverage gaps: %d\n", len(r.CoverageGaps))
		for _, g := range r.CoverageGaps {
			fmt.Fprintf(&b, "  %s: %s %s:%d %s\n", oneLine(g.RootModule), oneLine(string(g.Kind)), oneLine(g.File), g.Line, oneLine(g.Detail))
		}
	}
	s := r.Summary
	fmt.Fprintf(&b, "%d %s (critical %d, high %d, medium %d, low %d, info %d); %d blocking at fail-on %s\n",
		len(r.Findings), noun(len(r.Findings), "finding"), s.Critical, s.High, s.Medium, s.Low, s.Info, s.Blocking, s.FailOn)
	inputs := make([]string, len(r.Inputs))
	for i, in := range r.Inputs {
		inputs[i] = oneLine(in)
	}
	fmt.Fprintf(&b, "Scanned %d %s: %s\n", len(r.Inputs), noun(len(r.Inputs), "root module"), strings.Join(inputs, ", "))
	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}
	return nil
}

// noun returns word for one and its plural otherwise.
func noun(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// oneLine keeps a string from a policy or the scanned repository (messages, file and directory
// names) on one line without control characters, so it can neither forge report lines nor send
// terminal escape sequences.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
