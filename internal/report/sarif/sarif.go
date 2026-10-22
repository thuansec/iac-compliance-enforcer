// Package sarif writes a report as SARIF 2.1.0 for GitHub code scanning and other SARIF
// consumers, following iace-reporting's references/sarif.md. Regions are line-level: iace's
// columns count grapheme clusters, which no SARIF column kind matches; and the run carries no
// automationDetails, so the upload's category names it (ADR 0052). URIs are relative to the
// directory iace ran in: run it from the repository root for GitHub.
package sarif

import (
	"bytes"
	stdjson "encoding/json"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// InformationURI is the tool's home page.
const InformationURI = "https://github.com/thuansec/iac-compliance-enforcer"

// maxTags is GitHub's limit on tags per rule.
const maxTags = 20

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Invocations []invocation `json:"invocations"`
	Results     []result     `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	InformationURI  string `json:"informationUri"`
	Rules           []rule `json:"rules"`
}

type rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     text           `json:"shortDescription"`
	FullDescription      text           `json:"fullDescription"`
	Help                 help           `json:"help"`
	DefaultConfiguration configuration  `json:"defaultConfiguration"`
	Properties           ruleProperties `json:"properties"`
}

type text struct {
	Text string `json:"text"`
}

type help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type configuration struct {
	Level string `json:"level"`
}

type ruleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Precision        string   `json:"precision"`
	Tags             []string `json:"tags"`
}

type invocation struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	ToolExecutionNotifications []notification `json:"toolExecutionNotifications"`
}

type notification struct {
	Level   string `json:"level"`
	Message text   `json:"message"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []suppression     `json:"suppressions,omitempty"`
	Properties          resultProperties  `json:"properties"`
}

type location struct {
	PhysicalLocation physicalLocation  `json:"physicalLocation"`
	LogicalLocations []logicalLocation `json:"logicalLocations"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

// region is line-level: SARIF columns would need a column kind iace's grapheme-cluster
// columns do not match (ADR 0052).
type region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type logicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type suppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type resultProperties struct {
	PolicySource string `json:"policySource"`
}

// levels and securitySeverities map iace severities to SARIF (sarif.md); info has no security
// severity.
var (
	levels = map[model.Severity]string{
		model.SeverityCritical: "error", model.SeverityHigh: "error",
		model.SeverityMedium: "warning", model.SeverityLow: "note", model.SeverityInfo: "note",
	}
	securitySeverities = map[model.Severity]string{
		model.SeverityCritical: "9.5", model.SeverityHigh: "8.0",
		model.SeverityMedium: "5.5", model.SeverityLow: "3.0",
	}
	semver = regexp.MustCompile(`^v?(\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?)$`)
)

// Writer encodes reports as SARIF. Base, when set, is the scan path relative to the directory iace
// ran in: a scan of one path names files relative to that path, and SARIF URIs must be relative to
// the working directory (ADR 0052), so each URI is prefixed with Base. Several paths need no Base:
// their files are already named by their path.
type Writer struct {
	Base string
}

// Write writes r to w as SARIF 2.1.0 without a base.
func Write(w io.Writer, r *model.Report) error { return Writer{}.Write(w, r) }

// Marshal encodes r as SARIF 2.1.0 without a base.
func Marshal(r *model.Report) ([]byte, error) { return Writer{}.Marshal(r) }

// Write writes r to w as SARIF 2.1.0, indented and followed by a newline.
func (wr Writer) Write(w io.Writer, r *model.Report) error {
	data, err := wr.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write SARIF report: %w", err)
	}
	return nil
}

// Marshal encodes r as one SARIF run: one rule per rule that produced a finding (sorted by ID),
// one result per finding in the report's order, excepted findings as accepted suppressions.
func (wr Writer) Marshal(r *model.Report) ([]byte, error) {
	d := driver{Name: "iace", Version: r.Tool.Version, InformationURI: InformationURI, Rules: []rule{}}
	if m := semver.FindStringSubmatch(r.Tool.Version); m != nil {
		d.SemanticVersion = m[1]
	}
	index := map[string]int{}
	byID := map[string]model.Finding{}
	for _, f := range r.Findings {
		if _, ok := byID[f.RuleID]; !ok {
			byID[f.RuleID] = f
		}
	}
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		index[id] = len(d.Rules)
		d.Rules = append(d.Rules, ruleOf(byID[id]))
	}
	results := make([]result, 0, len(r.Findings))
	for _, f := range r.Findings {
		res := result{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     levels[f.Severity],
			Message:   text{Text: f.Message},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: uriOf(path.Join(wr.Base, f.Location.File))},
					Region:           region{StartLine: f.Location.StartLine, EndLine: f.Location.EndLine},
				},
				LogicalLocations: []logicalLocation{{FullyQualifiedName: f.Resource.Address, Kind: "resource"}},
			}},
			PartialFingerprints: map[string]string{"iaceFinding/v1": f.Fingerprint},
			Properties:          resultProperties{PolicySource: f.PolicySource.Name + "@" + f.PolicySource.Version},
		}
		if e := f.Exception; f.Status == model.StatusExcepted && e != nil {
			res.Suppressions = []suppression{{
				Kind: "external", Status: "accepted",
				Justification: fmt.Sprintf("%s (owner %s, expires %s, %s)", e.Reason, e.Owner, e.Expires, e.ID),
			}}
		}
		results = append(results, res)
	}
	notifications := []notification{}
	for _, g := range r.CoverageGaps {
		notifications = append(notifications, notification{
			Level:   "warning",
			Message: text{Text: fmt.Sprintf("coverage gap in %s: %s %s:%d %s", g.RootModule, g.Kind, g.File, g.Line, g.Detail)},
		})
	}
	if r.RulesEvaluated < r.RulesLoaded {
		notifications = append(notifications, notification{
			Level:   "warning",
			Message: text{Text: fmt.Sprintf("only %d of %d rules evaluated (--rule): the others were not checked", r.RulesEvaluated, r.RulesLoaded)},
		})
	}
	doc := log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			// No automationDetails: upload-sarif's category (or the workflow, job and matrix
			// key) then tells uploads for different roots apart (ADR 0052).
			Tool:        tool{Driver: d},
			Invocations: []invocation{{ExecutionSuccessful: true, ToolExecutionNotifications: notifications}},
			Results:     results,
		}},
	}
	compact, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode SARIF report: %w", err)
	}
	var out bytes.Buffer
	if err := stdjson.Indent(&out, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("format SARIF report: %w", err)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func ruleOf(f model.Finding) rule {
	tags := []string{"security", "terraform", f.CSP, f.Service}
	for _, k := range slices.Sorted(maps.Keys(f.Frameworks)) {
		for _, c := range f.Frameworks[k] {
			tags = append(tags, k+"/"+c)
		}
	}
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	md := "**Remediation:** " + f.Remediation
	if len(f.References) > 0 {
		md += "\n\n[Reference](" + f.References[0] + ")"
	}
	return rule{
		ID:                   f.RuleID,
		Name:                 pascal(f.Title),
		ShortDescription:     text{Text: f.Title},
		FullDescription:      text{Text: f.Title},
		Help:                 help{Text: f.Remediation, Markdown: md},
		DefaultConfiguration: configuration{Level: levels[f.Severity]},
		Properties: ruleProperties{
			SecuritySeverity: securitySeverities[f.Severity],
			Precision:        "high",
			Tags:             tags,
		},
	}
}

// uriOf makes a repo-relative, slash-separated file path a relative URI reference: each segment
// percent-encoded, so "a#b.tf" or "my file.tf" is not read as a fragment or broken.
func uriOf(file string) string {
	segs := strings.Split(file, "/")
	for i, s := range segs {
		// PathEscape keeps ":", which in a first segment would read as a URI scheme.
		segs[i] = strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
	}
	return strings.Join(segs, "/")
}

// pascal turns a title into a SARIF rule name: "EC2 instances must require IMDSv2" becomes
// "Ec2InstancesMustRequireImdsv2".
func pascal(title string) string {
	var b strings.Builder
	for _, w := range strings.FieldsFunc(title, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		rs := []rune(strings.ToLower(w))
		rs[0] = unicode.ToUpper(rs[0])
		b.WriteString(string(rs))
	}
	return b.String()
}
