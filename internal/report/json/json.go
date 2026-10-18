// Package json writes a report as the versioned JSON document of schemas/findings.v1.json, for
// machines and archives. The output is deterministic: struct fields in declaration order, map
// keys sorted, and every list already sorted by the scan.
package json

import (
	"bytes"
	stdjson "encoding/json"
	"encoding/json/v2"
	"fmt"
	"io"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// SchemaVersion is the schema_version of every report this package writes.
const SchemaVersion = "1"

// SchemaID is the $id of schemas/findings.v1.json.
const SchemaID = "https://github.com/thuansec/iac-compliance-enforcer/schemas/findings.v1.json"

type document struct {
	SchemaVersion string               `json:"schema_version"`
	Tool          model.Tool           `json:"tool"`
	PolicySources []model.PolicySource `json:"policy_sources"`
	Inputs        []string             `json:"inputs"`
	Summary       summary              `json:"summary"`
	Findings      []finding            `json:"findings"`
	Warnings      []string             `json:"warnings"`
	CoverageGaps  []gap                `json:"coverage_gaps"`
}

type summary struct {
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Open     int    `json:"open"`
	Excepted int    `json:"excepted"`
	Blocking int    `json:"blocking"`
	FailOn   string `json:"fail_on"`
	// MinSeverity and Hidden say which findings the report leaves out; the counts above
	// include them.
	MinSeverity    model.Severity `json:"min_severity"`
	Hidden         int            `json:"hidden"`
	RulesEvaluated int            `json:"rules_evaluated"`
	RulesLoaded    int            `json:"rules_loaded"`
}

// finding is model.Finding with attribute_path null, not [], when the violation names none.
type finding struct {
	RuleID        string                `json:"rule_id"`
	Title         string                `json:"title"`
	Severity      model.Severity        `json:"severity"`
	CSP           string                `json:"csp"`
	Service       string                `json:"service"`
	Status        model.Status          `json:"status"`
	Message       string                `json:"message"`
	Resource      model.FindingResource `json:"resource"`
	RootModule    string                `json:"root_module"`
	Location      model.Location        `json:"location"`
	AttributePath any                   `json:"attribute_path"`
	Remediation   string                `json:"remediation"`
	Frameworks    map[string][]string   `json:"frameworks"`
	References    []string              `json:"references"`
	PolicySource  model.PolicySource    `json:"policy_source"`
	Fingerprint   string                `json:"fingerprint"`
	Exception     *model.Exception      `json:"exception"`
	// AISuggestion is null until AI fix suggestions (M10) attach one.
	AISuggestion any `json:"ai_suggestion"`
}

type gap struct {
	RootModule string        `json:"root_module"`
	Kind       model.GapKind `json:"kind"`
	Detail     string        `json:"detail"`
	File       string        `json:"file"`
	Line       int           `json:"line"`
}

// Write writes r to w as indented JSON followed by a newline.
func Write(w io.Writer, r *model.Report) error {
	data, err := Marshal(r)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write JSON report: %w", err)
	}
	return nil
}

// Marshal encodes r as the indented findings v1 document.
func Marshal(r *model.Report) ([]byte, error) {
	doc := document{
		SchemaVersion: SchemaVersion,
		Tool:          r.Tool,
		PolicySources: r.PolicySources,
		Inputs:        r.Inputs,
		Summary: summary{
			Critical: r.Summary.Critical, High: r.Summary.High, Medium: r.Summary.Medium,
			Low: r.Summary.Low, Info: r.Summary.Info, Open: r.Summary.Open, Excepted: r.Summary.Excepted,
			Blocking: r.Summary.Blocking,
			FailOn:   r.Summary.FailOn, MinSeverity: r.MinSeverity, Hidden: r.Hidden,
			RulesEvaluated: r.RulesEvaluated, RulesLoaded: r.RulesLoaded,
		},
		Findings:     make([]finding, len(r.Findings)),
		Warnings:     r.Warnings,
		CoverageGaps: make([]gap, len(r.CoverageGaps)),
	}
	for i, f := range r.Findings {
		var path any
		if f.AttributePath != nil {
			path = f.AttributePath
		}
		doc.Findings[i] = finding{
			RuleID: f.RuleID, Title: f.Title, Severity: f.Severity, CSP: f.CSP, Service: f.Service,
			Status: f.Status, Message: f.Message, Resource: f.Resource, RootModule: f.RootModule,
			Location: f.Location, AttributePath: path, Remediation: f.Remediation,
			Frameworks: f.Frameworks, References: f.References, PolicySource: f.PolicySource,
			Fingerprint: f.Fingerprint, Exception: f.Exception,
		}
	}
	for i, g := range r.CoverageGaps {
		doc.CoverageGaps[i] = gap{RootModule: g.RootModule, Kind: g.Kind, Detail: g.Detail, File: g.File, Line: g.Line}
	}
	compact, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode JSON report: %w", err)
	}
	var out bytes.Buffer
	if err := stdjson.Indent(&out, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("format JSON report: %w", err)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
