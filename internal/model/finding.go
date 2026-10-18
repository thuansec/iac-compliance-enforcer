package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
)

// Finding is one rule violation on one resource (finding v1, specified in the iace-architecture
// skill, references/findings-and-cli.md). The engine builds it from a violation, the rule's
// metadata and the resource's source map; exceptions and AI suggestions are added by later
// stages. Field order is the JSON key order.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	CSP      string   `json:"csp"`
	Service  string   `json:"service"`
	Status   Status   `json:"status"`
	// Message comes from the violation; policies never put attribute values in it.
	Message    string          `json:"message"`
	Resource   FindingResource `json:"resource"`
	RootModule string          `json:"root_module"`
	Location   Location        `json:"location"`
	// AttributePath is nil when the violation names no attribute.
	AttributePath Path                `json:"attribute_path"`
	Remediation   string              `json:"remediation"`
	Frameworks    map[string][]string `json:"frameworks"`
	References    []string            `json:"references"`
	// PolicySource is the library the rule came from (the report's policy_sources lists them).
	PolicySource PolicySource `json:"policy_source"`
	Fingerprint  string       `json:"fingerprint"`
	// Exception is the exception that makes the finding excepted, nil while it is open
	// (exceptions arrive with M4).
	Exception *Exception `json:"exception"`
}

// Exception is an accepted risk that applies to a finding: who owns it, why, until when.
type Exception struct {
	ID      string `json:"id"`
	Owner   string `json:"owner"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	Ticket  string `json:"ticket"`
}

// FindingResource identifies the resource a finding is about.
type FindingResource struct {
	Address  string `json:"address"`
	Type     string `json:"type"`
	Module   string `json:"module"`
	Provider string `json:"provider"`
}

// Location is where a finding points: the attribute's range when the violation's path is
// located, else the resource block's.
type Location struct {
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	StartColumn int    `json:"start_column"`
	EndLine     int    `json:"end_line"`
	EndColumn   int    `json:"end_column"`
}

// Status says whether a finding still counts.
type Status string

// Finding statuses.
const (
	StatusOpen     Status = "open"
	StatusExcepted Status = "excepted"
)

// Severity is a rule's severity, from its metadata.
type Severity string

// Severities, from most to least severe.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank orders severities: higher is more severe, 0 for an unknown one.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// Fingerprint identifies a finding across runs: the hex SHA-256 of the JSON array
// [ruleID, rootModule, address, path] (path null when absent, its index steps integers). It
// leaves out line numbers so it survives edits above the resource, and the JSON encoding
// delimits every part, so no two different inputs share an encoding (ADR 0049).
func Fingerprint(ruleID, rootModule, address string, path Path) string {
	parts := []any{ruleID, rootModule, address, path}
	if path == nil {
		parts[3] = nil
	}
	data, err := json.Marshal(parts)
	if err != nil {
		// Only a negative index step fails to encode, and Path's constructors never make one.
		panic("model: fingerprint: " + err.Error())
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
