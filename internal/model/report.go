package model

// Report is everything one scan produced, the input of every reporter (iace-reporting). Field
// order is the JSON key order; the JSON report (schemas/findings.v1.json) adds tool and policy
// source information.
type Report struct {
	// Inputs are the scanned root modules, relative to the scan root, sorted.
	Inputs []string `json:"inputs"`
	// Findings are sorted by severity (most severe first), rule ID, file, line and address.
	// Those below MinSeverity are left out and counted in Hidden; the summary counts them all.
	Findings []Finding `json:"findings"`
	// MinSeverity is the lowest severity shown ("info" shows everything).
	MinSeverity  Severity    `json:"min_severity"`
	Hidden       int         `json:"hidden"`
	CoverageGaps []ReportGap `json:"coverage_gaps"`
	// RulesEvaluated and RulesLoaded differ when a rule selection left rules unchecked.
	RulesEvaluated int     `json:"rules_evaluated"`
	RulesLoaded    int     `json:"rules_loaded"`
	Summary        Summary `json:"summary"`
}

// ReportGap is a coverage gap of one root module.
type ReportGap struct {
	RootModule string `json:"root_module"`
	CoverageGap
}

// Summary counts a report's findings.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	// Blocking counts open findings at or above FailOn.
	Blocking int `json:"blocking"`
	// FailOn is a Severity, or "none" when no finding blocks.
	FailOn string `json:"fail_on"`
}

// FailOnNone makes no finding blocking.
const FailOnNone = "none"

// Summarize counts findings by severity and those open at or above failOn (a Severity or
// FailOnNone).
func Summarize(findings []Finding, failOn string) Summary {
	s := Summary{FailOn: failOn}
	threshold := Severity(failOn).Rank()
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
		if failOn != FailOnNone && f.Status == StatusOpen && f.Severity.Rank() >= threshold {
			s.Blocking++
		}
	}
	return s
}
