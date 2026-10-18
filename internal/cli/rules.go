package cli

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/thuansec/iac-compliance-enforcer/internal/app"
	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
)

// ruleSource names where a rule comes from; external bundles arrive with M8.
const ruleSource = "builtin"

var csps = []string{"aws", "azure", "generic"}

func newRulesCommand(policies fs.FS) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rules",
		Short:   "List the loaded rules or show one",
		Example: "  iace rules list\n  iace rules list --csp azure\n  iace rules show IACE-AWS-EC2-001",
	}
	cmd.AddCommand(newRulesListCommand(policies), newRulesShowCommand(policies))
	return cmd
}

func newRulesListCommand(policies fs.FS) *cobra.Command {
	var csp string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the loaded rules: ID, severity, CSP, source and title",
		Example: "  iace rules list\n  iace rules list --csp aws",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if csp != "" && !slices.Contains(csps, csp) {
				return fmt.Errorf("invalid value for the \"--csp\" flag: want one of %v", csps)
			}
			rules, err := app.Rules(cmd.Context(), policies)
			if err != nil {
				return &exitCodeError{code: exitError, msg: err.Error()}
			}
			var b bytes.Buffer
			tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			for _, r := range rules {
				if csp == "" || r.CSP == csp {
					// tabwriter buffers until Flush, whose error is checked below.
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", oneLine(r.ID), oneLine(r.Severity), oneLine(r.CSP), ruleSource, oneLine(r.Title))
				}
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b.Bytes())
			return err
		},
	}
	cmd.Flags().StringVar(&csp, "csp", "", "list only this cloud's rules: aws|azure|generic")
	return cmd
}

func newRulesShowCommand(policies fs.FS) *cobra.Command {
	return &cobra.Command{
		Use:     "show ID",
		Short:   "Show a rule's full metadata and remediation",
		Example: "  iace rules show IACE-AWS-EC2-001",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := app.Rules(cmd.Context(), policies)
			if err != nil {
				return &exitCodeError{code: exitError, msg: err.Error()}
			}
			i := slices.IndexFunc(rules, func(r engine.Rule) bool { return r.ID == args[0] })
			if i < 0 {
				return &exitCodeError{code: exitError, msg: fmt.Sprintf(
					"rules show: no loaded rule has ID %s (see iace rules list)", oneLine(args[0]))}
			}
			_, err = cmd.OutOrStdout().Write(showRule(rules[i]))
			return err
		},
	}
}

func showRule(r engine.Rule) []byte {
	var b bytes.Buffer
	field := func(name, value string) { fmt.Fprintf(&b, "%-16s %s\n", name+":", oneLine(value)) }
	fmt.Fprintf(&b, "%s · %s\n", oneLine(r.ID), oneLine(r.Title))
	field("severity", r.Severity)
	field("csp", r.CSP)
	field("service", r.Service)
	field("resource types", strings.Join(r.ResourceTypes, ", "))
	frameworks := "none"
	if len(r.Frameworks) > 0 {
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(r.Frameworks)) {
			parts = append(parts, k+" "+strings.Join(r.Frameworks[k], ", "))
		}
		frameworks = strings.Join(parts, "; ")
	}
	field("frameworks", frameworks)
	field("source", ruleSource)
	field("package", r.Package)
	if r.Deprecated {
		field("deprecated", "replaced by "+r.ReplacedBy)
	}
	if len(r.Params) > 0 {
		field("params", "declared (JSON Schema; set through the repository configuration)")
	}
	field("description", r.Description)
	field("remediation", r.Remediation)
	b.WriteString("references:\n")
	for _, rr := range r.RelatedResources {
		ref := oneLine(rr.Ref)
		if d := oneLine(rr.Description); d != "" {
			ref += " (" + d + ")"
		}
		fmt.Fprintf(&b, "  %s\n", ref)
	}
	return b.Bytes()
}

// oneLine keeps metadata text on one line without control characters.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
