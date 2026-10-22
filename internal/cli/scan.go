package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thuansec/iac-compliance-enforcer/internal/app"
	"github.com/thuansec/iac-compliance-enforcer/internal/engine"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	reportjson "github.com/thuansec/iac-compliance-enforcer/internal/report/json"
	"github.com/thuansec/iac-compliance-enforcer/internal/report/sarif"
	"github.com/thuansec/iac-compliance-enforcer/internal/report/text"
)

// outputFormats are the report formats -o accepts; writing to files and several formats per run
// arrive with T-0305.
var outputFormats = []string{"text", "json", "sarif"}

// failOnValues are the accepted --fail-on values, most severe first; --min-severity takes the
// same without none.
var failOnValues = []string{"critical", "high", "medium", "low", "info", model.FailOnNone}

func newScanCommand(policies fs.FS) *cobra.Command {
	var (
		opts        app.ScanOptions
		failOnGaps  bool
		timeout     time.Duration
		minSeverity string
		output      string
	)
	cmd := &cobra.Command{
		Use:   "scan [PATH...]",
		Short: "Check the Terraform under each PATH against the policies",
		Long: "scan loads the Terraform under each PATH (default \".\") without executing anything, evaluates\n" +
			"every rule over each root module and prints the findings; with several paths, root modules\n" +
			"and files are named by their path. It exits 0 when no open finding\n" +
			"is at or above --fail-on, 1 when one is, and 2 when the scan could not be trusted: a policy\n" +
			"error, a parse error, no Terraform under PATH, a timeout, or coverage gaps with --fail-on-gaps.",
		Example: "  iace scan\n  iace scan -o json > findings.json\n  iace scan -o sarif > iace.sarif\n  iace scan infra/prod infra/staging\n  iace scan infra/prod --fail-on critical\n  iace scan . --var env=prod --var-file prod.tfvars",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}
			cwd, err := os.Getwd()
			if err != nil {
				return &exitCodeError{code: exitError, msg: fmt.Sprintf("scan: working directory: %v", err)}
			}
			if paths, err = app.RelativePaths(cwd, paths); err != nil {
				return err
			}
			path := strings.Join(paths, " ")
			if !slices.Contains(failOnValues, opts.FailOn) {
				return fmt.Errorf("invalid value for the \"--fail-on\" flag: want one of %v", failOnValues)
			}
			severities := failOnValues[:len(failOnValues)-1]
			if !slices.Contains(severities, minSeverity) {
				return fmt.Errorf("invalid value for the \"--min-severity\" flag: want one of %v", severities)
			}
			opts.MinSeverity = model.Severity(minSeverity)
			if !slices.Contains(outputFormats, output) {
				return fmt.Errorf("invalid value for the \"--output\" flag: want one of %v", outputFormats)
			}
			if !cmd.Flags().Changed("trust-module-manifest") {
				trust, err := envBool(envTrustModuleManifest)
				if err != nil {
					return err
				}
				opts.TrustModuleManifest = trust
			}
			opts.Policies = policies
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			r, err := app.ScanPaths(ctx, paths, opts)
			var unknownRule *engine.UnknownRuleError
			var pathErr *app.PathError
			if errors.As(err, &pathErr) {
				return err
			}
			if errors.As(err, &unknownRule) {
				return fmt.Errorf("--rule argument %d names no loaded rule (rule IDs look like IACE-AWS-EC2-001)", unknownRule.Index)
			}
			if err != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return &exitCodeError{code: exitError, msg: fmt.Sprintf("scan %s: timed out after %s (--timeout)", path, timeout)}
				}
				return &exitCodeError{code: exitError, msg: err.Error()}
			}
			// Write the report before deciding the exit code: CI keeps it even when the scan fails.
			write := text.Write
			switch output {
			case "json":
				write = reportjson.Write
			case "sarif":
				write = sarif.Writer{Base: app.SingleScanBase(cwd, paths)}.Write
			}
			if err := write(cmd.OutOrStdout(), r); err != nil {
				return err
			}
			switch n := app.ReportParseErrors(r); {
			case n > 0:
				return &exitCodeError{code: exitError, msg: fmt.Sprintf(
					"scan %s: %d parse error(s); the coverage gaps name them", path, n)}
			case failOnGaps && len(r.CoverageGaps) > 0:
				return &exitCodeError{code: exitError, msg: fmt.Sprintf(
					"scan %s: %d coverage gap(s) with --fail-on-gaps", path, len(r.CoverageGaps))}
			case r.Summary.Blocking > 0:
				return &exitCodeError{code: exitBlocking, msg: fmt.Sprintf(
					"%d open %s at or above %s", r.Summary.Blocking, plural(r.Summary.Blocking, "finding"), opts.FailOn)}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.FailOn, "fail-on", "high", "exit 1 when an open finding is at or above this severity: critical|high|medium|low|info|none")
	f.StringVarP(&output, "output", "o", "text", "report format on stdout: text|json|sarif (json follows schemas/findings.v1.json; sarif is SARIF 2.1.0 for code scanning)")
	f.StringVar(&minSeverity, "min-severity", "info", "hide findings below this severity from the report (they still count for --fail-on): critical|high|medium|low|info")
	f.StringArrayVar(&opts.Rules, "rule", nil, "evaluate only this rule ID (repeatable)")
	f.BoolVar(&failOnGaps, "fail-on-gaps", false, "exit 2 when the scan has coverage gaps (parts it could not check)")
	f.DurationVar(&timeout, "timeout", 5*time.Minute, "abort the whole scan after this long, with exit 2")
	f.StringArrayVar(&opts.Vars, "var", nil, "set a root variable, NAME=VALUE (repeatable)")
	f.StringArrayVar(&opts.VarFiles, "var-file", nil, "read root variables from a tfvars file relative to PATH, in every PATH (repeatable)")
	f.BoolVar(&opts.TrustModuleManifest, "trust-module-manifest", false,
		"resolve remote modules through .terraform/modules/modules.json (also "+envTrustModuleManifest+"=true);\n"+
			"only for a pipeline that ran terraform init itself in a trusted step")
	return cmd
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
