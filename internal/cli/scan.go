package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/thuansec/iac-compliance-enforcer/internal/app"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/report/text"
)

// failOnValues are the accepted --fail-on values, most severe first.
var failOnValues = []string{"critical", "high", "medium", "low", "info", model.FailOnNone}

func newScanCommand(policies fs.FS) *cobra.Command {
	var (
		opts       app.ScanOptions
		failOnGaps bool
		timeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "scan [PATH]",
		Short: "Check the Terraform under PATH against the policies",
		Long: "scan loads the Terraform under PATH (default \".\") without executing anything, evaluates\n" +
			"every rule over each root module and prints the findings. It exits 0 when no open finding\n" +
			"is at or above --fail-on, 1 when one is, and 2 when the scan could not be trusted: a policy\n" +
			"error, a parse error, no Terraform under PATH, a timeout, or coverage gaps with --fail-on-gaps.",
		Example: "  iace scan\n  iace scan infra/prod --fail-on critical\n  iace scan . --var env=prod --var-file prod.tfvars",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			if !slices.Contains(failOnValues, opts.FailOn) {
				return fmt.Errorf("invalid value for the \"--fail-on\" flag: want one of %v", failOnValues)
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
			r, err := app.Scan(ctx, path, opts)
			if err != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return &exitCodeError{code: exitError, msg: fmt.Sprintf("scan %s: timed out after %s (--timeout)", path, timeout)}
				}
				return &exitCodeError{code: exitError, msg: err.Error()}
			}
			// Write the report before deciding the exit code: CI keeps it even when the scan fails.
			if err := text.Write(cmd.OutOrStdout(), r); err != nil {
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
	f.BoolVar(&failOnGaps, "fail-on-gaps", false, "exit 2 when the scan has coverage gaps (parts it could not check)")
	f.DurationVar(&timeout, "timeout", 5*time.Minute, "abort the whole scan after this long, with exit 2")
	f.StringArrayVar(&opts.Vars, "var", nil, "set a root variable, NAME=VALUE (repeatable)")
	f.StringArrayVar(&opts.VarFiles, "var-file", nil, "read root variables from a tfvars file relative to PATH (repeatable)")
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
