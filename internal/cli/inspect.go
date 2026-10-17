package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/thuansec/iac-compliance-enforcer/internal/app"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
)

// envTrustModuleManifest sets --trust-module-manifest from the pipeline's environment.
const envTrustModuleManifest = "IACE_TRUST_MODULE_MANIFEST"

func newInspectCommand() *cobra.Command {
	var (
		asJSON bool
		opts   app.InspectOptions
	)
	cmd := &cobra.Command{
		Use:   "inspect PATH",
		Short: "Print the normalized input document of each root module",
		Long: "inspect loads the Terraform under PATH without executing anything and prints, for each root\n" +
			"module, the input document that policies evaluate: resources with their values, unknown and\n" +
			"sensitive paths, module calls, variables, outputs and coverage gaps. Secrets are redacted.\n" +
			"It exits 2 when a file could not be parsed as Terraform would parse it.",
		Example: "  iace inspect .\n  iace inspect infra/prod --json\n  iace inspect . --var env=prod --var-file prod.tfvars",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("trust-module-manifest") {
				trust, err := envBool(envTrustModuleManifest)
				if err != nil {
					return err
				}
				opts.TrustModuleManifest = trust
			}
			docs, err := app.Inspect(cmd.Context(), args[0], opts)
			if err != nil {
				return err
			}
			if err := writeDocuments(cmd.OutOrStdout(), docs, asJSON); err != nil {
				return err
			}
			if n := app.ParseErrors(docs); n > 0 {
				return &exitCodeError{code: exitError, msg: fmt.Sprintf(
					"inspect %s: %d parse error(s); the documents' coverage_gaps name them", args[0], n)}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&asJSON, "json", false, "print the input documents as a JSON array")
	f.StringArrayVar(&opts.Vars, "var", nil, "set a root variable, NAME=VALUE (repeatable)")
	f.StringArrayVar(&opts.VarFiles, "var-file", nil, "read root variables from a tfvars file relative to PATH (repeatable)")
	f.BoolVar(&opts.TrustModuleManifest, "trust-module-manifest", false,
		"resolve remote modules through .terraform/modules/modules.json (also "+envTrustModuleManifest+"=true);\n"+
			"only for a pipeline that ran terraform init itself in a trusted step, which must first\n"+
			"remove any committed .terraform: a pull request can commit a forged manifest")
	return cmd
}

// envBool reads a boolean environment variable; unset or empty is false. An invalid value is an
// error that names the variable but not its value.
func envBool(name string) (bool, error) {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: want true or false", name)
	}
	return b, nil
}

// writeDocuments prints docs as an indented JSON array, or as a short summary per document.
func writeDocuments(w io.Writer, docs []*model.InputDocument, asJSON bool) error {
	if asJSON {
		var raw bytes.Buffer
		raw.WriteByte('[')
		for i, doc := range docs {
			data, err := model.EncodeInput(doc)
			if err != nil {
				return fmt.Errorf("encode input document: %w", err)
			}
			if i > 0 {
				raw.WriteByte(',')
			}
			raw.Write(data)
		}
		raw.WriteByte(']')
		var out bytes.Buffer
		if err := json.Indent(&out, raw.Bytes(), "", "  "); err != nil {
			return fmt.Errorf("format input documents: %w", err)
		}
		out.WriteByte('\n')
		if _, err := w.Write(out.Bytes()); err != nil {
			return fmt.Errorf("write input documents: %w", err)
		}
		return nil
	}
	var out bytes.Buffer
	if len(docs) == 0 {
		out.WriteString("no Terraform root modules under this path\n")
	}
	for _, doc := range docs {
		fmt.Fprintf(&out, "root module %s\n  resources: %d\n  module calls: %d\n  coverage gaps: %d\n",
			doc.Source.RootModule, len(doc.Resources), len(doc.ModuleCalls), len(doc.CoverageGaps))
		for _, g := range doc.CoverageGaps {
			fmt.Fprintf(&out, "    %s %s:%d %s\n", g.Kind, g.File, g.Line, g.Detail)
		}
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return fmt.Errorf("write input documents: %w", err)
	}
	return nil
}
