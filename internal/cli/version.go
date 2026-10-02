package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/thuansec/iac-compliance-enforcer/internal/version"
)

func newVersionCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "version",
		Short:   "Print the iace version, commit and build date",
		Example: "  iace version\n  iace version --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout(), version.Get(), asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the build information as a JSON document")
	return cmd
}

func writeVersion(w io.Writer, info version.Info, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			return fmt.Errorf("write version: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "%s %s (commit %s, built %s)\n", info.Name, info.Version, info.Commit, info.Date); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}
