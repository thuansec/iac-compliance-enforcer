// Package cli implements the iace command line: it parses arguments and flags, runs the command,
// and turns the outcome into an exit code. It is the only package that reads os.Args or the
// environment, decides where stdout and stderr go, and calls os.Exit.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes from the CLI contract. Exit code 1 (blocking findings) arrives with `iace scan`.
const (
	exitOK    = 0
	exitError = 2
)

// Main runs iace with the process arguments and exits with its exit code.
func Main() {
	os.Exit(Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// Run executes the iace command line with args. Reports go to stdout and diagnostics to stderr.
// It returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if args == nil {
		args = []string{} // cobra would read os.Args instead of nil args
	}
	root := newRootCommand()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		// Nothing else could report a failed write to stderr, so its error is ignored.
		_, _ = fmt.Fprintf(stderr, "iace: %v; see 'iace --help'\n", err)
		return exitError
	}
	return exitOK
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "iace",
		Short: "Check Terraform for security and compliance misconfigurations",
		Long: "iace statically checks Terraform for security and compliance misconfigurations in AWS and\n" +
			"Azure. It never runs Terraform, providers or modules from the code it scans.",
		Example: "  iace version\n  iace version --json",
		// Run prints errors as one line on stderr; full usage text would bury that line.
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableSuggestions: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(newVersionCommand())

	// cobra adds its help command lazily; create it now so it has an example like every command.
	root.InitDefaultHelpCmd()
	for _, cmd := range root.Commands() {
		if cmd.Name() == "help" {
			cmd.Example = "  iace help version"
		}
	}
	return root
}
