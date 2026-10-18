// Package cli implements the iace command line: it parses arguments and flags, runs the command,
// and turns the outcome into an exit code. It is the only package that reads os.Args or the
// environment, decides where stdout and stderr go, and calls os.Exit.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"

	"github.com/spf13/cobra"
)

// Exit codes from the CLI contract.
const (
	exitOK       = 0
	exitBlocking = 1
	exitError    = 2
)

// Main runs iace with the process arguments and exits with its exit code.
func Main() {
	os.Exit(Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// Run executes the iace command line with args. Reports go to stdout and diagnostics to stderr.
// It returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return RunWithPolicies(ctx, args, stdout, stderr, nil)
}

// RunWithPolicies is Run with the policy library of policies (rules and capabilities.json)
// instead of the built-in one when it is not nil. No flag reaches it: tests use it to scan with
// a broken policy.
func RunWithPolicies(ctx context.Context, args []string, stdout, stderr io.Writer, policies fs.FS) int {
	if args == nil {
		args = []string{} // cobra would read os.Args instead of nil args
	}
	root := newRootCommand(policies) //nolint:contextcheck // commands take ctx from cmd.Context(), which ExecuteContext(ctx) below sets
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		// Nothing else could report a failed write to stderr, so its errors are ignored.
		var ce *exitCodeError
		if errors.As(err, &ce) {
			_, _ = fmt.Fprintf(stderr, "iace: %s\n", ce.msg)
			return ce.code
		}
		_, _ = fmt.Fprintf(stderr, "iace: %v; see 'iace --help'\n", err)
		return exitError
	}
	return exitOK
}

// exitCodeError ends a command that already wrote its output with an exit code and a one-line
// message, without the usage hint: the command ran, but its result is not trustworthy.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

func newRootCommand(policies fs.FS) *cobra.Command {
	root := &cobra.Command{
		Use:   "iace",
		Short: "Check Terraform for security and compliance misconfigurations",
		Long: "iace statically checks Terraform for security and compliance misconfigurations in AWS and\n" +
			"Azure. It never runs Terraform, providers or modules from the code it scans.",
		Example: "  iace scan .\n  iace inspect .\n  iace rules list\n  iace version --json",
		// Run prints errors as one line on stderr; full usage text would bury that line.
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableSuggestions: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(newVersionCommand(), newInspectCommand(), newScanCommand(policies), newRulesCommand(policies))
	root.SetFlagErrorFunc(flagError)

	// cobra adds its help command lazily; create it now so it has an example like every command.
	root.InitDefaultHelpCmd()
	for _, cmd := range root.Commands() {
		if cmd.Name() == "help" {
			cmd.Example = "  iace help version"
		}
	}
	return root
}

// Flag errors that may be printed: they name the flag and nothing the user typed after it.
var (
	safeFlagError = regexp.MustCompile(`^(unknown flag|flag needs an argument): --[A-Za-z0-9][A-Za-z0-9-]*$`)
	shorthandFlag = regexp.MustCompile(`^(unknown shorthand flag|flag needs an argument): '(.)' in `)
	invalidValue  = regexp.MustCompile(`^invalid argument ".*" for "(-[A-Za-z0-9], )?(--[A-Za-z0-9][A-Za-z0-9-]*)" flag`)
)

// flagError names the flag but never repeats what was typed: a pipeline's flags can carry
// secrets, and CI logs keep stderr (T-0003 review). It is an allowlist: a message of another
// shape, such as pflag's "bad flag syntax: <argument>", becomes a generic one.
func flagError(_ *cobra.Command, err error) error {
	msg := err.Error()
	switch {
	case safeFlagError.MatchString(msg):
		return err
	case invalidValue.MatchString(msg):
		return fmt.Errorf("invalid value for the %q flag", invalidValue.FindStringSubmatch(msg)[2])
	case shorthandFlag.MatchString(msg):
		m := shorthandFlag.FindStringSubmatch(msg)
		return fmt.Errorf("%s: '%s' (flags take two dashes, as in --var)", m[1], m[2])
	}
	return errors.New("invalid flag syntax (flags take two dashes, as in --var NAME=VALUE)")
}
