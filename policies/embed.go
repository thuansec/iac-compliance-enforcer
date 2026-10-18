// Package policies embeds iace's built-in Rego library and rules and the capabilities file that
// restricts which builtins they may call. Layout mirrors the packages: iace/lib/<name>/ for
// helpers (iace.lib.<name>) and iace/rules/<csp>/<service>/<rule>/ for rules
// (iace.rules.<csp>.<service>.<rule>); each Rego file has a *_test.rego beside it.
package policies

import "embed"

// FS holds every file under iace/, including names that start with _ or . and the tests (the
// engine loads only the other files), and capabilities.json.
//
//go:embed all:iace capabilities.json
var FS embed.FS
