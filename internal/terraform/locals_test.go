package terraform_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// evalLocals parses the root module in "." and evaluates its variables (with opts) and locals.
func evalLocals(t *testing.T, contents map[string]string, opts terraform.VarOptions) (*terraform.ParsedModule, map[string]terraform.Local) {
	t.Helper()
	m, vars, err := evalVars(t, ".", contents, opts)
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatalf("EvaluateLocals: %v", err)
	}
	return m, locals
}

func codes(m *terraform.ParsedModule) []string {
	var out []string
	for _, d := range m.Diagnostics {
		out = append(out, string(d.Code)+"@"+d.File+":"+strconv.Itoa(d.Line))
	}
	return out
}

func paths(ps []cty.Path) []string {
	out := []string{}
	for _, p := range ps {
		var parts []string
		for _, step := range p {
			switch s := step.(type) {
			case cty.GetAttrStep:
				parts = append(parts, s.Name)
			case cty.IndexStep:
				if s.Key.Type() == cty.String {
					parts = append(parts, s.Key.AsString())
				} else {
					parts = append(parts, s.Key.AsBigFloat().String())
				}
			}
		}
		out = append(out, strings.Join(parts, "."))
	}
	return out
}

func TestEvaluateLocalsDependencyOrder(t *testing.T) {
	t.Parallel()
	// Declared out of order and across files and blocks: c needs b, b needs a and a variable.
	m, locals := evalLocals(t, map[string]string{
		"a.tf": `
variable "env" {
  default = "dev"
}
locals {
  c = "${local.b}-c"
}
`,
		"b.tf": `
locals {
  b = "${local.a}-${var.env}"
}
locals {
  a    = "app"
  list = [local.a, local.c]
  obj  = { name = local.c, n = 1 + 2 }
}
`,
	}, terraform.VarOptions{})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", codes(m))
	}
	want := map[string]cty.Value{
		"a":    cty.StringVal("app"),
		"b":    cty.StringVal("app-dev"),
		"c":    cty.StringVal("app-dev-c"),
		"list": cty.TupleVal([]cty.Value{cty.StringVal("app"), cty.StringVal("app-dev-c")}),
		"obj":  cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("app-dev-c"), "n": cty.NumberIntVal(3)}),
	}
	if len(locals) != len(want) {
		t.Fatalf("got %d locals, want %d", len(locals), len(want))
	}
	for name, w := range want {
		l := locals[name]
		if l.Name != name || !l.Value.RawEquals(w) {
			t.Errorf("local.%s = %#v, want %#v", name, l.Value, w)
		}
		if len(l.Unknown) != 0 || len(l.References) != 0 {
			t.Errorf("local.%s: unknown %v, references %v; want none", name, paths(l.Unknown), l.References)
		}
		if l.DeclRange.Filename == "" || l.DeclRange.Start.Line == 0 {
			t.Errorf("local.%s has no declaration range", name)
		}
	}
}

func TestEvaluateLocalsCycles(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"main.tf": `
locals {
  a    = local.b
  b    = [local.c]
  c    = "${local.a}x"
  self = local.self
  # Downstream of the cycle, not in it: evaluated, with the cyclic part unknown.
  down = { x = local.a, y = "known" }
  ok   = "fine"
}
`,
	}, terraform.VarOptions{})
	for _, name := range []string{"a", "b", "c", "self"} {
		l := locals[name]
		if l.Value.IsKnown() {
			t.Errorf("local.%s = %#v, want unknown", name, l.Value)
		}
		if got := paths(l.Unknown); !slices.Equal(got, []string{""}) {
			t.Errorf("local.%s unknown paths = %q, want the whole value", name, got)
		}
	}
	for name, incomplete := range map[string]bool{"a": true, "self": true, "down": true, "ok": false} {
		if got := locals[name].ReferencesIncomplete; got != incomplete {
			t.Errorf("local.%s references incomplete = %v, want %v", name, got, incomplete)
		}
	}
	if got := locals["ok"].Value; !got.RawEquals(cty.StringVal("fine")) {
		t.Errorf("local.ok = %#v", got)
	}
	down := locals["down"]
	if !down.Value.IsKnown() || !down.Value.GetAttr("y").RawEquals(cty.StringVal("known")) {
		t.Errorf("local.down = %#v, want an object with y known", down.Value)
	}
	if got := paths(down.Unknown); !slices.Equal(got, []string{"x"}) {
		t.Errorf("local.down unknown paths = %q, want [x]", got)
	}
	// One warning per local in a cycle, at its name, and nothing else.
	want := []string{"local_cycle@main.tf:3", "local_cycle@main.tf:4", "local_cycle@main.tf:5", "local_cycle@main.tf:6"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	for _, d := range m.Diagnostics {
		if d.Severity != terraform.SeverityWarning {
			t.Errorf("%v: want a warning", d)
		}
	}
}

// TestEvaluateLocalsCycleThroughShortcut: a cycle a -> b -> c -> a with an extra edge a -> c.
// Every member is in the cycle, whichever edge the walk takes first.
func TestEvaluateLocalsCycleThroughShortcut(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"main.tf": `
locals {
  a = [local.c, local.b]
  b = local.c
  c = local.a
}
`,
	}, terraform.VarOptions{})
	for _, name := range []string{"a", "b", "c"} {
		if locals[name].Value.IsKnown() {
			t.Errorf("local.%s is known, want unknown", name)
		}
	}
	if got := len(m.Diagnostics); got != 3 {
		t.Errorf("got %d diagnostics, want 3 cycle warnings: %v", got, codes(m))
	}
}

func TestEvaluateLocalsResourceReferences(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"main.tf": `
locals {
  bucket  = aws_s3_bucket.logs.id
  ami     = data.aws_ami.ubuntu.id
  vpc     = module.network.vpc_id
  eph     = ephemeral.random_password.db.result
  indexed = aws_instance.web[0].id
  mixed   = { arn = aws_s3_bucket.logs.arn, name = "logs" }
  derived = "${local.bucket}/${local.ami}"
  nested  = [local.derived, local.mixed]
  plain   = "x"
}
`,
	}, terraform.VarOptions{})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", codes(m))
	}
	tests := []struct {
		name    string
		refs    []string
		unknown []string
	}{
		{"bucket", []string{"aws_s3_bucket.logs"}, []string{""}},
		{"ami", []string{"data.aws_ami.ubuntu"}, []string{""}},
		{"vpc", []string{"module.network"}, []string{""}},
		{"eph", []string{"ephemeral.random_password.db"}, []string{""}},
		{"indexed", []string{"aws_instance.web"}, []string{""}},
		{"mixed", []string{"aws_s3_bucket.logs"}, []string{"arn"}},
		// References carry through other locals, sorted and without duplicates.
		{"derived", []string{"aws_s3_bucket.logs", "data.aws_ami.ubuntu"}, []string{""}},
		{"nested", []string{"aws_s3_bucket.logs", "data.aws_ami.ubuntu"}, []string{"0", "1.arn"}},
		{"plain", nil, []string{}},
	}
	for _, tt := range tests {
		l := locals[tt.name]
		if diff := cmp.Diff(tt.refs, l.References); diff != "" {
			t.Errorf("local.%s references (-want +got):\n%s", tt.name, diff)
		}
		if diff := cmp.Diff(tt.unknown, paths(l.Unknown)); diff != "" {
			t.Errorf("local.%s unknown paths (-want +got):\n%s", tt.name, diff)
		}
	}
	if got := locals["mixed"].Value.GetAttr("name"); !got.RawEquals(cty.StringVal("logs")) {
		t.Errorf("local.mixed.name = %#v, want the known part kept", got)
	}
}

func TestEvaluateLocalsUnknownVariablesAndSensitivity(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"main.tf": `
variable "unset" {
  type = string
}
variable "password" {
  type      = string
  default   = "fake-password"
  sensitive = true
}
locals {
  from_unset = { a = var.unset, b = "b" }
  conn       = "user:${var.password}"
  via_local  = [local.conn]
  # Evaluation fails (no such variable): unknown, and still sensitive because an input is.
  broken     = "${var.password}${var.missing}"
  broken_via = "${local.conn}${local.nope}"
  # In a cycle: unknown, and still sensitive because an input is.
  cyc_a      = "${var.password}${local.cyc_b}"
  cyc_b      = local.cyc_a
  after_cyc  = local.cyc_b
}
`,
	}, terraform.VarOptions{})
	if got := paths(locals["from_unset"].Unknown); !slices.Equal(got, []string{"a"}) {
		t.Errorf("local.from_unset unknown paths = %q, want [a]", got)
	}
	for _, name := range []string{"conn", "via_local", "broken", "broken_via", "cyc_a", "cyc_b", "after_cyc"} {
		if !locals[name].Value.ContainsMarked() {
			t.Errorf("local.%s is not marked sensitive", name)
		}
	}
	conn, _ := locals["conn"].Value.Unmark()
	if !conn.RawEquals(cty.StringVal("user:fake-password")) {
		t.Errorf("local.conn = %#v", conn)
	}
	if locals["broken"].Value.IsKnown() {
		t.Error("local.broken is known, want unknown")
	}
	want := []string{"evaluation@main.tf:15", "evaluation@main.tf:16", "local_cycle@main.tf:18", "local_cycle@main.tf:19"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	for _, d := range m.Diagnostics {
		if d.Severity != terraform.SeverityWarning || strings.Contains(d.Summary+d.Detail, "fake-password") {
			t.Errorf("%v (%q): want a warning that quotes no value", d, d.Detail)
		}
	}
}

// TestEvaluateLocalsUnsupportedExpressionsAreUnknown: function calls (until the function table
// exists), invalid references and Terraform-only objects are unknown, never errors.
func TestEvaluateLocalsUnsupportedExpressionsAreUnknown(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"main.tf": `
locals {
  fn        = upper("x")
  missing   = local.nope
  workspace = "${terraform.workspace}-x"
  where     = path.module
}
`,
	}, terraform.VarOptions{})
	for name, l := range locals {
		if l.Value.IsKnown() {
			t.Errorf("local.%s = %#v, want unknown", name, l.Value)
		}
	}
	if m.HasErrors() {
		t.Errorf("unknown values must not be errors: %v", codes(m))
	}
}

func TestEvaluateLocalsDuplicates(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"a.tf": "locals {\n  x = 1\n}\n",
		"b.tf": "locals {\n  x = 2\n}\n",
	}, terraform.VarOptions{})
	if got := locals["x"].Value; !got.RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("local.x = %#v, want the first declaration", got)
	}
	want := []string{"duplicate_local@b.tf:2"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	if !m.HasErrors() {
		t.Error("a duplicate local must be an error: Terraform rejects the module")
	}
}

func TestEvaluateLocalsJSON(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{
		"main.tf.json": `{
  "variable": {"env": {"default": "prod"}},
  "locals": {
    "name": "${var.env}-app",
    "full": "${local.name}-${aws_s3_bucket.b.id}",
    "num": 3
  }
}`,
	}, terraform.VarOptions{})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", codes(m))
	}
	if got := locals["name"].Value; !got.RawEquals(cty.StringVal("prod-app")) {
		t.Errorf("local.name = %#v", got)
	}
	if got := locals["full"]; got.Value.IsKnown() || !slices.Equal(got.References, []string{"aws_s3_bucket.b"}) {
		t.Errorf("local.full = %#v, references %v", got.Value, got.References)
	}
	if got := locals["num"].Value; !got.RawEquals(cty.NumberIntVal(3)) {
		t.Errorf("local.num = %#v", got)
	}
}

// TestEvaluateLocalsGuardsDependencyAnalysis: finding a local's references makes hcl parse the
// templates inside .tf.json strings, so it must pass the same guard as evaluation. A template
// over the operator limit is unknown with a warning, and is not analysed at all.
func TestEvaluateLocalsGuardsDependencyAnalysis(t *testing.T) {
	t.Parallel()
	chain := "${aws_s3_bucket.b.id" + strings.Repeat("+1", 1001) + "}"
	m, locals := evalLocals(t, map[string]string{
		"main.tf.json": `{"locals": {"big": "` + chain + `", "user": "${local.big}"}}`,
	}, terraform.VarOptions{})
	big := locals["big"]
	if big.Value.IsKnown() || len(big.References) != 0 {
		t.Errorf("local.big = %#v, references %v; want unknown and not analysed", big.Value, big.References)
	}
	if locals["user"].Value.IsKnown() {
		t.Error("local.user is known, want unknown")
	}
	for _, name := range []string{"big", "user"} {
		if !locals[name].ReferencesIncomplete {
			t.Errorf("local.%s: references not marked incomplete", name)
		}
	}
	want := []string{"expression_too_complex@main.tf.json:1"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestEvaluateLocalsDiagnosticsStaySorted: repeated evaluation adds no duplicates, and the
// diagnostics stay in the documented order.
func TestEvaluateLocalsDiagnosticsStaySorted(t *testing.T) {
	t.Parallel()
	m, vars, err := evalVars(t, ".", map[string]string{
		"b.tf": "locals {\n  y = local.y\n}\n",
		"a.tf": "locals {\n  x = upper(\"x\")\n}\n",
	}, terraform.VarOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := m.EvaluateLocals(context.Background(), vars); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"evaluation@a.tf:2", "local_cycle@b.tf:2"}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestEvaluateLocalsLongChain: dependency analysis does not recurse per local, so a long chain
// of locals is evaluated without exhausting the stack, whichever end is declared first.
func TestEvaluateLocalsLongChain(t *testing.T) {
	t.Parallel()
	const n = 20000
	for _, reversed := range []bool{false, true} {
		var b strings.Builder
		b.WriteString("locals {\n")
		for i := range n {
			j := i
			if reversed {
				j = n - 1 - i
			}
			if j == 0 {
				b.WriteString("  l0 = 0\n")
				continue
			}
			b.WriteString("  l" + strconv.Itoa(j) + " = local.l" + strconv.Itoa(j-1) + "\n")
		}
		b.WriteString("}\n")
		m, locals := evalLocals(t, map[string]string{"main.tf": b.String()}, terraform.VarOptions{})
		if len(m.Diagnostics) != 0 {
			t.Errorf("reversed=%v: diagnostics: %v", reversed, codes(m))
		}
		if got := locals["l"+strconv.Itoa(n-1)].Value; !got.RawEquals(cty.NumberIntVal(0)) {
			t.Errorf("reversed=%v: last local = %#v, want 0", reversed, got)
		}
	}
}

func TestEvaluateLocalsHonoursCancellation(t *testing.T) {
	t.Parallel()
	m, vars, err := evalVars(t, ".", map[string]string{"main.tf": "locals {\n  a = 1\n}\n"}, terraform.VarOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.EvaluateLocals(ctx, vars); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// chain builds one locals block of n locals, l0 = first and lN = step(N) for N > 0.
func chain(n int, first string, step func(i int) string) map[string]string {
	var b strings.Builder
	b.WriteString("locals {\n  l0 = " + first + "\n")
	for i := 1; i < n; i++ {
		b.WriteString("  l" + strconv.Itoa(i) + " = " + step(i) + "\n")
	}
	b.WriteString("}\n")
	return map[string]string{"main.tf": b.String()}
}

func prev(i int) string { return "local.l" + strconv.Itoa(i-1) }

// TestEvaluateLocalsValuesThatDouble: each local uses the previous one twice, so values would
// double per local. Once a value passes the size limit it is unknown with a warning, and the
// locals after it stay small; nothing hangs or exhausts memory.
func TestEvaluateLocalsValuesThatDouble(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		first     string
		step      func(i int) string
		lastKnown int // the last local still known
		warnings  []string
	}{
		// Size 3*2^k - 1 nodes: l16 fits in 2^18, l17 does not.
		{
			"tuples", "[aws_s3_bucket.x.id]", func(i int) string { return "[" + prev(i) + ", " + prev(i) + "]" }, 16,
			// From the unknown l17 the values double again; l34 passes the limit too (by the estimate).
			[]string{"value_too_large@main.tf:19", "value_too_large@main.tf:36"},
		},
		// 2^(k+1) bytes: l16 is 128 KiB, l17 would pass the limit.
		{
			"strings", `"ab"`, func(i int) string { return `"${` + prev(i) + `}${` + prev(i) + `}"` }, 16,
			// Strings over an unknown string stay unknown.
			[]string{"value_too_large@main.tf:19"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, locals := evalLocals(t, chain(40, tt.first, tt.step), terraform.VarOptions{})
			last := locals["l"+strconv.Itoa(tt.lastKnown)]
			if !last.Value.IsKnown() {
				t.Errorf("l%d is unknown, want known", tt.lastKnown)
			}
			if next := locals["l"+strconv.Itoa(tt.lastKnown+1)]; next.Value.IsKnown() || len(next.References) != len(last.References) {
				t.Errorf("l%d = known %v, references %v; want unknown with l%d's references", tt.lastKnown+1, next.Value.IsKnown(), next.References, tt.lastKnown)
			}
			if diff := cmp.Diff(tt.warnings, codes(m)); diff != "" {
				t.Errorf("diagnostics (-want +got):\n%s", diff)
			}
		})
	}
	// 2^16 unknown leaves are more paths than recorded: the whole value is reported instead.
	_, locals := evalLocals(t, chain(17, "[aws_s3_bucket.x.id]", func(i int) string { return "[" + prev(i) + ", " + prev(i) + "]" }), terraform.VarOptions{})
	if got := paths(locals["l16"].Unknown); !slices.Equal(got, []string{""}) {
		t.Errorf("l16 unknown paths: got %d, want the whole value", len(got))
	}
}

// TestEvaluateLocalsDeepValues: each local nests the previous one a level deeper. A value
// deeper than the nesting limit is unknown, and the chain continues from there.
func TestEvaluateLocalsDeepValues(t *testing.T) {
	t.Parallel()
	const n = 20000
	m, locals := evalLocals(t, chain(n, "[aws_s3_bucket.r0.id]", func(i int) string {
		return "[" + prev(i) + ", aws_s3_bucket.r" + strconv.Itoa(i) + ".id]"
	}), terraform.VarOptions{})
	// l_k's leaves are k+1 levels below its top; the limit is 512 levels. From the unknown l512
	// the depth grows again, so every 513th local passes the limit.
	if !locals["l511"].Value.IsKnown() || locals["l512"].Value.IsKnown() {
		t.Errorf("l511 known %v, l512 known %v; want the limit between them", locals["l511"].Value.IsKnown(), locals["l512"].Value.IsKnown())
	}
	deep, together := 0, 0
	for _, d := range m.Diagnostics {
		switch {
		case d.Code == terraform.DiagValueTooLarge && strings.HasSuffix(d.Summary, "together"):
			together++
		case d.Code == terraform.DiagValueTooLarge:
			deep++
		}
	}
	// The values of all locals together also pass maxLocalsSize: one warning, not one per local.
	if deep < 2 || deep > n/513 || together != 1 {
		t.Errorf("got %d nesting and %d total warnings, want at most %d and exactly 1", deep, together, n/513)
	}
}

// TestEvaluateLocalsManyReferences: references carried through a long chain of locals would
// grow quadratically. Past the reference limit, locals keep only their own references and are
// marked incomplete, with one warning.
func TestEvaluateLocalsManyReferences(t *testing.T) {
	t.Parallel()
	const n = 20000
	m, locals := evalLocals(t, chain(n, `"${aws_s3_bucket.r0.id}"`, func(i int) string {
		return `"${` + prev(i) + `}${aws_s3_bucket.r` + strconv.Itoa(i) + `.id}"`
	}), terraform.VarOptions{})
	if l := locals["l100"]; len(l.References) != 101 || l.ReferencesIncomplete {
		t.Errorf("l100: %d references, incomplete %v; want 101, complete", len(l.References), l.ReferencesIncomplete)
	}
	last := locals["l"+strconv.Itoa(n-1)]
	if !last.ReferencesIncomplete || !slices.Contains(last.References, "aws_s3_bucket.r"+strconv.Itoa(n-1)) {
		t.Errorf("last local: incomplete %v, %d references; want incomplete with its own reference", last.ReferencesIncomplete, len(last.References))
	}
	total := 0
	for _, l := range locals {
		total += len(l.References)
	}
	if total > 1<<17+n {
		t.Errorf("stored %d references, want at most the limit plus one per local", total)
	}
	var got []string
	for _, c := range codes(m) {
		if !strings.HasPrefix(c, "value_too_large@") {
			got = append(got, strings.SplitN(c, "@", 2)[0])
		}
	}
	if diff := cmp.Diff([]string{"references_incomplete"}, got); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestEvaluateLocalsManyUsesOfALargeValue: thousands of locals each using one large value cost
// no more than the size limits allow: once the locals together are full, the rest are unknown.
func TestEvaluateLocalsManyUsesOfALargeValue(t *testing.T) {
	t.Parallel()
	const n = 20000
	big := `"` + strings.Repeat("x", 100000) + `"`
	m, locals := evalLocals(t, chain(n, big, func(int) string { return "local.l0" }), terraform.VarOptions{})
	if !locals["l1"].Value.IsKnown() || locals["l"+strconv.Itoa(n-1)].Value.IsKnown() {
		t.Errorf("l1 known %v, last known %v; want the first copies known and the rest unknown",
			locals["l1"].Value.IsKnown(), locals["l"+strconv.Itoa(n-1)].Value.IsKnown())
	}
	if got := len(m.Diagnostics); got != 1 {
		t.Errorf("got %d diagnostics, want one total-size warning: %v", got, codes(m)[:min(got, 5)])
	}
}
