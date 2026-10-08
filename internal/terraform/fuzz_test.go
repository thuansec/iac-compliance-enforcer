package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// FuzzParseFile feeds arbitrary bytes to the parser as HCL or JSON. Parsing, the nesting guard,
// module-source extraction, guarded evaluation, locals evaluation and resource decoding must
// never panic or crash, and every diagnostic and block must name the file it came from. Seeds
// are below and in testdata/fuzz/FuzzParseFile.
func FuzzParseFile(f *testing.F) {
	seeds := []struct {
		src    string
		isJSON bool
	}{
		{"resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"example\"\n  tags = { env = var.env }\n}\n", false},
		{"module \"net\" {\n  source = \"./net\"\n  count  = length(var.azs)\n}\n", false},
		{"locals {\n  a = [for x in var.l : upper(x) if x != \"\"]\n  b = { for k, v in var.m : k => v... }\n}\n", false},
		{"variable \"v\" {\n  default = <<-EOT\n    ${var.x} %{ if true }y%{ endif }\n  EOT\n}\n", false},
		{"output \"o\" {\n  value = aws_instance.web[*].id\n  sensitive = !false ? true : -1 > 0\n}\n", false},
		{"resource \"a\" \"b\" {\n  dynamic \"ingress\" {\n    for_each = var.ports\n    content { from_port = ingress.value }\n  }\n}\n", false},
		{"resource \"x\" {\n", false},
		{"a = " + strings.Repeat("[", 600) + strings.Repeat("]", 600) + "\n", false},
		{`{"resource": {"aws_s3_bucket": {"b": {"bucket": "example"}}}, "//": "c"}`, true},
		{`{"module": {"net": {"source": "./net"}}, "variable": {"v": [{"default": 1}]}}`, true},
		{`{"a": ` + strings.Repeat("[", 600) + strings.Repeat("]", 600) + `}`, true},
		{`{"unterminated": `, true},
		{`{"resource": {"x": {"y": {"count": 2, "provider": "a.b", "depends_on": ["x.z"], "a": "${count.index}", "b": {"c": [1]}, "lifecycle": {"ignore_changes": "all"}, "dynamic": {"d": {"for_each": [1], "content": {}}}}}}}`, true},
		{"locals {\n  a = local.b\n  b = [local.a, aws_s3_bucket.x.id]\n  c = \"${local.a}-${data.d.e.f}\"\n}\n", false},
		{`{"locals": {"a": "${local.b}", "b": "${module.m.o}", "c": {"k": "${local.a}"}}}`, true},
		{"locals {\n  a = formatlist(\"%5s\", distinct(concat(split(\",\", \"a,b\"), [jsonencode({ k = 1 })])))\n  b = try(provider::aws::f(local.a), timestamp(), core::upper(\"x\"))\n}\n", false},
		{`{"locals": {"a": "${format(\"%d\", max(1, 2))}", "b": "${uuid()}"}}`, true},
		{"resource \"x\" \"d\" {\n  dynamic \"a\" {\n    for_each = { k = [1, 2] }\n    iterator = it\n    content {\n      dynamic \"b\" {\n        for_each = it.value\n        content { v = b.value }\n      }\n    }\n  }\n  dynamic \"c\" {\n    for_each = x.y\n    content {}\n  }\n  dynamic {}\n}\n", false},
		{"resource \"x\" \"c\" {\n  count = 3\n  a = count.index\n}\nresource \"x\" \"f\" {\n  for_each = { k = [1] }\n  b = each.value[0]\n}\nresource \"x\" \"u\" {\n  for_each = toset([x.c[0].id])\n  count = -1\n}\n", false},
		{"resource \"x\" \"y\" {\n  provider = a.b.c\n  depends_on = [\"s\", var.x, x.y[0]]\n  dup = 1\n  dup {}\n  lifecycle {\n    ignore_changes = [a[\"b\"][0], all]\n    prevent_destroy = 1\n  }\n  n { m { k = path.module } }\n}\n", false},
	}
	for _, s := range seeds {
		f.Add([]byte(s.src), s.isJSON)
	}
	f.Fuzz(func(t *testing.T, data []byte, isJSON bool) {
		name := "fuzz/main.tf"
		if isJSON {
			name += ".json"
		}
		m := &ParsedModule{Dir: "fuzz"}
		m.parseFile(hclparse.NewParser(), name, data)
		for _, d := range m.Diagnostics {
			if d.File != name || d.Line < 0 || d.Column < 0 || d.Summary == "" {
				t.Errorf("bad diagnostic %+v", d)
			}
		}
		for _, b := range m.Blocks {
			if b.File != name || b.Range.Filename != name {
				t.Errorf("block %s %v does not name %s", b.Type, b.Labels, name)
			}
		}
		_ = moduleSources(name, data)
		// Evaluate every block's attributes through the guard, with a context so that JSON
		// strings are parsed as templates too.
		ctx := &hcl.EvalContext{}
		for _, b := range m.Blocks {
			attrs, _ := b.Body.JustAttributes()
			for _, a := range attrs {
				_, _ = m.evalExpr(a.Expr, ctx)
			}
		}
		locals, err := m.EvaluateLocals(context.Background(), nil)
		if err != nil {
			t.Fatalf("EvaluateLocals: %v", err)
		}
		for name, l := range locals {
			if l.Value.Type() == cty.NilType {
				t.Errorf("local.%s has no value", name)
			}
		}
		res, err := m.DecodeResources(context.Background(), nil, locals)
		if err != nil {
			t.Fatalf("DecodeResources: %v", err)
		}
		for _, r := range res {
			if r.Value.Type() == cty.NilType || r.File != name {
				t.Errorf("resource %s has no value or names %q", r.Address, r.File)
			}
		}
	})
}
