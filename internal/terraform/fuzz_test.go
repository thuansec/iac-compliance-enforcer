package terraform

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

// FuzzParseFile feeds arbitrary bytes to the parser as HCL or JSON. Parsing, the nesting guard
// and module-source extraction must never panic or crash, and every diagnostic and block must
// name the file it came from. Seeds are below and in testdata/fuzz/FuzzParseFile.
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
	})
}
