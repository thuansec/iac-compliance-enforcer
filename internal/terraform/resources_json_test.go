package terraform_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

func TestDecodeJSONResources(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"vars.tf": `variable "env" {
  default = "prod"
}

variable "pw" {
  default   = "hunter2"
  sensitive = true
}
`,
		"main.tf.json": `{
  "//": "generated",
  "resource": {
    "aws_instance": {
      "web": {
        "//": "a comment, not an attribute",
        "count": 2,
        "provider": "aws.eu",
        "depends_on": ["aws_iam_role.r", "data.aws_ami.x"],
        "ami": "ami-0123456789abcdef0",
        "name": "web-${var.env}-${count.index}",
        "subnet_id": "${aws_subnet.a.id}",
        "password": "${var.pw}",
        "tags": {"Name": "web", "Env": "${var.env}"},
        "metadata_options": {"http_tokens": "required"},
        "ebs_block_device": [{"device_name": "/dev/sdb", "encrypted": true}],
        "lifecycle": {"prevent_destroy": true, "ignore_changes": ["tags", "ami"]},
        "provisioner": {"local-exec": {"command": "echo"}},
        "connection": {"host": "${self.id}"}
      }
    }
  },
  "data": {
    "aws_ami": {
      "x": {"most_recent": true}
    }
  }
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	if diff := cmp.Diff([]string{"aws_instance.web[0]", "aws_instance.web[1]", "data.aws_ami.x"}, addresses(res)); diff != "" {
		t.Fatalf("addresses (-want +got):\n%s", diff)
	}
	web := resource(t, res, "aws_instance.web[1]")
	if web.ProviderConfig != "aws.eu" || web.File != "main.tf.json" {
		t.Errorf("provider %q, file %q", web.ProviderConfig, web.File)
	}
	if diff := cmp.Diff([]string{"aws_iam_role.r", "data.aws_ami.x"}, web.DependsOn); diff != "" {
		t.Errorf("depends_on (-want +got):\n%s", diff)
	}
	if web.Lifecycle.PreventDestroy == nil || !*web.Lifecycle.PreventDestroy {
		t.Errorf("prevent_destroy = %v", web.Lifecycle.PreventDestroy)
	}
	if diff := cmp.Diff([]string{"tags", "ami"}, web.Lifecycle.IgnoreChanges); diff != "" {
		t.Errorf("ignore_changes (-want +got):\n%s", diff)
	}
	for _, meta := range []string{"//", "count", "provider", "depends_on", "lifecycle", "provisioner", "connection"} {
		if web.Value.Type().HasAttribute(meta) {
			t.Errorf("value has %q", meta)
		}
	}
	// Properties keep the shape they are written in (ADR 0006): a nested block written as one
	// object is an object, written as an array it is an array of objects.
	for path, want := range map[string]cty.Value{
		"ami":                            cty.StringVal("ami-0123456789abcdef0"),
		"name":                           cty.StringVal("web-prod-1"),
		"tags.Env":                       cty.StringVal("prod"),
		"metadata_options.http_tokens":   cty.StringVal("required"),
		"ebs_block_device.0.device_name": cty.StringVal("/dev/sdb"),
		"ebs_block_device.0.encrypted":   cty.True,
	} {
		if got := attr(t, web.Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
	if pw := attr(t, web.Value, "password"); !pw.HasMark(terraform.SensitiveMark) {
		t.Errorf("password = %#v, want sensitive", pw)
	}
	if diff := cmp.Diff([]string{"subnet_id"}, paths(web.Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}
	if r := web.Attributes["ami"]; r.Filename != "main.tf.json" || r.Start.Line != 10 {
		t.Errorf("ami range %v, want main.tf.json line 10", r)
	}
	if _, ok := web.Attributes["metadata_options"]; !ok {
		t.Errorf("attribute ranges %v lack metadata_options", web.Attributes)
	}
	if d := resource(t, res, "data.aws_ami.x"); !attr(t, d.Value, "most_recent").True() {
		t.Errorf("data.aws_ami.x = %#v", d.Value)
	}
}

// TestDecodeJSONResourcesFailClosed: what iace cannot decode in JSON is unknown with a warning.
func TestDecodeJSONResourcesFailClosed(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf.json": `{
  "resource": {
    "x": {
      "dyn": {
        "name": "n",
        "dynamic": {"ingress": {"for_each": [1], "content": {"port": "${ingress.value}"}}}
      },
      "unknown_count": {
        "count": "${var.missing}"
      },
      "bad_lifecycle": {
        "lifecycle": [{"prevent_destroy": true}, {"prevent_destroy": false}],
        "a": 1
      },
      "err": {
        "a": "${upper(1, 2)}",
        "b": 2
      }
    }
  }
}
`,
	})
	dyn := resource(t, res, "x.dyn")
	// JSON dynamic blocks expand (T-0106e).
	if len(dyn.Unknown) != 0 || !attr(t, dyn.Value, "ingress.0.port").RawEquals(cty.NumberIntVal(1)) {
		t.Errorf("x.dyn = %#v, unknown %v", dyn.Value, paths(dyn.Unknown))
	}
	if got := attr(t, dyn.Value, "name"); !got.RawEquals(cty.StringVal("n")) {
		t.Errorf("x.dyn.name = %#v", got)
	}
	if bad := resource(t, res, "x.bad_lifecycle"); !bad.Value.IsKnown() || bad.Lifecycle.PreventDestroy != nil {
		t.Errorf("x.bad_lifecycle = %#v, prevent_destroy %v", bad.Value, bad.Lifecycle.PreventDestroy)
	}
	if err := resource(t, res, "x.err"); len(err.Unknown) != 1 || !attr(t, err.Value, "b").RawEquals(cty.NumberIntVal(2)) {
		t.Errorf("x.err = %#v, unknown %v", err.Value, paths(err.Unknown))
	}
	if r := resource(t, res, "x.unknown_count[*]"); !r.CountUnknown {
		t.Errorf("x.unknown_count = %+v", r)
	}
	got := strings.Join(codes(m), " ")
	for _, want := range []string{"evaluation@main.tf.json:9", "evaluation@main.tf.json:12", "evaluation@main.tf.json:16"} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics %s lack %s", got, want)
		}
	}
}

// TestDuplicateLifecycle: Terraform rejects a second lifecycle block, so its settings are all
// ignored with a warning, in HCL as in JSON.
func TestDuplicateLifecycle(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf": `resource "x" "y" {
  lifecycle {
    prevent_destroy = true
  }
  lifecycle {
    ignore_changes = all
  }
}
`})
	if r := res[0]; r.Lifecycle.PreventDestroy != nil || len(r.Lifecycle.IgnoreChanges) != 0 {
		t.Errorf("lifecycle = %+v, want ignored", r.Lifecycle)
	}
	if diff := cmp.Diff([]string{"evaluation@main.tf:5"}, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestJSONResourceInvalidShape: a meta-argument block that is not an object makes the resource
// wholly unknown with a warning, as Terraform would reject it.
func TestJSONResourceInvalidShape(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{"main.tf.json": `{
  "resource": {
    "x": {
      "y": {
        "a": 1,
        "dynamic": "oops"
      }
    }
  }
}
`})
	if r := res[0]; r.Value.IsKnown() || len(r.Unknown) != 1 || len(r.Unknown[0]) != 0 {
		t.Errorf("x.y = %#v, unknown %v; want wholly unknown", r.Value, paths(r.Unknown))
	}
	if got := codes(m); len(got) != 1 || !strings.HasPrefix(got[0], "evaluation@main.tf.json:") {
		t.Errorf("diagnostics %v, want one evaluation warning", got)
	}
}

// TestJSONNestedDynamicExpands: a property holding a dynamic block can only be a nested block,
// so it is decoded as blocks and the dynamic block expands; a string "dynamic" stays data.
func TestJSONNestedDynamicExpands(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"vars.tf": "variable \"pw\" {\n  default   = \"hunter2\"\n  sensitive = true\n}\n",
		"main.tf.json": `{
  "resource": {
    "x": {
      "y": {
        "name": "n",
        "setting": {"dynamic": {"ingress": {"for_each": [1], "content": {"port": 22}}}},
        "list": [{"a": 1}, {"dynamic": [{"b": {"for_each": [], "content": {}}}]}],
        "secret": {"p": "${var.pw}", "dynamic": {"c": {"for_each": [1], "content": {}}}},
        "plain": {"dynamic": "a string is data"},
        "lifecycle": [1]
      }
    }
  }
}
`,
	})
	y := res[0]
	if len(y.Unknown) != 0 {
		t.Errorf("unknown: %v", paths(y.Unknown))
	}
	for path, want := range map[string]cty.Value{
		"setting.0.ingress.0.port": cty.NumberIntVal(22),
		"list.0.a":                 cty.NumberIntVal(1),
		"secret.0.c.0":             cty.EmptyObjectVal,
		"plain.dynamic":            cty.StringVal("a string is data"),
	} {
		if got := attr(t, y.Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
	if n := attr(t, y.Value, "list").LengthInt(); n != 2 {
		t.Errorf("list has %d entries, want 2", n)
	}
	if p := attr(t, y.Value, "secret.0.p"); !p.HasMark(terraform.SensitiveMark) {
		t.Errorf("secret.0.p = %#v, want sensitive", p)
	}
	if diff := cmp.Diff([]string{"evaluation@main.tf.json:10"}, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}
