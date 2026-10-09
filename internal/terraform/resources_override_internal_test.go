package terraform

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"
)

// decodeOne parses files, decodes the module's resources and returns them by address.
func decodeOne(t *testing.T, files map[string]string) (*ParsedModule, map[string]Resource) {
	t.Helper()
	m := parseFilesModule(t, files)
	if m.HasErrors() {
		t.Fatalf("diagnostics: %v", m.Diagnostics)
	}
	vars, err := m.EvaluateVariables(context.Background(), m.root, VarOptions{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.DecodeResources(context.Background(), vars, map[string]Local{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Resource{}
	for _, r := range res {
		out[r.Address] = r
	}
	return m, out
}

func attr(t *testing.T, r Resource, name string) cty.Value {
	t.Helper()
	if !r.Value.Type().IsObjectType() || !r.Value.Type().HasAttribute(name) {
		return cty.NilVal
	}
	return r.Value.GetAttr(name)
}

// A weakening override reaches the decoded resource, as Terraform would apply it (threat model
// T14): attributes replace, the rest of the base stays, and the attribute's source is the
// override file. Overrides apply in file name order, in HCL and JSON alike.
func TestResourceOverridesMergeAttributes(t *testing.T) {
	t.Parallel()
	for name, files := range map[string]map[string]string{
		"hcl over hcl": {
			"main.tf":          "resource \"aws_s3_bucket\" \"b\" {\n  acl    = \"private\"\n  bucket = \"logs\"\n}\n",
			"main_override.tf": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
		},
		"json over hcl": {
			"main.tf":               "resource \"aws_s3_bucket\" \"b\" {\n  acl    = \"private\"\n  bucket = \"logs\"\n}\n",
			"main_override.tf.json": `{"resource": {"aws_s3_bucket": {"b": {"acl": "public-read"}}}}`,
		},
		"hcl over json": {
			"main.tf.json":     `{"resource": {"aws_s3_bucket": {"b": {"acl": "private", "bucket": "logs"}}}}`,
			"main_override.tf": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
		},
		"compounding in name order": {
			"main.tf":       "resource \"aws_s3_bucket\" \"b\" {\n  acl    = \"private\"\n  bucket = \"logs\"\n}\n",
			"a_override.tf": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"authenticated-read\"\n}\n",
			"b_override.tf": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, res := decodeOne(t, files)
			r := res["aws_s3_bucket.b"]
			if got := attr(t, r, "acl"); !got.RawEquals(cty.StringVal("public-read")) {
				t.Errorf("acl = %#v, want the override's public-read", got)
			}
			if got := attr(t, r, "bucket"); !got.RawEquals(cty.StringVal("logs")) {
				t.Errorf("bucket = %#v, want the base's", got)
			}
			if got := r.Attributes["acl"].Filename; !strings.Contains(got, "override") {
				t.Errorf("acl is located in %s, want the override file", got)
			}
		})
	}
}

// Nested blocks of a type in an override, static or dynamic, replace all the base's blocks of
// that type; other types stay. A replaced value is not recorded.
func TestResourceOverridesReplaceNestedBlocksByType(t *testing.T) {
	t.Parallel()
	_, res := decodeOne(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "b" {
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "a"
  }
  logging {
    target_bucket = "b"
  }
  dynamic "grant" {
    for_each = [1, 2]
    content {
      id = grant.value
    }
  }
}
`,
		"override.tf": `
resource "aws_s3_bucket" "b" {
  versioning {
    enabled = false
  }
  dynamic "logging" {
    for_each = ["c"]
    content {
      target_bucket = logging.value
    }
  }
  grant {
    id = 3
  }
}
`,
	})
	r := res["aws_s3_bucket.b"]
	want := cty.ObjectVal(map[string]cty.Value{
		"versioning": cty.TupleVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{"enabled": cty.False})}),
		"logging":    cty.TupleVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{"target_bucket": cty.StringVal("c")})}),
		"grant":      cty.TupleVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{"id": cty.NumberIntVal(3)})}),
	})
	if !r.Value.RawEquals(want) {
		t.Errorf("value %#v, want %#v", r.Value, want)
	}
	for path, rng := range r.Attributes {
		if rng.Filename != "override.tf" {
			t.Errorf("%s is recorded from %s, which the override replaced", path, rng.Filename)
		}
	}
}

// Meta-arguments replace one by one: count and each lifecycle argument.
func TestResourceOverridesReplaceMetaArguments(t *testing.T) {
	t.Parallel()
	_, res := decodeOne(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "c" {}
resource "aws_s3_bucket" "b" {
  count      = 1
  depends_on = [aws_s3_bucket.a]
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [tags]
  }
}
`,
		"override.tf": `
resource "aws_s3_bucket" "b" {
  count = 2
  lifecycle {
    ignore_changes = [acl]
  }
}
`,
	})
	r, ok := res["aws_s3_bucket.b[1]"]
	if !ok {
		t.Fatalf("no second instance: the override's count was not applied (%v)", slices.Sorted(maps.Keys(res)))
	}
	if !slices.Equal(r.DependsOn, []string{"aws_s3_bucket.a"}) {
		t.Errorf("depends_on %v, want the base's", r.DependsOn)
	}
	if r.Lifecycle.PreventDestroy == nil || !*r.Lifecycle.PreventDestroy {
		t.Error("prevent_destroy, which the override does not set, was lost")
	}
	if !slices.Equal(r.Lifecycle.IgnoreChanges, []string{"acl"}) {
		t.Errorf("ignore_changes %v, want only the override's", r.Lifecycle.IgnoreChanges)
	}
}

// Data sources merge like resources.
func TestDataOverridesMerge(t *testing.T) {
	t.Parallel()
	_, res := decodeOne(t, map[string]string{
		"main.tf":     "data \"aws_iam_policy_document\" \"p\" {\n  version = \"2012-10-17\"\n}\n",
		"override.tf": "data \"aws_iam_policy_document\" \"p\" {\n  version = \"2008-10-17\"\n}\n",
	})
	if got := attr(t, res["data.aws_iam_policy_document.p"], "version"); !got.RawEquals(cty.StringVal("2008-10-17")) {
		t.Errorf("version = %#v, want the override's", got)
	}
}

// Decoding stays linear in the overrides of one resource: 1 MiB of one-line overrides.
func TestResourceOverridesAreLinear(t *testing.T) {
	block := "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n"
	override := strings.Repeat(block, (1<<20-64)/len(block))
	start := time.Now()
	_, res := decodeOne(t, map[string]string{
		"main.tf":     "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"private\"\n}\n",
		"override.tf": override,
	})
	if got := attr(t, res["aws_s3_bucket.b"], "acl"); !got.RawEquals(cty.StringVal("public-read")) {
		t.Errorf("acl = %#v, want the override's", got)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("decoding %d overrides took %v", strings.Count(override, "\n}\n"), elapsed)
	}
}

// Terraform keeps ignore_changes = all once set, replaces a list only with a non-empty list, and
// does not confuse a top-level argument named ignore_changes with the lifecycle one.
func TestResourceOverridesLifecycleEdges(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		base, override string
		want           []string
	}{
		"all stays all":             {"ignore_changes = all", "lifecycle {\n    ignore_changes = [acl]\n  }", []string{"*"}},
		"empty list keeps the base": {"ignore_changes = [tags]", "lifecycle {\n    ignore_changes = []\n  }", []string{"tags"}},
		"top-level argument":        {"ignore_changes = [tags]", "ignore_changes = 1", []string{"tags"}},
		"two lifecycle blocks":      {"ignore_changes = [tags]", "lifecycle {\n    ignore_changes = [acl]\n  }\n  lifecycle {}", []string{"tags"}},
		"a list replaces a list":    {"ignore_changes = [tags]", "lifecycle {\n    ignore_changes = [acl]\n  }", []string{"acl"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, res := decodeOne(t, map[string]string{
				"main.tf":     "resource \"aws_s3_bucket\" \"b\" {\n  lifecycle {\n    " + tc.base + "\n  }\n}\n",
				"override.tf": "resource \"aws_s3_bucket\" \"b\" {\n  " + tc.override + "\n}\n",
			})
			if got := res["aws_s3_bucket.b"].Lifecycle.IgnoreChanges; !slices.Equal(got, tc.want) {
				t.Errorf("ignore_changes %v, want %v", got, tc.want)
			}
		})
	}
}

// depends_on may not be overridden: Terraform rejects the module, in HCL and JSON alike.
func TestResourceOverrideOfDependsOnIsAnError(t *testing.T) {
	t.Parallel()
	m := parseFilesModule(t, map[string]string{
		"main.tf":            "resource \"aws_s3_bucket\" \"a\" {}\nresource \"aws_s3_bucket\" \"b\" {}\ndata \"aws_caller_identity\" \"c\" {}\n",
		"a_override.tf":      "resource \"aws_s3_bucket\" \"b\" {\n  depends_on = [aws_s3_bucket.a]\n}\n",
		"b_override.tf.json": `{"data": {"aws_caller_identity": {"c": {"depends_on": ["aws_s3_bucket.a"]}}}}`,
	})
	var got []string
	for _, d := range m.Diagnostics {
		if d.Code == DiagOverrideUnsupported {
			got = append(got, d.File)
		}
	}
	if !slices.Equal(got, []string{"a_override.tf", "b_override.tf.json"}) {
		t.Errorf("override_unsupported in %v, want both overrides", got)
	}
}

// JSON dynamic blocks layer like HCL ones: a replaced dynamic block, and the reference in its
// content, leave no trace in Attributes, References or Unknown.
func TestResourceOverridesReplaceJSONDynamicBlocks(t *testing.T) {
	t.Parallel()
	for name, files := range map[string]map[string]string{
		"json dynamic base, hcl override": {
			"main.tf.json": `{"resource": {"aws_s3_bucket": {"b": {"dynamic": {"grant": {"for_each": "${var.ids}", "content": {"id": "${grant.value}"}}}}}}}`,
			"override.tf":  "resource \"aws_s3_bucket\" \"b\" {\n  grant {\n    id = 3\n  }\n}\n",
			"vars.tf":      "variable \"ids\" {}\n",
		},
		"hcl dynamic base, json override": {
			"main.tf":               "resource \"aws_s3_bucket\" \"b\" {\n  dynamic \"grant\" {\n    for_each = var.ids\n    content {\n      id = grant.value\n    }\n  }\n}\n",
			"main_override.tf.json": `{"resource": {"aws_s3_bucket": {"b": {"dynamic": {"grant": {"for_each": [3], "content": {"id": "${grant.value}"}}}}}}}`,
			"vars.tf":               "variable \"ids\" {}\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, res := decodeOne(t, files)
			r := res["aws_s3_bucket.b"]
			want := cty.ObjectVal(map[string]cty.Value{
				"grant": cty.TupleVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{"id": cty.NumberIntVal(3)})}),
			})
			if !r.Value.RawEquals(want) {
				t.Errorf("value %#v, want %#v", r.Value, want)
			}
			if len(r.Unknown) != 0 {
				t.Errorf("unknown paths %v from the replaced dynamic block", r.Unknown)
			}
			for path, rng := range r.Attributes {
				if !strings.Contains(rng.Filename, "override") {
					t.Errorf("%s is recorded from %s, which the override replaced", path, rng.Filename)
				}
			}
			for path, refs := range r.References {
				if slices.Contains(refs, "var.ids") {
					t.Errorf("%s still refers to var.ids, from the replaced dynamic block", path)
				}
			}
		})
	}
}
