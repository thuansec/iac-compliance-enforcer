package terraform_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty/cty"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// decodeResources parses the root module in "." and decodes its resources after evaluating
// its variables and locals.
func decodeResources(t *testing.T, contents map[string]string) (*terraform.ParsedModule, []terraform.Resource) {
	t.Helper()
	m, vars, err := evalVars(t, ".", contents, terraform.VarOptions{})
	if err != nil {
		t.Fatalf("EvaluateVariables: %v", err)
	}
	locals, err := m.EvaluateLocals(context.Background(), vars)
	if err != nil {
		t.Fatalf("EvaluateLocals: %v", err)
	}
	res, err := m.DecodeResources(context.Background(), vars, locals)
	if err != nil {
		t.Fatalf("DecodeResources: %v", err)
	}
	return m, res
}

// resource returns the resource with address addr.
func resource(t *testing.T, res []terraform.Resource, addr string) terraform.Resource {
	t.Helper()
	i := slices.IndexFunc(res, func(r terraform.Resource) bool { return r.Address == addr })
	if i < 0 {
		var got []string
		for _, r := range res {
			got = append(got, r.Address)
		}
		t.Fatalf("no resource %s in %v", addr, got)
	}
	return res[i]
}

// attr returns the value at the dot-separated path in v ("ingress.0.port").
func attr(t *testing.T, v cty.Value, path string) cty.Value {
	t.Helper()
	for _, step := range strings.Split(path, ".") {
		v, _ = v.Unmark()
		if !v.IsKnown() {
			t.Fatalf("%s: unknown before %q", path, step)
		}
		var i int
		if _, err := fmt.Sscanf(step, "%d", &i); err == nil && (v.Type().IsTupleType() || v.Type().IsListType()) {
			v = v.Index(cty.NumberIntVal(int64(i)))
			continue
		}
		if !v.Type().IsObjectType() || !v.Type().HasAttribute(step) {
			t.Fatalf("%s: no attribute %q in %#v", path, step, v)
		}
		v = v.GetAttr(step)
	}
	return v
}

func TestDecodeResources(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "env" {
  default = "prod"
}

locals {
  name = "web-${var.env}"
}

resource "aws_instance" "web" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.a.id
  tags          = { Name = local.name }

  metadata_options {
    http_tokens = "optional"
  }

  ebs_block_device {
    device_name = "/dev/sdb"
    encrypted   = true
  }
  ebs_block_device {
    device_name = "/dev/sdc"
    encrypted   = false
  }

  root_block_device {
    tag {
      key = path.module
    }
  }
}
`,
		"data.tf": `data "aws_ami" "x" {
  most_recent = true
  owners      = ["amazon"]
}

ephemeral "aws_secret" "s" {
  id = "x"
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	var addrs []string
	for _, r := range res {
		addrs = append(addrs, r.Address)
	}
	// File order (data.tf before main.tf), then source order; ephemeral resources are not decoded.
	if diff := cmp.Diff([]string{"data.aws_ami.x", "aws_instance.web"}, addrs); diff != "" {
		t.Errorf("addresses (-want +got):\n%s", diff)
	}
	data := resource(t, res, "data.aws_ami.x")
	if data.Mode != model.ModeData || data.Type != "aws_ami" || data.Name != "x" || data.File != "data.tf" {
		t.Errorf("data source = %+v", data)
	}

	web := resource(t, res, "aws_instance.web")
	if web.Mode != model.ModeManaged || web.Type != "aws_instance" || web.Name != "web" || web.File != "main.tf" {
		t.Errorf("resource = %+v", web)
	}
	if web.DefRange.Start.Line != 9 || web.Range.End.Line != 33 {
		t.Errorf("ranges: def %v, block %v", web.DefRange, web.Range)
	}
	for path, want := range map[string]cty.Value{
		"ami":                            cty.StringVal("ami-0123456789abcdef0"),
		"tags.Name":                      cty.StringVal("web-prod"),
		"metadata_options.0.http_tokens": cty.StringVal("optional"),
		"ebs_block_device.0.device_name": cty.StringVal("/dev/sdb"),
		"ebs_block_device.1.encrypted":   cty.False,
		"root_block_device.0.tag.0.key":  cty.StringVal("."),
	} {
		if got := attr(t, web.Value, path); !got.RawEquals(want) {
			t.Errorf("%s = %#v, want %#v", path, got, want)
		}
	}
	if n := attr(t, web.Value, "ebs_block_device").LengthInt(); n != 2 {
		t.Errorf("ebs_block_device has %d entries, want 2", n)
	}
	if diff := cmp.Diff([]string{"subnet_id"}, paths(web.Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}
	wantAttrs := []string{
		"ami", "ebs_block_device.0.device_name", "ebs_block_device.0.encrypted",
		"ebs_block_device.1.device_name", "ebs_block_device.1.encrypted", "instance_type",
		"metadata_options.0.http_tokens", "root_block_device.0.tag.0.key", "subnet_id", "tags",
	}
	var gotAttrs []string
	for k := range web.Attributes {
		gotAttrs = append(gotAttrs, k)
	}
	slices.Sort(gotAttrs)
	if diff := cmp.Diff(wantAttrs, gotAttrs); diff != "" {
		t.Errorf("attribute ranges (-want +got):\n%s", diff)
	}
	if r := web.Attributes["metadata_options.0.http_tokens"]; r.Start.Line != 16 || r.Start.Column != 19 {
		t.Errorf("http_tokens range = %v, want the expression at 16:19", r)
	}
}

func TestDecodeResourceMetaArguments(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "b" {
  count      = 2
  provider   = aws.eu
  depends_on = [module.m, aws_iam_role.r, data.aws_ami.x.id, aws_iam_role.r]
  bucket     = "logs-${count.index}"

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [tags["Name"], acl]
  }

  provisioner "local-exec" {
    command = "echo"
  }

  connection {
    host = self.id
  }

  settings {
    count    = 3
    provider = "x"
  }
}

resource "aws_s3_bucket" "c" {
  for_each = toset(["a"])
  bucket   = each.key

  lifecycle {
    ignore_changes = all
  }
}
`,
	})
	if len(m.Diagnostics) != 0 {
		t.Errorf("diagnostics: %v", m.Diagnostics)
	}
	b := resource(t, res, "aws_s3_bucket.b[1]")
	for _, meta := range []string{"count", "provider", "depends_on", "lifecycle", "provisioner", "connection"} {
		if b.Value.Type().HasAttribute(meta) {
			t.Errorf("value has meta-argument %q", meta)
		}
	}
	if b.ProviderConfig != "aws.eu" || b.Count == nil || b.ForEach != nil {
		t.Errorf("provider %q, count %v, for_each %v", b.ProviderConfig, b.Count, b.ForEach)
	}
	if diff := cmp.Diff([]string{"aws_iam_role.r", "data.aws_ami.x", "module.m"}, b.DependsOn); diff != "" {
		t.Errorf("depends_on (-want +got):\n%s", diff)
	}
	if b.Lifecycle.PreventDestroy == nil || !*b.Lifecycle.PreventDestroy {
		t.Errorf("prevent_destroy = %v", b.Lifecycle.PreventDestroy)
	}
	if diff := cmp.Diff([]string{"tags.Name", "acl"}, b.Lifecycle.IgnoreChanges); diff != "" {
		t.Errorf("ignore_changes (-want +got):\n%s", diff)
	}
	// Meta-argument names are plain attributes in nested blocks.
	if got := attr(t, b.Value, "settings.0.count"); !got.RawEquals(cty.NumberIntVal(3)) {
		t.Errorf("settings.0.count = %#v", got)
	}
	// Every instance records the meta-arguments, and count.index is set.
	if got := attr(t, b.Value, "bucket"); !got.RawEquals(cty.StringVal("logs-1")) {
		t.Errorf("bucket = %#v", got)
	}
	if b0 := resource(t, res, "aws_s3_bucket.b[0]"); b0.ProviderConfig != "aws.eu" || len(b0.DependsOn) != 3 {
		t.Errorf("aws_s3_bucket.b[0] = %+v", b0)
	}

	c := resource(t, res, `aws_s3_bucket.c["a"]`)
	if c.ForEach == nil || c.Count != nil || c.ProviderConfig != "" || len(c.DependsOn) != 0 || c.Lifecycle.PreventDestroy != nil {
		t.Errorf("c = %+v", c)
	}
	if diff := cmp.Diff([]string{"*"}, c.Lifecycle.IgnoreChanges); diff != "" {
		t.Errorf("ignore_changes = all (-want +got):\n%s", diff)
	}
}

// TestDecodeResourcesFailClosed: what iace cannot decode yet is unknown with a warning.
func TestDecodeResourcesFailClosed(t *testing.T) {
	t.Parallel()
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "pw" {
  default   = "hunter2"
  sensitive = true
}

resource "aws_security_group" "sg" {
  name = "sg"

  ingress {
    from_port = 22
  }

  dynamic "ingress" {
    for_each = [1]
    content {
      from_port = ingress.value
    }
  }

  dynamic "egress" {
    for_each = [1]
    content {
      from_port = 1
    }
  }
}

resource "aws_db_instance" "db" {
  password    = var.pw
  engine      = upper(1, 2)
  description = tostring(var.missing)
}
`,
		"json.tf.json": `{"resource": {"aws_s3_bucket": {"j": {"bucket": "x"}}}}`,
	})
	sg := resource(t, res, "aws_security_group.sg")
	if diff := cmp.Diff([]string{"egress", "ingress"}, paths(sg.Unknown)); diff != "" {
		t.Errorf("dynamic blocks unknown (-want +got):\n%s", diff)
	}
	if got := attr(t, sg.Value, "name"); !got.RawEquals(cty.StringVal("sg")) {
		t.Errorf("name = %#v", got)
	}

	db := resource(t, res, "aws_db_instance.db")
	if pw := attr(t, db.Value, "password"); !pw.HasMark(terraform.SensitiveMark) {
		t.Errorf("password = %#v, want sensitive", pw)
	}
	if diff := cmp.Diff([]string{"description", "engine"}, paths(db.Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}

	j := resource(t, res, "aws_s3_bucket.j")
	if j.Value.IsKnown() || len(j.Unknown) != 1 || len(j.Unknown[0]) != 0 || j.File != "json.tf.json" {
		t.Errorf("JSON resource = %#v, unknown %v; want wholly unknown", j.Value, j.Unknown)
	}

	want := []string{
		"json_body_not_decoded@json.tf.json:1",
		"dynamic_block_not_expanded@main.tf:13",
		"dynamic_block_not_expanded@main.tf:20",
		"evaluation@main.tf:30",
		"evaluation@main.tf:31",
	}
	if diff := cmp.Diff(want, codes(m)); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
	for _, d := range m.Diagnostics {
		if d.Severity != terraform.SeverityWarning || strings.Contains(d.Summary+d.Detail, "hunter2") {
			t.Errorf("diagnostic %v: want a warning that never quotes values", d)
		}
	}
}

// TestDecodeResourcesSizeLimits: an attribute over the value limit, and attributes past the
// module's total, are unknown with one warning each.
func TestDecodeResourcesSizeLimits(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("variable \"s\" {\n  default = \"" + strings.Repeat("x", 200_000) + "\"\n}\n\n")
	b.WriteString("resource \"x\" \"big\" {\n  a = \"${var.s}${var.s}\"\n  b = \"small\"\n}\n\n")
	for i := range 100 {
		fmt.Fprintf(&b, "resource \"x\" \"r%03d\" {\n  a = var.s\n}\n\n", i)
	}
	m, res := decodeResources(t, map[string]string{"main.tf": b.String()})

	big := resource(t, res, "x.big")
	if diff := cmp.Diff([]string{"a"}, paths(big.Unknown)); diff != "" {
		t.Errorf("x.big unknown (-want +got):\n%s", diff)
	}
	if got := attr(t, big.Value, "b"); !got.RawEquals(cty.StringVal("small")) {
		t.Errorf("x.big.b = %#v", got)
	}
	// 2^22 units hold 20 copies of the 200,001-unit string.
	known := 0
	for _, r := range res[1:] {
		if attr(t, r.Value, "a").IsKnown() {
			known++
		}
	}
	if known != 20 {
		t.Errorf("%d resources keep var.s, want 20", known)
	}
	var tooLarge []string
	for _, c := range codes(m) {
		if strings.HasPrefix(c, "value_too_large@") {
			tooLarge = append(tooLarge, c)
		}
	}
	if diff := cmp.Diff([]string{"value_too_large@main.tf:6", "value_too_large@main.tf:91"}, tooLarge); diff != "" {
		t.Errorf("value_too_large diagnostics (-want +got):\n%s", diff)
	}
}

func TestDecodeResourcesCancelled(t *testing.T) {
	t.Parallel()
	m, locals := evalLocals(t, map[string]string{"main.tf": "resource \"x\" \"y\" {}\n"}, terraform.VarOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.DecodeResources(ctx, nil, locals); err == nil {
		t.Error("DecodeResources with a cancelled context succeeded")
	}
}

// TestDecodeResourceInvalidMetaArguments: meta-arguments Terraform would reject are ignored
// with a warning; other edge cases stay unknown rather than guessed.
func TestDecodeResourceInvalidMetaArguments(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("1 + ", 1001) + "1" // past maxOperators
	m, res := decodeResources(t, map[string]string{
		"main.tf": `variable "pw" {
  default   = "hunter2"
  sensitive = true
}
resource "x" "a" {
  provider   = aws.eu.extra
  depends_on = [var.x, "str"]

  lifecycle {
    prevent_destroy = var.pw
    ignore_changes  = [tags[0], "acl", rules[1]["x"]]
  }
}

resource "x" "c" {
  provider = aws["eu"]

  lifecycle {
    prevent_destroy = "true"
  }
}

resource "x" "b" {
  depends_on = aws_iam_role.r
  provider   = aws
  secret     = upper(var.pw, 1)
  deep       = ` + deep + `
  dup        = 1

  dup {
    a = 1
  }

  lifecycle {
    ignore_changes = all.x
  }
}
`,
	})
	a := resource(t, res, "x.a")
	if a.ProviderConfig != "" || len(a.DependsOn) != 0 || a.Lifecycle.PreventDestroy != nil {
		t.Errorf("x.a = %+v; want invalid meta-arguments ignored", a)
	}
	if diff := cmp.Diff([]string{"tags.0", "rules.1.x"}, a.Lifecycle.IgnoreChanges); diff != "" {
		t.Errorf("ignore_changes (-want +got):\n%s", diff)
	}
	c := resource(t, res, "x.c")
	if c.ProviderConfig != "" || c.Lifecycle.PreventDestroy == nil || !*c.Lifecycle.PreventDestroy {
		t.Errorf("x.c = %+v; want the provider index rejected and prevent_destroy converted", c)
	}
	b := resource(t, res, "x.b")
	if b.ProviderConfig != "aws" || len(b.Lifecycle.IgnoreChanges) != 0 {
		t.Errorf("x.b = %+v", b)
	}
	if diff := cmp.Diff([]string{"deep", "dup", "secret"}, paths(b.Unknown)); diff != "" {
		t.Errorf("unknown (-want +got):\n%s", diff)
	}
	if s := attr(t, b.Value, "secret"); !s.HasMark(terraform.SensitiveMark) {
		t.Errorf("secret = %#v, want unknown and sensitive", s)
	}
	want := []string{
		"evaluation@main.tf:6", "evaluation@main.tf:7", "evaluation@main.tf:7",
		"evaluation@main.tf:10", "evaluation@main.tf:11",
		"evaluation@main.tf:16",
		"evaluation@main.tf:24", "evaluation@main.tf:26", "expression_too_complex@main.tf:27", "evaluation@main.tf:35",
	}
	got := codes(m)
	slices.Sort(want)
	slices.Sort(got)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diagnostics (-want +got):\n%s", diff)
	}
}

// TestDecodeResourcesEstimateBeforeEvaluating: an attribute whose inputs alone pass the value
// limit is refused before it is built, so a template repeating a large variable costs nothing.
func TestDecodeResourcesEstimateBeforeEvaluating(t *testing.T) {
	src := "variable \"s\" {\n  default = \"" + strings.Repeat("x", 100_000) + "\"\n}\n\n" +
		"resource \"x\" \"y\" {\n  a = \"" + strings.Repeat("${var.s}", 200) + "\"\n}\n"
	m, vars, err := evalVars(t, ".", map[string]string{"main.tf": src}, terraform.VarOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res, err := m.DecodeResources(context.Background(), vars, nil)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := attr(t, res[0].Value, "a"); got.IsKnown() {
		t.Errorf("a is known, want unknown")
	}
	// Building the value would allocate 20 MB.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Errorf("decoding allocated %d bytes; want the attribute refused before it is built", alloc)
	}
}

// TestDecodeResourcesManyReferences: each reference to a large value costs a lookup, not a walk
// of the value (2,000 walks of this variable took over a minute). Every attribute here is over
// the value limit, so nothing is evaluated and only the references cost anything.
func TestDecodeResourcesManyReferences(t *testing.T) {
	var b strings.Builder
	b.WriteString("variable \"big\" {\n  default = [" + strings.Repeat("0,", 100_000) + "0]\n}\n\nresource \"x\" \"y\" {\n")
	for i := range 2000 {
		fmt.Fprintf(&b, "  a%d = [var.big, var.big, var.big]\n", i)
	}
	b.WriteString("  many = [" + strings.Repeat("var.big, ", 900) + "1]\n}\n")
	m, vars, err := evalVars(t, ".", map[string]string{"main.tf": b.String()}, terraform.VarOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := m.DecodeResources(context.Background(), vars, nil); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	// One walk of the variable allocates megabytes; 6,900 walks would be gigabytes.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Errorf("decoding allocated %d bytes; want each value walked once", alloc)
	}
}
