package terraform_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/thuansec/iac-compliance-enforcer/internal/fsutil"
	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/terraform"
)

// scanDocuments discovers, evaluates and normalizes dir into input documents with their gaps.
func scanDocuments(t *testing.T, dir string) []*model.InputDocument {
	t.Helper()
	r, err := fsutil.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	ctx := context.Background()
	limits := terraform.DefaultLimits()
	d, err := terraform.Discover(ctx, r, limits)
	if err != nil {
		t.Fatal(err)
	}
	mods, err := terraform.ClassifyModules(ctx, r, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	results, err := terraform.EvaluateRoots(ctx, r, d, mods, terraform.VarOptions{}, limits, terraform.TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	docs := terraform.Documents(d, results)
	schema := inputSchema(t)
	for _, doc := range docs {
		data, err := model.EncodeInput(doc)
		if err != nil {
			t.Fatal(err)
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(inst); err != nil {
			t.Fatalf("%s: document does not validate: %v", doc.Source.RootModule, err)
		}
	}
	return docs
}

// gapLines lists a document's gaps as "kind file:line detail".
func gapLines(doc *model.InputDocument) []string {
	var out []string
	for _, g := range doc.CoverageGaps {
		out = append(out, fmt.Sprintf("%s %s:%d %s", g.Kind, g.File, g.Line, g.Detail))
	}
	return out
}

func hasGap(lines []string, kind model.GapKind, file, detail string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, string(kind)+" "+file+":") && strings.Contains(l, detail) {
			return true
		}
	}
	return false
}

func TestDocumentsReportEveryGap(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": `variable "n" {
  type = number
}

module "remote" {
  source = "terraform-aws-modules/s3-bucket/aws"
}

resource "aws_s3_bucket" "b" {
  count  = var.n
  bucket = "b-${timestamp()}"
}

resource "aws_security_group" "many" {
  names = [` + strings.Repeat("var.n, ", 1100) + `]
}
`,
		"big.tf":         "# " + strings.Repeat("x", 1<<20) + "\n",
		"broken/main.tf": "resource \"aws_s3_bucket\" \"x\" {\n",
	})
	docs := scanDocuments(t, dir)
	if len(docs) != 2 {
		t.Fatalf("%d documents, want the root and broken/", len(docs))
	}
	root, broken := gapLines(docs[0]), gapLines(docs[1])
	for _, want := range []struct {
		kind         model.GapKind
		file, detail string
	}{
		{model.GapUnresolvedModule, "main.tf", `module "remote"`},
		{model.GapUnsupportedFunction, "main.tf", "timestamp"},
		{model.GapUnknownExpansion, "main.tf", "unknown_expansion"},
		{model.GapLimitExceeded, "big.tf", "too_large"},
		{model.GapIncompleteAnalysis, "main.tf", "aws_security_group.many"},
	} {
		if !hasGap(root, want.kind, want.file, want.detail) {
			t.Errorf("root document lacks a %s gap on %s naming %q; gaps:\n%s", want.kind, want.file, want.detail, strings.Join(root, "\n"))
		}
	}
	if !hasGap(broken, model.GapParseError, "broken/main.tf", "syntax") {
		t.Errorf("broken/ lacks a parse_error gap; gaps:\n%s", strings.Join(broken, "\n"))
	}
	// A skip is reported once, in the document that owns its directory.
	if hasGap(broken, model.GapLimitExceeded, "big.tf", "too_large") {
		t.Error("the root's skipped file is also reported in broken/")
	}
}

func TestDocumentGapsAreSortedAndUnique(t *testing.T) {
	dir := files(t, map[string]string{
		"main.tf": "resource \"x\" \"a\" {\n  v = timestamp()\n  w = timestamp()\n}\n\nresource \"x\" \"b\" {\n  v = uuid()\n}\n",
	})
	gaps := scanDocuments(t, dir)[0].CoverageGaps
	if len(gaps) == 0 {
		t.Fatal("no gaps")
	}
	for i := 1; i < len(gaps); i++ {
		a, b := gaps[i-1], gaps[i]
		if a == b {
			t.Errorf("duplicate gap %+v", b)
		}
		if a.File > b.File || a.File == b.File && a.Line > b.Line {
			t.Errorf("gaps out of order: %+v before %+v", a, b)
		}
	}
}

func TestDocumentsReportSkipsWithoutRoots(t *testing.T) {
	docs := scanDocuments(t, files(t, map[string]string{"big.tf": "# " + strings.Repeat("x", 1<<20) + "\n"}))
	if len(docs) != 1 || docs[0].Source.RootModule != "." {
		t.Fatalf("%d documents, want one for the scan root", len(docs))
	}
	if !hasGap(gapLines(docs[0]), model.GapLimitExceeded, "big.tf", "too_large") {
		t.Errorf("the skipped file is not reported: %v", gapLines(docs[0]))
	}
}

func TestDocumentsReportSkipsInTheRootsThatLoadThem(t *testing.T) {
	docs := scanDocuments(t, files(t, map[string]string{
		"envs/dev/main.tf":  "resource \"aws_s3_bucket\" \"d\" {\n  bucket = \"d\"\n}\n",
		"envs/prod/main.tf": "module \"m\" {\n  source = \"../../modules/m\"\n}\n",
		"modules/m/main.tf": "resource \"aws_s3_bucket\" \"m\" {\n  bucket = \"m\"\n}\n",
		"modules/m/big.tf":  "# " + strings.Repeat("x", 1<<20) + "\n",
	}))
	byRoot := map[string][]string{}
	for _, d := range docs {
		byRoot[d.Source.RootModule] = gapLines(d)
	}
	if !hasGap(byRoot["envs/prod"], model.GapLimitExceeded, "modules/m/big.tf", "too_large") {
		t.Errorf("envs/prod loads modules/m but does not report its skipped file: %v", byRoot["envs/prod"])
	}
	if hasGap(byRoot["envs/dev"], model.GapLimitExceeded, "modules/m/big.tf", "too_large") {
		t.Error("envs/dev reports a file of a module it does not load")
	}
}

// TestDocumentsReportLocalCycles covers locals whose references are incomplete without a
// references_incomplete diagnostic (a cycle): the resources and outputs that use them are
// reported, and so is the cycle.
func TestDocumentsReportLocalCycles(t *testing.T) {
	docs := scanDocuments(t, files(t, map[string]string{
		"main.tf": "locals {\n  a = local.b\n  b = local.a\n}\n\nresource \"aws_s3_bucket\" \"x\" {\n  bucket = local.a\n}\n\n" +
			"output \"o\" {\n  value = local.b\n}\n",
	}))
	lines := gapLines(docs[0])
	for _, want := range []struct {
		kind   model.GapKind
		detail string
	}{
		{model.GapIncompleteAnalysis, "local_cycle"},
		{model.GapIncompleteReferences, "aws_s3_bucket.x"},
		{model.GapIncompleteReferences, "output.o"},
	} {
		if !hasGap(lines, want.kind, "main.tf", want.detail) {
			t.Errorf("no %s gap naming %q; gaps:\n%s", want.kind, want.detail, strings.Join(lines, "\n"))
		}
	}
}
