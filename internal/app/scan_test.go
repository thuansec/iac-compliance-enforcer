package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestScanFindsAndSummarizes(t *testing.T) {
	r, err := Scan(context.Background(), filepath.Join(fixtureRoot, "IACE-AWS-EC2-001", "fail"), ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Summary.High != 2 || r.Summary.Blocking != 2 || len(r.Inputs) != 1 {
		t.Errorf("report %+v", r)
	}
	if r.Findings[0].Resource.Address != "aws_instance.optional" {
		t.Errorf("findings not sorted: %v", r.Findings)
	}
}

func TestScanWithoutRootModules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("no terraform"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), dir, ScanOptions{FailOn: "high"}); !errors.Is(err, ErrNoRootModules) {
		t.Errorf("error %v, want ErrNoRootModules", err)
	}
}

// A setting an override file weakens is found and located in the override file (ADR 0048).
func TestScanLocatesFindingsInOverrideFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"main.tf": "resource \"aws_s3_account_public_access_block\" \"this\" {\n" +
			"  block_public_acls       = true\n  block_public_policy     = true\n" +
			"  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n",
		"main_override.tf": "# weakens the account block\nresource \"aws_s3_account_public_access_block\" \"this\" {\n" +
			"  block_public_policy = false\n}\n",
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Scan(context.Background(), dir, ScanOptions{FailOn: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings %+v, want the overridden setting only", r.Findings)
	}
	if loc := r.Findings[0].Location; loc.File != "main_override.tf" || loc.StartLine != 3 {
		t.Errorf("location %+v, want main_override.tf:3", loc)
	}
}
