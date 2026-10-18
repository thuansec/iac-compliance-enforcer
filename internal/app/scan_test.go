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
