// Package terraform loads Terraform configuration statically: it discovers modules under a scan
// root, parses and evaluates them, and normalizes the result into input documents. It reads
// scanned files only through internal/fsutil and never executes Terraform, providers, modules or
// anything else from the scanned repository.
package terraform
