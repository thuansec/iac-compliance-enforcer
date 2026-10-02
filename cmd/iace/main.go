// Command iace checks Terraform for security and compliance misconfigurations.
// All behaviour lives in internal/cli; this file only starts it.
package main

import "github.com/thuansec/iac-compliance-enforcer/internal/cli"

func main() {
	cli.Main()
}
