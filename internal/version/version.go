// Package version reports the build information of the running binary. Release builds set it
// with the linker; nothing at runtime changes it, and it does no I/O.
package version

// Name is the command name reported in build information.
const Name = "iace"

// SchemaVersion is the version of the JSON document that `iace version --json` prints.
const SchemaVersion = "1"

// Version, Commit and Date are set at link time, for example:
//
//	go build -ldflags "-X github.com/thuansec/iac-compliance-enforcer/internal/version.Version=v0.1.0"
//
// They are variables only because -X can set nothing else; code never assigns them.
var (
	Version = "dev"
	Commit  = "dev"
	Date    = "dev"
)

// Info is the build information of the running binary. Field order is the JSON key order.
type Info struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Date          string `json:"date"`
}

// Get returns the build information of the running binary.
func Get() Info {
	return Info{SchemaVersion: SchemaVersion, Name: Name, Version: Version, Commit: Commit, Date: Date}
}
