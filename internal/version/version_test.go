package version

import "testing"

func TestGetDefaults(t *testing.T) {
	t.Parallel()

	got := Get()
	want := Info{SchemaVersion: "1", Name: "iace", Version: "dev", Commit: "dev", Date: "dev"}
	if got != want {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}
