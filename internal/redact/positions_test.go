package redact_test

import (
	"math/rand/v2"
	"testing"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/redact"
)

// TestIsSecretCatchesRandomKeys checks the entropy rule statistically: random base62 keys just
// over the 32-character threshold must nearly all be caught (T-0109f review: a fixed cutoff
// missed about a quarter of them).
func TestIsSecretCatchesRandomKeys(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{33, 40, 64} {
		caught := 0
		for range 1000 {
			b := make([]byte, n)
			for i := range b {
				b[i] = alphabet[r.IntN(len(alphabet))]
			}
			if redact.IsSecret(string(b)) {
				caught++
			}
		}
		if caught < 950 {
			t.Errorf("%d characters: caught %d of 1,000 random keys, want at least 950", n, caught)
		}
	}
}

// TestDocumentHidesEveryPosition places, at each position, a value that only the mechanism under
// test can catch: plain names and plain-looking values unless the case is about them.
func TestDocumentHidesEveryPosition(t *testing.T) {
	const fakeKey = "AKIAIOSFODNN7EXAMPLE" // AWS documentation example (iace:fake-secret)
	path := func(steps ...model.PathStep) model.Path { return model.Path(steps) }
	doc := &model.InputDocument{
		Terraform: model.TerraformSettings{Backend: &model.Backend{Values: model.Values{"note": fakeKey}}},
		Providers: []model.ProviderConfig{{
			Values:    model.Values{"region": "plain-provider-value", "note": fakeKey},
			Sensitive: []model.Path{path(model.AttrStep("region"))},
		}},
		Resources: []model.Resource{
			{
				Values: model.Values{
					"passwords": []any{"plain-a", "plain-b"},
					"config":    map[string]any{"a": "plain-c", "n": 1234},
					"tags":      map[string]any{"foo": "plain-d", "bar": "kept-1"},
					"pin":       4321,
					"enabled":   true,
					"empty":     []any(nil),
					"nomap":     map[string]any(nil),
					"lifetime":  map[string]any{"token_lifetime": 3600},
				},
				Sensitive: []model.Path{
					path(model.AttrStep("config")),
					path(model.AttrStep("tags"), model.AttrStep("foo")),
					path(model.AttrStep("pin")),
					path(model.AttrStep("enabled")),
				},
			},
			// The first resource's sensitive paths must not apply to this one.
			{Values: model.Values{"config": map[string]any{"a": "kept-2"}, "pin": 1111}},
		},
		ModuleCalls: []model.ModuleCall{{Source: "./m", Version: fakeKey}},
	}
	got := redact.Document(doc)
	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"backend pattern", got.Terraform.Backend.Values, `{"note":"<redacted>"}`},
		{"provider sensitive path and pattern", got.Providers[0].Values, `{"note":"<redacted>","region":"<redacted>"}`},
		{"resource", got.Resources[0].Values, `{"config":{"a":"<redacted>","n":"<redacted>"},"empty":null,` +
			`"enabled":"<redacted>","lifetime":{"token_lifetime":3600},"nomap":null,` +
			`"passwords":["<redacted>","<redacted>"],"pin":"<redacted>","tags":{"bar":"kept-1","foo":"<redacted>"}}`},
		{"other resource", got.Resources[1].Values, `{"config":{"a":"kept-2"},"pin":1111}`},
		{"module call version", got.ModuleCalls[0].Version, `"<redacted>"`},
	} {
		if s := encode(t, tc.v); s != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, s, tc.want)
		}
	}
}

func TestDocumentIsADeepCopy(t *testing.T) {
	doc := &model.InputDocument{
		ProviderVersions: map[string]string{"p": "1.0.0"},
		Resources: []model.Resource{{
			Values:     model.Values{"a": "x"},
			Unknown:    []model.Path{{model.AttrStep("u")}},
			References: map[string][]string{"a": {"x.y"}},
			Meta:       model.ResourceMeta{DependsOn: []string{"x.y"}},
			Source: model.ResourceSource{
				Attributes:     map[string]model.Range{"a": {StartLine: 1}},
				AttributeFiles: map[string]string{"a": "main_override.tf"},
			},
		}},
		Variables:    []model.Variable{{Name: "v"}},
		CoverageGaps: []model.CoverageGap{{Detail: "d"}},
	}
	before := encode(t, doc)
	got := redact.Document(doc)
	got.ProviderVersions["p"] = "changed"
	got.Resources[0].Unknown[0] = model.Path{model.AttrStep("changed")}
	got.Resources[0].References["a"][0] = "changed"
	got.Resources[0].Meta.DependsOn[0] = "changed"
	got.Resources[0].Source.Attributes["a"] = model.Range{StartLine: 9}
	got.Resources[0].Source.AttributeFiles["a"] = "changed"
	got.Variables[0].Name = "changed"
	got.CoverageGaps[0].Detail = "changed"
	if after := encode(t, doc); after != before {
		t.Errorf("changing the copy changed the input:\n%s\n%s", before, after)
	}
}
