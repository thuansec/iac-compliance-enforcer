package redact_test

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/thuansec/iac-compliance-enforcer/internal/model"
	"github.com/thuansec/iac-compliance-enforcer/internal/redact"
)

// Every secret below is fake: well-known documentation examples or obviously made-up strings.
func TestIsSecret(t *testing.T) {
	for _, s := range []string{
		"AKIAIOSFODNN7EXAMPLE",               // AWS access key ID (AWS docs example) (iace:fake-secret)
		"prefix ASIAIOSFODNN7EXAMPLE suffix", // embedded temporary key ID (iace:fake-secret)
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----", // iace:fake-secret
		"-----BEGIN PRIVATE KEY-----",         // iace:fake-secret
		"-----BEGIN OPENSSH PRIVATE KEY-----", // iace:fake-secret
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXRlc3QifQ.ZmFrZS1zaWduYXR1cmUtZm9yLXRlc3Rz", // JWT of fake claims
		"DefaultEndpointsProtocol=https;AccountName=fake;AccountKey=ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleQ==;EndpointSuffix=core.windows.net",
		"Endpoint=sb://fake.servicebus.windows.net/;SharedAccessKeyName=fake;SharedAccessKey=ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZQ=",
		strings.Repeat("Zm", 43) + "==",                                   // 88-character base64 storage-key shape
		"git::https://fakeuser:fake-token-123@example.com/org/module.git", // iace:fake-secret
		"q8Zr2Lx9Vt4Wn7Pk3Ys6Hd1Jf5Mb0Cg8a",                               // 33 random-looking characters
		"fake/Q8zR2lX9vT4wN7pK3yS6hD1jF5mB0cG8eA+",
		"https://stfake.blob.core.windows.net/pkg/app.zip?sv=2022-11-02&se=2030-01-01&sp=r&sig=ZmFrZQ%2Bc2lnbmF0dXJl%2Fhere%3D", // SAS URL
		"Server=tcp:fake.database.windows.net,1433;Database=db;User ID=admin;Password=fake-password;Encrypt=true;",
		"Host=fake;Username=app;Pwd=fake-password",
	} {
		if !redact.IsSecret(s) {
			t.Errorf("IsSecret(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"",
		"t3.micro",
		"ami-0123456789abcdef0",
		"arn:aws:iam::123456789012:role/service-role/my-application-deployment-role",
		"my-company-production-application-logs-bucket-2024",
		"registry.terraform.io/hashicorp/aws",
		"terraform-aws-modules/s3-bucket/aws",
		"git::https://example.com/org/module.git?ref=v1.2.3",
		"0.0.0.0/0",
		"10.0.0.0/16",
		"This is a fairly long description of the bucket that is not a secret at all.",
		"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-fake",
		"/subscriptions/3f2504e0-4f89-11d3-9a0c-0305e82c3301/resourceGroups/MyResourceGroup1/providers/Microsoft.Network/virtualNetworks/MyVnet01",
		"arn:aws:iam::123456789012:policy/MyApplicationDeploymentPolicyForProduction2024",
		"projects/my-project-123/locations/europe-west1/keyRings/MyKeyRing01/cryptoKeys/MyKey02",
		"https://stfake.blob.core.windows.net/pkg/app.zip",                 // no signature
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // a SHA-256 checksum
		"q8Zr2Lx9Vt4Wn7Pk3Ys6Hd1Jf5Mb0Cg8",                                 // random-looking, but 32 characters: not over 32
	} {
		if redact.IsSecret(s) {
			t.Errorf("IsSecret(%q) = true, want false", s)
		}
	}
}

func TestIsCredentialName(t *testing.T) {
	for name, want := range map[string]bool{
		"password": true, "db_password": true, "Secret": true, "client_secret": true, "token": true,
		"private_key": true, "credentials": true, "connection_string": true, "access_key": true,
		"secret_key": true, "api_key": true, "sas_token": true,
		"bucket": false, "tags": false, "region": false, "name": false, "key": false,
	} {
		if got := redact.IsCredentialName(name); got != want {
			t.Errorf("IsCredentialName(%q) = %v, want %v", name, got, want)
		}
	}
}

func encode(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDocument(t *testing.T) {
	doc := &model.InputDocument{
		Terraform: model.TerraformSettings{Backend: &model.Backend{
			Type:   "s3",
			Values: model.Values{"bucket": "tf-state", "access_key": "fake-access-key", "encrypt": true},
		}},
		Providers: []model.ProviderConfig{{LocalName: "aws", Values: model.Values{"region": "eu-west-1", "token": "fake"}}},
		Resources: []model.Resource{{
			Address: "aws_db_instance.db",
			Values: model.Values{
				"engine":    "postgres",
				"password":  "fake-password",
				"port":      5432,
				"user_data": "export KEY=AKIAIOSFODNN7EXAMPLE", // iace:fake-secret
				"tags":      map[string]any{"Name": "db", "api_key": "fake"},
				"settings":  []any{map[string]any{"value": "kept"}, map[string]any{"value": "hidden"}},
				"unknown":   nil,
			},
			Sensitive: []model.Path{{model.AttrStep("settings"), model.IndexStep(1)}},
		}},
		ModuleCalls: []model.ModuleCall{
			{Address: "module.a", Source: "git::https://fakeuser:fake-token-123@example.com/m.git"}, // iace:fake-secret
			{Address: "module.b", Source: "./b"},
		},
	}
	before := encode(t, doc)
	got := redact.Document(doc)
	if after := encode(t, doc); after != before {
		t.Fatal("Document modified its input")
	}
	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"backend", got.Terraform.Backend.Values, `{"access_key":"<redacted>","bucket":"tf-state","encrypt":true}`},
		{"provider", got.Providers[0].Values, `{"region":"eu-west-1","token":"<redacted>"}`},
		{"resource", got.Resources[0].Values, `{"engine":"postgres","password":"<redacted>","port":5432,` +
			`"settings":[{"value":"kept"},{"value":"<redacted>"}],"tags":{"Name":"db","api_key":"<redacted>"},` +
			`"unknown":null,"user_data":"<redacted>"}`},
		{"module calls", []string{got.ModuleCalls[0].Source, got.ModuleCalls[1].Source}, `["<redacted>","./b"]`},
	} {
		if s := encode(t, tc.v); s != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, s, tc.want)
		}
	}
	if strings.Contains(encode(t, got), "fake-") || strings.Contains(encode(t, got), "AKIA") {
		t.Errorf("a fake secret survived: %s", encode(t, got))
	}
}

func TestDocumentNil(t *testing.T) {
	if redact.Document(nil) != nil {
		t.Error("Document(nil) is not nil")
	}
	got := redact.Document(&model.InputDocument{})
	if got == nil || got.Terraform.Backend != nil {
		t.Errorf("Document of an empty document: %+v", got)
	}
}

// TestDocumentIsLinear bounds redaction of a large document: 200,000 values, many sensitive.
func TestDocumentIsLinear(t *testing.T) {
	items := make([]any, 200_000)
	var sensitive []model.Path
	for i := range items {
		items[i] = map[string]any{"v": "plain-value"}
		if i%2 == 0 {
			sensitive = append(sensitive, model.Path{model.AttrStep("items"), model.IndexStep(i)})
		}
	}
	doc := &model.InputDocument{Resources: []model.Resource{{Values: model.Values{"items": items}, Sensitive: sensitive}}}
	start := time.Now()
	got := redact.Document(doc)
	if d := time.Since(start); d > 2*time.Second*raceSlowdown {
		t.Errorf("redacting took %v", d)
	}
	list := got.Resources[0].Values["items"].([]any)
	if list[0].(map[string]any)["v"] != redact.Placeholder || list[1].(map[string]any)["v"] != "plain-value" {
		t.Errorf("items 0 and 1: %v %v", list[0], list[1])
	}
}
