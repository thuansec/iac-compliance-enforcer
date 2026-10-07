package model

import (
	"encoding/json/v2"
	"fmt"
)

// EncodeInput encodes an input document as compact JSON. The output is deterministic (object
// keys sorted) and never contains null for a collection: nil slices encode as [] and nil maps
// as {}, so policies can iterate without null checks.
func EncodeInput(doc *InputDocument) ([]byte, error) {
	data, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode input document: %w", err)
	}
	return data, nil
}

// DecodeInput decodes an input document. It checks the shape only: unknown members, duplicate
// names, invalid UTF-8, malformed paths or instance keys, and a schema_version other than
// InputSchemaVersion are errors. It does not apply the value constraints of
// schemas/input.v1.json (such as relative file paths or 1-based ranges), which remains the
// authority. Numbers in values decode as float64.
func DecodeInput(data []byte) (*InputDocument, error) {
	var doc InputDocument
	if err := json.Unmarshal(data, &doc, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode input document: %w", err)
	}
	if doc.SchemaVersion != InputSchemaVersion {
		return nil, fmt.Errorf("decode input document: schema_version is not %q", InputSchemaVersion)
	}
	return &doc, nil
}
