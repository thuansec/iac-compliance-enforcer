package model

import (
	"encoding/json/v2"
	"fmt"
)

// Values holds attribute values as generic JSON values: strings, float64 or int64 numbers, bools,
// []any, map[string]any and nil. A nil Values encodes as {} (the attribute set is empty), but
// inside it every nil, including a typed nil slice or map, encodes as null, because null means
// "unknown" (contract rule 2). A nil slice there must never read as a known empty list. The one
// exception is a known null list or map element, which is null without being unknown (ADR 0045).
type Values map[string]any

// MarshalJSON encodes the values with sorted keys and nil collections as null.
func (v Values) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	data, err := json.Marshal(map[string]any(v),
		json.Deterministic(true), json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true))
	if err != nil {
		return nil, fmt.Errorf("values: %w", err)
	}
	return data, nil
}
