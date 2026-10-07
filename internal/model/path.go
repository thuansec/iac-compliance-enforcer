package model

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Path addresses a value inside a resource's values: attribute and block names as strings, list
// indexes as integers. It encodes as a JSON array such as ["ingress", 0, "cidr_blocks"].
type Path []PathStep

// String returns the dot-joined form used as a JSON object key: "ingress.0.cidr_blocks".
func (p Path) String() string {
	parts := make([]string, len(p))
	for i, s := range p {
		parts[i] = s.String()
	}
	return strings.Join(parts, ".")
}

// PathStep is one element of a Path: an attribute or block name, or a list index.
type PathStep struct {
	name    string
	index   int
	isIndex bool
}

// AttrStep returns a path step for an attribute or block name.
func AttrStep(name string) PathStep { return PathStep{name: name} }

// IndexStep returns a path step for a list index; i must not be negative.
func IndexStep(i int) PathStep { return PathStep{index: i, isIndex: true} }

// IsIndex reports whether the step is a list index.
func (s PathStep) IsIndex() bool { return s.isIndex }

// Name returns the attribute or block name, or "" for an index step.
func (s PathStep) Name() string { return s.name }

// Index returns the list index, or 0 for a name step.
func (s PathStep) Index() int { return s.index }

// String returns the name, or the decimal index.
func (s PathStep) String() string {
	if s.isIndex {
		return strconv.Itoa(s.index)
	}
	return s.name
}

// MarshalJSON encodes a name as a JSON string and an index as a JSON integer.
func (s PathStep) MarshalJSON() ([]byte, error) {
	if s.isIndex {
		if s.index < 0 {
			return nil, fmt.Errorf("path element: negative index %d", s.index)
		}
		return strconv.AppendInt(nil, int64(s.index), 10), nil
	}
	return json.Marshal(s.name)
}

// UnmarshalJSON accepts a JSON string or a non-negative JSON integer.
func (s *PathStep) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var name string
		if err := json.Unmarshal(data, &name); err != nil {
			return fmt.Errorf("path element: %w", err)
		}
		*s = AttrStep(name)
		return nil
	}
	i, err := parseIndex(data)
	if err != nil {
		return fmt.Errorf("path element (%s): %w", jsonKind(data), err)
	}
	*s = IndexStep(i)
	return nil
}

// instanceKeyKind says which form an InstanceKey holds.
type instanceKeyKind uint8

const (
	keyNone instanceKeyKind = iota
	keyInt
	keyString
)

// InstanceKey is a resource instance key: none (JSON null), a count index (JSON integer) or a
// for_each key (JSON string). The zero value is NoKey.
type InstanceKey struct {
	kind instanceKeyKind
	i    int
	s    string
}

// NoKey is the key of a resource without count or for_each, or whose key is unknown.
var NoKey = InstanceKey{}

// IntKey returns a count index key; i must not be negative.
func IntKey(i int) InstanceKey { return InstanceKey{kind: keyInt, i: i} }

// StringKey returns a for_each key.
func StringKey(s string) InstanceKey { return InstanceKey{kind: keyString, s: s} }

// IsNone reports whether the key is NoKey.
func (k InstanceKey) IsNone() bool { return k.kind == keyNone }

// Int returns the count index and whether the key is one.
func (k InstanceKey) Int() (int, bool) { return k.i, k.kind == keyInt }

// Str returns the for_each key and whether the key is one.
func (k InstanceKey) Str() (string, bool) { return k.s, k.kind == keyString }

// MarshalJSON encodes NoKey as null, a count index as an integer and a for_each key as a string.
func (k InstanceKey) MarshalJSON() ([]byte, error) {
	switch k.kind {
	case keyInt:
		if k.i < 0 {
			return nil, fmt.Errorf("instance key: negative index %d", k.i)
		}
		return strconv.AppendInt(nil, int64(k.i), 10), nil
	case keyString:
		return json.Marshal(k.s)
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON accepts null, a non-negative integer or a string.
func (k *InstanceKey) UnmarshalJSON(data []byte) error {
	switch {
	case string(data) == "null":
		*k = NoKey
		return nil
	case len(data) > 0 && data[0] == '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("instance key: %w", err)
		}
		*k = StringKey(s)
		return nil
	}
	i, err := parseIndex(data)
	if err != nil {
		return fmt.Errorf("instance key (%s): %w", jsonKind(data), err)
	}
	*k = IntKey(i)
	return nil
}

// jsonKind names the kind of a JSON value for error messages. Errors never quote the value
// itself, which may be a secret, nor grow with the input.
func jsonKind(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	switch data[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

var errNotIndex = errors.New("want a non-negative integer or a string")

// parseIndex parses a JSON number that must be a non-negative integer that fits in an int.
func parseIndex(data []byte) (int, error) {
	i, err := strconv.ParseUint(string(data), 10, strconv.IntSize-1)
	if err != nil {
		return 0, errNotIndex
	}
	return int(i), nil
}
