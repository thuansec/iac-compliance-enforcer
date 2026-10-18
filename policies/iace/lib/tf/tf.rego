# METADATA
# title: Terraform input helpers
# description: Shared, side-effect-free helpers for querying the normalized iace input document.
package iace.lib.tf

# Managed resources of the given type.
resources(rtype) := [r |
	some r in input.resources
	r.mode == "managed"
	r.type == rtype
]

# Data sources of the given type (e.g. aws_iam_policy_document).
data_sources(rtype) := [r |
	some r in input.resources
	r.mode == "data"
	r.type == rtype
]

# Paths are written as for a plan document: a nested block is a list, so its first entry is
# ["metadata_options", 0, "http_tokens"]. In .tf.json a block written as one object stays an
# object (ADR 0006), so every helper resolves an integer step 0 against an object as the object
# itself, and matches unknown and sensitive paths, which keep the stored shape, against the path
# rewritten the same way. Paths of more than 12 steps are not resolved.

# The value and the stored-shape path reached by following path from values.
_walk(values, path) := w if {
	count(path) <= 12
	w0 := {"v": values, "p": []}
	w1 := _next(w0, path, 0)
	w2 := _next(w1, path, 1)
	w3 := _next(w2, path, 2)
	w4 := _next(w3, path, 3)
	w5 := _next(w4, path, 4)
	w6 := _next(w5, path, 5)
	w7 := _next(w6, path, 6)
	w8 := _next(w7, path, 7)
	w9 := _next(w8, path, 8)
	w10 := _next(w9, path, 9)
	w11 := _next(w10, path, 10)
	w := _next(w11, path, 11)
}

_next(w, path, i) := w if {
	i >= count(path)
} else := _step(w, path[i])

# A 0 against an object stays on the object: the block written as one object.
_step(w, s) := w if {
	s == 0
	is_object(w.v)
} else := {"v": _child(w.v, s), "p": array.concat(w.p, [s])}

_child(v, s) := x if {
	x := v[s]
} else := null

# The stored-shape path for path: matches unknown and sensitive paths.
stored_path(r, path) := _walk(r.values, path).p

# True when the value at path, or one of its ancestors, is unknown statically (an unresolved
# expression, known after apply, an unresolved module).
is_unknown(r, path) if {
	some u in r.unknown
	_covers(u, stored_path(r, path))
}

# A path too long to walk is treated as unknown, never judged.
is_unknown(_, path) if count(path) > 12

# True when the value at path, an ancestor or a descendant is sensitive: rules must not print it.
is_sensitive(r, path) if {
	p := stored_path(r, path)
	some s in object.get(r, "sensitive", [])
	_overlaps(s, p)
}

is_sensitive(_, path) if count(path) > 12

_covers(prefix, path) if {
	count(prefix) <= count(path)
	array.slice(path, 0, count(prefix)) == prefix
}

_overlaps(a, b) if _covers(a, b)

_overlaps(a, b) if _covers(b, a)

# Configured value at path, or fallback when the attribute is absent or null.
# Callers must check is_unknown first: unknown values are stored as null.
value_or(r, path, fallback) := v if {
	v := _walk(r.values, path).v
	v != null
} else := fallback

# The entries of the nested block name in values: a list as it is, a block written as one object
# as a one-entry list, and none when the block is absent or unknown (null). An empty list is
# therefore not proof of absence: check not is_unknown(r, [name]) before concluding from it, and
# guard each entry with is_unknown(r, [name, i, attr]) (an unknown entry is null). Rules iterate
# blocks only through it.
blocks(values, name) := b if {
	b := values[name]
	is_array(b)
} else := [b] if {
	b := values[name]
	is_object(b)
} else := []

# Major version of the provider managing r, from the lock file; -1 when unknown.
provider_major(r) := to_number(split(input.provider_versions[r.provider], ".")[0])

provider_major(r) := -1 if {
	not input.provider_versions[r.provider]
}

# Resources of rtype whose attribute attr references the target resource object,
# by its exact instance address or its base address (index unknown at reference time).
referencing(rtype, attr, target) := [r |
	some r in resources(rtype)
	some ref in object.get(r.references, attr, [])
	ref in {target.address, object.get(target, "base_address", target.address)}
]
