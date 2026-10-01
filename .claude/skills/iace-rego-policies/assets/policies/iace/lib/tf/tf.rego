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

# True when the value at path (or one of its ancestors) is unknown statically
# (unresolved expression, known-after-apply, unresolved module).
is_unknown(r, path) if {
	some u in r.unknown
	count(u) <= count(path)
	array.slice(path, 0, count(u)) == u
}

# Configured value at path, or fallback when the attribute is absent or null.
# Callers must check is_unknown first: unknown values are stored as null.
value_or(r, path, fallback) := object.get(r.values, path, fallback) if {
	object.get(r.values, path, null) != null
}

value_or(r, path, fallback) := fallback if {
	object.get(r.values, path, null) == null
}

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
