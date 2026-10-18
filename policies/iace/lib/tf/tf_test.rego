package iace.lib.tf_test

import data.iace.lib.tf

bucket := {
	"address": "aws_s3_bucket.logs[0]",
	"base_address": "aws_s3_bucket.logs",
	"type": "aws_s3_bucket",
	"mode": "managed",
	"provider": "registry.terraform.io/hashicorp/aws",
	"values": {"bucket": "logs"},
	"unknown": [],
	"references": {},
}

pab(address, refs) := {
	"address": address,
	"base_address": address,
	"type": "aws_s3_bucket_public_access_block",
	"mode": "managed",
	"provider": "registry.terraform.io/hashicorp/aws",
	"values": {"block_public_acls": true},
	"unknown": [],
	"references": {"bucket": refs},
}

test_resources_filters_by_type_and_mode if {
	ds := object.union(bucket, {"mode": "data"})
	inp := {"resources": [bucket, pab("aws_s3_bucket_public_access_block.a", []), ds]}
	tf.resources("aws_s3_bucket") == [bucket] with input as inp
}

test_data_sources_filters_by_type_and_mode if {
	ds := object.union(bucket, {"mode": "data", "type": "aws_iam_policy_document"})
	tf.data_sources("aws_iam_policy_document") == [ds] with input as {"resources": [bucket, ds]}
}

test_is_unknown_matches_path_and_descendants if {
	r := object.union(bucket, {"unknown": [["logging"]]})
	tf.is_unknown(r, ["logging"])
	tf.is_unknown(r, ["logging", 0, "target_bucket"])
	not tf.is_unknown(r, ["bucket"])
}

test_value_or_returns_configured_value if {
	tf.value_or(pab("x", []), ["block_public_acls"], false) == true
}

test_value_or_returns_fallback_when_absent if {
	tf.value_or(pab("x", []), ["ignore_public_acls"], false) == false
}

test_provider_major_from_lock_file if {
	inp := {"provider_versions": {"registry.terraform.io/hashicorp/aws": "6.12.0"}}
	tf.provider_major(bucket) == 6 with input as inp
}

test_provider_major_unknown if {
	tf.provider_major(bucket) == -1 with input as {"provider_versions": {}}
}

test_referencing_matches_exact_instance_address if {
	exact := pab("aws_s3_bucket_public_access_block.exact", ["aws_s3_bucket.logs[0]"])
	inp := {"resources": [bucket, exact]}
	got := tf.referencing("aws_s3_bucket_public_access_block", "bucket", bucket) with input as inp
	got == [exact]
}

test_referencing_matches_base_address if {
	base := pab("aws_s3_bucket_public_access_block.base", ["aws_s3_bucket.logs"])
	other := pab("aws_s3_bucket_public_access_block.other", ["aws_s3_bucket.other"])
	inp := {"resources": [bucket, base, other]}
	got := tf.referencing("aws_s3_bucket_public_access_block", "bucket", bucket) with input as inp
	got == [base]
}

# A block written as a list (HCL, and JSON lists) and as one object (.tf.json, ADR 0006).
listed := {
	"values": {"metadata_options": [{"http_tokens": "required"}], "ingress": [{"port": 22}, {"port": 443}]},
	"unknown": [["ingress", 1, "cidr"]],
	"sensitive": [["metadata_options", 0, "secret"]],
}

single := {
	"values": {"metadata_options": {"http_tokens": "optional"}, "ingress": {"port": 22}},
	"unknown": [["ingress", "cidr"]],
	"sensitive": [["metadata_options", "secret"]],
}

test_value_or_resolves_step_zero_against_an_object if {
	tf.value_or(listed, ["metadata_options", 0, "http_tokens"], "") == "required"
	tf.value_or(single, ["metadata_options", 0, "http_tokens"], "") == "optional"
}

test_value_or_does_not_resolve_other_indexes_against_an_object if {
	tf.value_or(single, ["ingress", 1, "port"], "absent") == "absent"
	tf.value_or(listed, ["ingress", 1, "port"], "absent") == 443
}

test_value_or_falls_back_for_missing_and_null if {
	tf.value_or(listed, ["nope", 0, "x"], "fb") == "fb"
	tf.value_or({"values": {"a": null}}, ["a"], "fb") == "fb"
	tf.value_or({"values": {"a": "x"}}, ["a", "b"], "fb") == "fb"
}

test_stored_path_rewrites_against_the_values if {
	tf.stored_path(single, ["metadata_options", 0, "http_tokens"]) == ["metadata_options", "http_tokens"]
	tf.stored_path(listed, ["metadata_options", 0, "http_tokens"]) == ["metadata_options", 0, "http_tokens"]
}

test_is_unknown_matches_both_shapes if {
	tf.is_unknown(single, ["ingress", 0, "cidr"])
	tf.is_unknown(listed, ["ingress", 1, "cidr"])
	not tf.is_unknown(listed, ["ingress", 0, "cidr"])
	not tf.is_unknown(single, ["ingress", 0, "port"])
}

test_is_unknown_fails_closed_for_paths_too_long_to_walk if {
	tf.is_unknown(listed, ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m"])
	tf.is_sensitive(listed, ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m"])
}

test_is_sensitive_matches_both_shapes_and_ancestors if {
	tf.is_sensitive(single, ["metadata_options", 0, "secret"])
	tf.is_sensitive(listed, ["metadata_options", 0, "secret"])
	tf.is_sensitive(listed, ["metadata_options"]) # an ancestor holds a sensitive value
	not tf.is_sensitive(single, ["metadata_options", 0, "http_tokens"])
	not tf.is_sensitive({"values": {"a": "x"}}, ["a"]) # no sensitive field at all
}

test_blocks_returns_a_list_for_both_shapes if {
	tf.blocks(listed.values, "ingress") == [{"port": 22}, {"port": 443}]
	tf.blocks(single.values, "ingress") == [{"port": 22}]
	tf.blocks(single.values, "nope") == []
	tf.blocks({"x": "scalar"}, "x") == []
}

test_blocks_is_empty_for_an_unknown_block if {
	r := {"values": {"ingress": null}, "unknown": [["ingress"]]}
	tf.blocks(r.values, "ingress") == []
	tf.is_unknown(r, ["ingress"]) # rules must check this before concluding from an empty list
}

twelve := ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]

test_paths_of_twelve_steps_are_walked if {
	deep := {"values": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": {"l": "v"}}}}}}}}}}}}}
	tf.value_or(object.union(deep, {"unknown": [], "sensitive": []}), twelve, "fb") == "v"
	not tf.is_unknown(object.union(deep, {"unknown": []}), twelve)
	tf.is_unknown(object.union(deep, {"unknown": [twelve]}), twelve)
	tf.is_sensitive(object.union(deep, {"sensitive": [["a", "b"]]}), twelve)
	not tf.is_sensitive(object.union(deep, {"sensitive": []}), twelve)
}
