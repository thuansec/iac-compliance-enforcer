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
