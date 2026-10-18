package iace.rules.aws.s3.public_access_block_test

import data.iace.rules.aws.s3.public_access_block

block(rtype, values, unknown) := {
	"address": $"{rtype}.this",
	"type": rtype,
	"mode": "managed",
	"provider": "registry.terraform.io/hashicorp/aws",
	"values": values,
	"unknown": unknown,
	"references": {},
}

all_on := {
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

test_passes_when_all_settings_enabled if {
	inp := {"resources": [
		block("aws_s3_bucket_public_access_block", object.union(all_on, {"bucket": "b"}), []),
		block("aws_s3_account_public_access_block", all_on, []),
	]}
	count(public_access_block.deny) == 0 with input as inp
}

test_fails_for_each_setting_left_unset if {
	inp := {"resources": [block("aws_s3_bucket_public_access_block", {"bucket": "b"}, [])]}
	count(public_access_block.deny) == 4 with input as inp
}

test_fails_when_a_setting_is_false if {
	values := object.union(all_on, {"restrict_public_buckets": false})
	inp := {"resources": [block("aws_s3_account_public_access_block", values, [])]}
	count(public_access_block.deny) == 1 with input as inp
	some v in public_access_block.deny with input as inp
	v.address == "aws_s3_account_public_access_block.this"
	v.attribute_path == ["restrict_public_buckets"]
}

test_skips_unknown_settings if {
	values := object.union(all_on, {"block_public_policy": null})
	inp := {"resources": [block("aws_s3_bucket_public_access_block", values, [["block_public_policy"]])]}
	count(public_access_block.deny) == 0 with input as inp
}

test_ignores_buckets_without_a_block if {
	inp := {"resources": [block("aws_s3_bucket", {"bucket": "b"}, [])]}
	count(public_access_block.deny) == 0 with input as inp
}

test_accepts_true_written_as_a_string if {
	values := object.union(all_on, {"block_public_acls": "true"})
	inp := {"resources": [block("aws_s3_bucket_public_access_block", values, [])]}
	count(public_access_block.deny) == 0 with input as inp
}

test_fails_when_false_is_written_as_a_string if {
	values := object.union(all_on, {"block_public_acls": "false"})
	inp := {"resources": [block("aws_s3_bucket_public_access_block", values, [])]}
	count(public_access_block.deny) == 1 with input as inp
}

test_ignores_data_sources if {
	data_block := object.union(block("aws_s3_bucket_public_access_block", {"bucket": "b"}, []), {"mode": "data"})
	count(public_access_block.deny) == 0 with input as {"resources": [data_block]}
}
