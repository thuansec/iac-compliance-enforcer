package iace.rules.aws.ec2.imdsv2_required_test

import data.iace.rules.aws.ec2.imdsv2_required

resource(rtype, address, values, unknown) := {
	"address": address,
	"type": rtype,
	"mode": "managed",
	"provider": "registry.terraform.io/hashicorp/aws",
	"values": values,
	"unknown": unknown,
	"references": {},
}

instance(values) := resource("aws_instance", "aws_instance.web", values, [])

account_defaults(tokens) := resource(
	"aws_ec2_instance_metadata_defaults",
	"aws_ec2_instance_metadata_defaults.this",
	{"http_tokens": tokens},
	[],
)

test_fails_when_metadata_options_absent if {
	count(imdsv2_required.deny) == 1 with input as {"resources": [instance({})]}
}

test_fails_when_tokens_optional if {
	inp := {"resources": [instance({"metadata_options": [{"http_tokens": "optional"}]})]}
	some v in imdsv2_required.deny with input as inp
	v.address == "aws_instance.web"
	v.attribute_path == ["metadata_options", 0, "http_tokens"]
}

test_passes_when_tokens_required if {
	inp := {"resources": [instance({"metadata_options": [{"http_tokens": "required"}]})]}
	count(imdsv2_required.deny) == 0 with input as inp
}

test_passes_when_account_default_requires_tokens if {
	inp := {"resources": [instance({}), account_defaults("required")]}
	count(imdsv2_required.deny) == 0 with input as inp
}

test_fails_when_account_default_has_no_preference if {
	inp := {"resources": [instance({}), account_defaults("no-preference")]}
	count(imdsv2_required.deny) == 1 with input as inp
}

test_instance_setting_overrides_account_default if {
	inp := {"resources": [
		instance({"metadata_options": [{"http_tokens": "optional"}]}),
		account_defaults("required"),
	]}
	count(imdsv2_required.deny) == 1 with input as inp
}

test_skips_unknown_tokens if {
	inp := {"resources": [resource(
		"aws_instance", "aws_instance.web",
		{"metadata_options": [{"http_tokens": null}]},
		[["metadata_options", 0, "http_tokens"]],
	)]}
	count(imdsv2_required.deny) == 0 with input as inp
}

test_skips_unknown_parent_block if {
	unknown_block := resource(
		"aws_instance", "aws_instance.web",
		{"metadata_options": null},
		[["metadata_options"]],
	)
	count(imdsv2_required.deny) == 0 with input as {"resources": [unknown_block]}
}

test_ignores_data_sources if {
	ds := object.union(instance({}), {"mode": "data"})
	count(imdsv2_required.deny) == 0 with input as {"resources": [ds]}
}

# A .tf.json block written as one object (ADR 0006) answers the same paths.
test_single_object_block_requiring_tokens_passes if {
	inst := {
		"address": "aws_instance.json", "type": "aws_instance", "mode": "managed",
		"values": {"metadata_options": {"http_tokens": "required"}}, "unknown": [],
	}
	count(imdsv2_required.deny) == 0 with input as {"resources": [inst]}
}

test_single_object_block_allowing_imdsv1_is_denied if {
	inst := {
		"address": "aws_instance.json", "type": "aws_instance", "mode": "managed",
		"values": {"metadata_options": {"http_tokens": "optional"}}, "unknown": [],
	}
	count(imdsv2_required.deny) == 1 with input as {"resources": [inst]}
}

test_single_object_block_with_unknown_tokens_is_skipped if {
	inst := {
		"address": "aws_instance.json", "type": "aws_instance", "mode": "managed",
		"values": {"metadata_options": {"http_tokens": null}}, "unknown": [["metadata_options", "http_tokens"]],
	}
	count(imdsv2_required.deny) == 0 with input as {"resources": [inst]}
}
