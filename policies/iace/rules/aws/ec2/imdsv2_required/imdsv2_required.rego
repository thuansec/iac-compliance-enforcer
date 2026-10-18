# METADATA
# title: EC2 instances must require IMDSv2
# description: >-
#   IMDSv1 answers unauthenticated requests, so an SSRF bug in the workload can
#   steal the instance role's credentials. Requiring session tokens (IMDSv2) blocks this.
# scope: package
# related_resources:
#   - ref: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html
#     description: Configure the instance metadata options
# custom:
#   id: IACE-AWS-EC2-001
#   severity: high
#   csp: aws
#   service: ec2
#   resource_types: [aws_instance]
#   frameworks:
#     aws-securityhub: [EC2.8]
#   remediation: Add metadata_options { http_tokens = "required" } to the instance.
package iace.rules.aws.ec2.imdsv2_required

import data.iace.lib.tf

tokens_path := ["metadata_options", 0, "http_tokens"]

deny contains violation if {
	some r in tf.resources("aws_instance")
	not tf.is_unknown(r, tokens_path)
	not requires_tokens(r)
	violation := {
		"address": r.address,
		"attribute_path": tokens_path,
		"message": sprintf("%s allows IMDSv1: set metadata_options.http_tokens to \"required\"", [r.address]),
	}
}

requires_tokens(r) if tf.value_or(r, tokens_path, "") == "required"

# Unset on the instance: it inherits the account default, which this configuration
# may set with aws_ec2_instance_metadata_defaults. Without one, AWS may allow IMDSv1.
requires_tokens(r) if {
	tf.value_or(r, tokens_path, "") == ""
	account_default_requires_tokens
}

default account_default_requires_tokens := false

account_default_requires_tokens if {
	defaults := tf.resources("aws_ec2_instance_metadata_defaults")
	count(defaults) > 0
	every d in defaults {
		not tf.is_unknown(d, ["http_tokens"])
		tf.value_or(d, ["http_tokens"], "no-preference") == "required"
	}
}
