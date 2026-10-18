# METADATA
# title: S3 block public access settings must not be disabled
# description: >-
#   A public access block with a setting off lets bucket ACLs or policies make data public.
#   Every setting a declared block leaves false or unset (the provider default) is a gap.
# scope: package
# related_resources:
#   - ref: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
#     description: Blocking public access to your Amazon S3 storage
#   - ref: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html
#     description: Security Hub controls for Amazon S3 (S3.1, S3.8)
# custom:
#   id: IACE-AWS-S3-001
#   severity: high
#   csp: aws
#   service: s3
#   resource_types: [aws_s3_bucket_public_access_block, aws_s3_account_public_access_block]
#   frameworks:
#     aws-securityhub: [S3.1, S3.8]
#   remediation: Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.
package iace.rules.aws.s3.public_access_block

import data.iace.lib.tf

settings := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

resource_types := ["aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"]

# A bucket without a public access block is not flagged: AWS blocks public access on new
# buckets by default since April 2023 (iace-cloud-controls, IACE-AWS-S3-001).
deny contains violation if {
	some rtype in resource_types
	some r in tf.resources(rtype)
	some setting in settings
	not tf.is_unknown(r, [setting])

	# All four default to false on both resources (aws provider 5.x and 6.x). Terraform converts
	# the string "true" to the bool, so both forms enable a setting.
	not tf.value_or(r, [setting], false) in {true, "true"}
	violation := {
		"address": r.address,
		"attribute_path": [setting],
		"message": sprintf("%s does not enable %s", [r.address, setting]),
	}
}
