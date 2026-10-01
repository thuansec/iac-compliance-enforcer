# AWS control catalog

Defaults were checked against the provider docs for **aws 6.67.0** on 2026-10-01, and
aws-securityhub IDs against the AWS Security Hub controls reference on the same day. Re-verify
anything marked `(verify)`, and verify the 5.x behaviour for every rule (the protocol is in SKILL.md).

## P1 (M2 / M6)

### IACE-AWS-EC2-001 · EC2 instances must require IMDSv2 (P1 · high) — template rule, done in M2
- resources: `aws_instance`; account default `aws_ec2_instance_metadata_defaults`
- check: `metadata_options[0].http_tokens == "required"`. When unset on the instance, it is
  compliant only if every `aws_ec2_instance_metadata_defaults` in the config sets `http_tokens = "required"`.
- defaults: instance: none in the provider (the AWS/AMI default may allow IMDSv1); account resource `"no-preference"`
- mappings: aws-securityhub EC2.8
- also consider (P2): `aws_launch_template.metadata_options`

### IACE-AWS-S3-001 · S3 block public access must not be disabled (P1 · high) — M2
- resources: `aws_s3_bucket_public_access_block` (per bucket), `aws_s3_account_public_access_block`
- check: violation for each of `block_public_acls`, `block_public_policy`, `ignore_public_acls`,
  `restrict_public_buckets` that is explicitly `false` or absent (provider default `false`) on a
  declared public-access-block resource. A bucket with no PAB resource is **not** flagged here,
  because since April 2023 AWS enables block public access on new buckets by default. Absence is
  a separate low-severity hygiene rule (S3-007, P3).
- defaults: all four default `false` on both resources, so declaring the resource without setting them is a violation
- mappings: aws-securityhub S3.1 (account level), S3.8 (bucket level)

### IACE-AWS-S3-002 · No public S3 bucket ACLs (P1 · critical)
- resources: `aws_s3_bucket_acl` (`acl`, `access_control_policy[0].grant[*].grantee[0].uri`);
  deprecated inline `aws_s3_bucket.acl` / `grant` (still present in 6.x)
- check: `acl` ∈ {`public-read`, `public-read-write`, `authenticated-read`}, or any grantee URI
  `http://acs.amazonaws.com/groups/global/AllUsers` or `.../AuthenticatedUsers`
- mappings: aws-securityhub S3.2 (read), S3.3 (write)

### IACE-AWS-EC2-002 · EBS volumes must be encrypted (P1 · medium)
- resources: `aws_ebs_volume.encrypted`; `aws_instance.root_block_device[0].encrypted`,
  `ebs_block_device[*].encrypted`; `aws_launch_template.block_device_mappings[*].ebs[0].encrypted`
  (a **string** `"true"`/`"false"` in launch templates (verify))
- check: not encrypted, unless an `aws_ebs_encryption_by_default` in the config has `enabled = true`
- defaults: `root_block_device.encrypted` defaults to `false`; `aws_ebs_encryption_by_default.enabled`
  defaults to `true` (so declaring the resource enables it)
- mappings: aws-securityhub EC2.3 (attached volumes), EC2.7 (default encryption, a separate P2 rule IACE-AWS-EC2-003)

### IACE-AWS-VPC-001 · No internet ingress to remote administration ports (P1 · high)
- resources: inline `aws_security_group.ingress[*]`; `aws_security_group_rule` with `type = "ingress"`;
  `aws_vpc_security_group_ingress_rule` (`cidr_ipv4`, `cidr_ipv6`, `from_port`, `to_port`, `ip_protocol`)
- check: a source of `0.0.0.0/0` or `::/0` (`cidr_blocks`, `ipv6_cidr_blocks`, `cidr_ipv4`, `cidr_ipv6`)
  **and** a port range covering 22 or 3389, where protocol `-1`/`all` means all ports. Emit one
  violation per offending rule entry, with its `attribute_path`.
- mappings: aws-securityhub EC2.13 (22), EC2.14 (3389), EC2.53 (IPv4 admin ports), EC2.54 (IPv6 admin ports)

### IACE-AWS-VPC-002 · No unrestricted ingress on all ports (P1 · high)
- resources: same as VPC-001
- check: internet source plus protocol `-1`, or the full range 0–65535
- mappings: aws-securityhub EC2.18, EC2.19 (verify which applies best; EC2.19 is "ports with high risk")

### IACE-AWS-RDS-001 · RDS storage must be encrypted (P1 · medium)
- resources: `aws_db_instance.storage_encrypted`; `aws_rds_cluster.storage_encrypted`
- defaults: instance `false`; cluster `false` for provisioned, `true` for `engine_mode = "serverless"` (v1);
  Serverless v2 `false`. Read replicas in another region use `kms_key_id` instead, so treat
  `replicate_source_db` set with `kms_key_id` as compliant.
- mappings: aws-securityhub RDS.3 (instances), RDS.27 (clusters)

### IACE-AWS-RDS-002 · RDS instances must not be publicly accessible (P1 · high)
- resources: `aws_db_instance.publicly_accessible` (and `aws_rds_cluster_instance.publicly_accessible`)
- defaults: `false`, so only an explicit `true` violates
- mappings: aws-securityhub RDS.2

### IACE-AWS-IAM-001 · No IAM policies granting full administrative access (P1 · critical)
- resources: policy JSON strings in `aws_iam_policy.policy`, `aws_iam_role_policy.policy`,
  `aws_iam_user_policy.policy`, `aws_iam_group_policy.policy`; data source
  `aws_iam_policy_document` (`statement[*]` blocks, mode `data`, which `tf.data_sources(type)` returns)
- check: a statement with `Effect` `Allow` (the default in policy documents), `Action` (string or
  list) containing `"*"`, and `Resource` containing `"*"`. Unknown JSON (unresolved template) is unknown.
- mappings: aws-securityhub IAM.1. A related P2 rule, IAM.21 (`service:*` wildcards), is a separate rule.

### IACE-AWS-KMS-001 · KMS key rotation must be enabled (P1 · medium)
- resources: `aws_kms_key.enable_key_rotation`
- check: only for symmetric encryption keys (`customer_master_key_spec` absent or `SYMMETRIC_DEFAULT`,
  and `key_usage` absent or `ENCRYPT_DECRYPT`); asymmetric and HMAC keys are exempt
- defaults: `enable_key_rotation` defaults to `false`
- mappings: aws-securityhub KMS.4

### IACE-AWS-CT-001 · CloudTrail log file validation must be enabled (P1 · medium)
- resources: `aws_cloudtrail.enable_log_file_validation`
- defaults: `false`
- mappings: aws-securityhub CloudTrail.4

### IACE-AWS-EKS-001 · EKS API endpoint must not be open to the internet (P1 · high)
- resources: `aws_eks_cluster.vpc_config[0].endpoint_public_access`, `.public_access_cidrs`
- check: public access enabled (default `true`) **and** `public_access_cidrs` contains `0.0.0.0/0`
  (EKS default `["0.0.0.0/0"]` when absent)
- mappings: aws-securityhub EKS.1

### IACE-AWS-ELB-001 · Application load balancers must use HTTPS (P1 · medium)
- resources: `aws_lb_listener` (with `aws_lb` `load_balancer_type` `application` or absent, which is ALB)
- check: `protocol` `HTTP` (the ALB default when absent) is compliant only if `default_action`
  is a `redirect` with `protocol = "HTTPS"`
- mappings: aws-securityhub ELB.1

### IACE-GEN-SECRETS-001 · No hardcoded secrets in sensitive arguments (P1 · high) — CSP-generic
- resources/attributes (known string literal ⇒ violation; unknown ⇒ skip):
  `aws_db_instance.password`, `aws_rds_cluster.master_password`, `aws_redshift_cluster.master_password`,
  `aws_docdb_cluster.master_password`, `aws_elasticache_replication_group.auth_token`,
  `aws_mq_broker.user[*].password`, `aws_secretsmanager_secret_version.secret_string`,
  `aws_ssm_parameter.value` (when `type = "SecureString"`), the `aws` provider's `access_key`/`secret_key`;
  `azurerm_linux_virtual_machine.admin_password`, `azurerm_windows_virtual_machine.admin_password`,
  `azurerm_mssql_server.administrator_login_password`, `azurerm_postgresql_flexible_server.administrator_password`,
  `azurerm_mysql_flexible_server.administrator_password`, `azurerm_key_vault_secret.value`, the `azurerm` provider's `client_secret`
- compliant alternatives: `manage_master_user_password = true` (RDS), values from variables
  without committed defaults or tfvars, `ephemeral`/write-only arguments (verify availability per version)
- the message must **never** include the value. A test asserts that fixture secrets appear in no output format.

## P2 (next wave)
| ID | control | key resources / check | mapping |
|---|---|---|---|
| IACE-AWS-S3-003 | buckets require TLS (`aws:SecureTransport` deny) | `aws_s3_bucket_policy.policy` JSON | S3.5 |
| IACE-AWS-EC2-003 | EBS encryption by default enabled | `aws_ebs_encryption_by_default` | EC2.7 |
| IACE-AWS-EC2-004 | instances without public IPv4 | `aws_instance.associate_public_ip_address` | EC2.9 |
| IACE-AWS-EC2-005 | launch templates require IMDSv2 | `aws_launch_template.metadata_options` | EC2.170 |
| IACE-AWS-VPC-003 | default SG allows nothing | `aws_default_security_group` ingress/egress empty | EC2.2 |
| IACE-AWS-VPC-004 | VPC flow logs enabled | `aws_flow_log` referencing each `aws_vpc` | EC2.6 |
| IACE-AWS-CT-002 | CloudTrail multi-region | `aws_cloudtrail.is_multi_region_trail` | CloudTrail.1 |
| IACE-AWS-CT-003 | CloudTrail encrypted with KMS | `aws_cloudtrail.kms_key_id` | CloudTrail.2 |
| IACE-AWS-EKS-002 | EKS secrets encryption | `encryption_config` with `resources = ["secrets"]` | EKS.3 |
| IACE-AWS-EKS-003 | EKS audit logging | `enabled_cluster_log_types` includes `audit` | EKS.8 |
| IACE-AWS-ELB-002 | modern TLS policy on listeners | `aws_lb_listener.ssl_policy` in allowlist | ELB.17 |
| IACE-AWS-IAM-002 | no service-wide wildcard actions | policy JSON `service:*` | IAM.21 |
| IACE-AWS-CF-001 | CloudFront requires HTTPS | `viewer_protocol_policy` ∈ {`redirect-to-https`, `https-only`} | CloudFront.3 |
| IACE-AWS-RDS-003 | RDS deletion protection | `deletion_protection` | RDS.7 / RDS.8 |

## P3 (candidates)
S3 versioning (S3.14), S3 access logging (S3.9), S3-007 "bucket declares an explicit public
access block", RDS IAM auth (RDS.10 / RDS.12), RDS backup retention, ALB drop invalid headers
(ELB.4), IAM password policy (IAM.7 / IAM.15), KMS keys not publicly accessible (KMS.5), SQS/SNS
encryption, DynamoDB PITR, ECR scan-on-push and immutable tags, Secrets Manager rotation.
