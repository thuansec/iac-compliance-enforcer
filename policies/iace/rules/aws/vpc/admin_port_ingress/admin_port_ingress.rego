# METADATA
# title: Security groups must not open remote administration ports to the internet
# description: >-
#   SSH (22) and RDP (3389) reachable from any address invite credential brute-forcing and
#   exploitation of the remote access service.
# scope: package
# related_resources:
#   - ref: https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
#     description: Security group rules
#   - ref: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html
#     description: Security Hub controls for Amazon EC2 (EC2.13, EC2.14, EC2.53, EC2.54)
# custom:
#   id: IACE-AWS-VPC-001
#   severity: high
#   csp: aws
#   service: vpc
#   resource_types: [aws_security_group, aws_security_group_rule, aws_vpc_security_group_ingress_rule]
#   frameworks:
#     aws-securityhub: [EC2.13, EC2.14, EC2.53, EC2.54]
#   remediation: Limit the rule's source to known address ranges, or reach hosts through a bastion or Session Manager.
package iace.rules.aws.vpc.admin_port_ingress

import data.iace.lib.tf

admin_ports := {22, 3389}

internet := {"0.0.0.0/0", "::/0"}

# Protocols whose rules carry no ports, or carry ports that are not TCP/UDP services.
no_port_protocols := {"icmp", "1", "icmpv6", "58"}

# Inline ingress blocks of aws_security_group.
deny contains violation if {
	some r in tf.resources("aws_security_group")
	some i, _ in tf.blocks(r.values, "ingress")
	some attr in ["cidr_blocks", "ipv6_cidr_blocks"]
	open_to_internet(r, ["ingress", i, attr])
	covers_admin_port(r, ["ingress", i], "protocol")
	violation := finding(r, ["ingress", i, attr])
}

# Standalone aws_security_group_rule of type ingress.
deny contains violation if {
	some r in tf.resources("aws_security_group_rule")
	not tf.is_unknown(r, ["type"])
	tf.value_or(r, ["type"], "") == "ingress"
	some attr in ["cidr_blocks", "ipv6_cidr_blocks"]
	open_to_internet(r, [attr])
	covers_admin_port(r, [], "protocol")
	violation := finding(r, [attr])
}

# aws_vpc_security_group_ingress_rule holds one source per resource.
deny contains violation if {
	some r in tf.resources("aws_vpc_security_group_ingress_rule")
	some attr in ["cidr_ipv4", "cidr_ipv6"]
	not tf.is_unknown(r, [attr])
	tf.value_or(r, [attr], "") in internet
	covers_admin_port(r, [], "ip_protocol")
	violation := finding(r, [attr])
}

# A known source list containing an internet range. An unknown list, or an unknown element,
# is neither a violation nor a pass.
open_to_internet(r, path) if {
	not tf.is_unknown(r, path)
	some cidr in tf.value_or(r, path, [])
	cidr in internet
}

# The rule's protocol is all traffic (-1), or a port protocol whose range covers 22 or 3389.
# Every judged value must be known.
covers_admin_port(r, base, protocol_attr) if {
	not tf.is_unknown(r, array.concat(base, [protocol_attr]))
	lower(sprintf("%v", [tf.value_or(r, array.concat(base, [protocol_attr]), "")])) in {"-1", "all"}
}

covers_admin_port(r, base, protocol_attr) if {
	protocol_path := array.concat(base, [protocol_attr])
	not tf.is_unknown(r, protocol_path)
	not lower(sprintf("%v", [tf.value_or(r, protocol_path, "")])) in ({"-1", "all"} | no_port_protocols)
	from := port_value(r, array.concat(base, ["from_port"]))
	to := port_value(r, array.concat(base, ["to_port"]))
	some port in admin_ports
	from <= port
	port <= to
}

# A known port as a number. Terraform converts a quoted port ("22") through the provider schema,
# which iace does not have, so a string of digits counts as that number. Anything else is
# undefined: the entry is skipped, never passed by accident.
port_value(r, path) := n if {
	not tf.is_unknown(r, path)
	n := tf.value_or(r, path, null)
	is_number(n)
} else := to_number(s) if {
	not tf.is_unknown(r, path)
	s := tf.value_or(r, path, null)
	is_string(s)
	regex.match(`^-?[0-9]+$`, s)
}

finding(r, path) := {
	"address": r.address,
	"attribute_path": path,
	"message": sprintf("%s allows remote administration ports (SSH or RDP) from the internet", [r.address]),
}
