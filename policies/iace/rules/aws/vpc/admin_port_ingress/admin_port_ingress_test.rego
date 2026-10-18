package iace.rules.aws.vpc.admin_port_ingress_test

import data.iace.rules.aws.vpc.admin_port_ingress

res(rtype, values, unknown) := {
	"address": $"{rtype}.this",
	"type": rtype,
	"mode": "managed",
	"provider": "registry.terraform.io/hashicorp/aws",
	"values": values,
	"unknown": unknown,
	"references": {},
}

ingress(from, to, protocol, cidrs) := {"from_port": from, "to_port": to, "protocol": protocol, "cidr_blocks": cidrs}

sg(blocks) := res("aws_security_group", {"ingress": blocks}, [])

inp(r) := {"resources": [r]}

test_flags_ssh_open_to_ipv4_internet if {
	vs := admin_port_ingress.deny with input as inp(sg([ingress(22, 22, "tcp", ["0.0.0.0/0"])]))
	count(vs) == 1
	some v in vs
	v.attribute_path == ["ingress", 0, "cidr_blocks"]
}

test_flags_rdp_inside_a_range if {
	count(admin_port_ingress.deny) == 1 with input as inp(sg([ingress(3000, 4000, "tcp", ["0.0.0.0/0"])]))
}

test_flags_all_traffic if {
	count(admin_port_ingress.deny) == 1 with input as inp(sg([ingress(0, 0, "-1", ["0.0.0.0/0"])]))
}

test_flags_ipv6_internet if {
	block := {"from_port": 22, "to_port": 22, "protocol": "tcp", "ipv6_cidr_blocks": ["::/0"]}
	vs := admin_port_ingress.deny with input as inp(sg([block]))
	some v in vs
	v.attribute_path == ["ingress", 0, "ipv6_cidr_blocks"]
}

test_flags_the_offending_entry_only if {
	blocks := [ingress(443, 443, "tcp", ["0.0.0.0/0"]), ingress(22, 22, "tcp", ["0.0.0.0/0"])]
	vs := admin_port_ingress.deny with input as inp(sg(blocks))
	count(vs) == 1
	some v in vs
	v.attribute_path == ["ingress", 1, "cidr_blocks"]
}

test_passes_restricted_source if {
	count(admin_port_ingress.deny) == 0 with input as inp(sg([ingress(22, 22, "tcp", ["10.0.0.0/16"])]))
}

test_passes_other_ports if {
	count(admin_port_ingress.deny) == 0 with input as inp(sg([ingress(443, 443, "tcp", ["0.0.0.0/0"])]))
}

test_passes_icmp if {
	count(admin_port_ingress.deny) == 0 with input as inp(sg([ingress(-1, -1, "icmp", ["0.0.0.0/0"])]))
}

test_skips_unknown_cidrs if {
	r := res("aws_security_group", {"ingress": [ingress(22, 22, "tcp", null)]}, [["ingress", 0, "cidr_blocks"]])
	count(admin_port_ingress.deny) == 0 with input as inp(r)
}

test_skips_unknown_ports if {
	r := res("aws_security_group", {"ingress": [ingress(null, 22, "tcp", ["0.0.0.0/0"])]}, [["ingress", 0, "from_port"]])
	count(admin_port_ingress.deny) == 0 with input as inp(r)
}

test_skips_unknown_protocol if {
	r := res("aws_security_group", {"ingress": [ingress(22, 22, null, ["0.0.0.0/0"])]}, [["ingress", 0, "protocol"]])
	count(admin_port_ingress.deny) == 0 with input as inp(r)
}

test_reads_a_single_object_block if {
	count(admin_port_ingress.deny) == 1 with input as inp(sg(ingress(22, 22, "tcp", ["0.0.0.0/0"])))
}

test_flags_security_group_rule if {
	values := object.union(ingress(22, 22, "tcp", ["0.0.0.0/0"]), {"type": "ingress"})
	vs := admin_port_ingress.deny with input as inp(res("aws_security_group_rule", values, []))
	some v in vs
	v.attribute_path == ["cidr_blocks"]
}

test_ignores_egress_rules if {
	values := object.union(ingress(22, 22, "tcp", ["0.0.0.0/0"]), {"type": "egress"})
	count(admin_port_ingress.deny) == 0 with input as inp(res("aws_security_group_rule", values, []))
}

test_skips_unknown_rule_type if {
	values := object.union(ingress(22, 22, "tcp", ["0.0.0.0/0"]), {"type": null})
	count(admin_port_ingress.deny) == 0 with input as inp(res("aws_security_group_rule", values, [["type"]]))
}

test_flags_vpc_ingress_rule if {
	values := {"from_port": 3389, "to_port": 3389, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}
	vs := admin_port_ingress.deny with input as inp(res("aws_vpc_security_group_ingress_rule", values, []))
	some v in vs
	v.attribute_path == ["cidr_ipv4"]
}

test_flags_vpc_ingress_rule_all_traffic if {
	values := {"ip_protocol": "-1", "cidr_ipv6": "::/0"}
	count(admin_port_ingress.deny) == 1 with input as inp(res("aws_vpc_security_group_ingress_rule", values, []))
}

test_passes_vpc_ingress_rule_restricted if {
	values := {"from_port": 22, "to_port": 22, "ip_protocol": "tcp", "cidr_ipv4": "10.0.0.0/16"}
	count(admin_port_ingress.deny) == 0 with input as inp(res("aws_vpc_security_group_ingress_rule", values, []))
}

test_skips_unknown_vpc_cidr if {
	values := {"from_port": 22, "to_port": 22, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}
	r := res("aws_vpc_security_group_ingress_rule", values, [["cidr_ipv4"]])
	count(admin_port_ingress.deny) == 0 with input as inp(r)
}

test_numeric_protocol_all if {
	count(admin_port_ingress.deny) == 1 with input as inp(sg([ingress(0, 0, -1, ["0.0.0.0/0"])]))
}

test_flags_quoted_ports if {
	count(admin_port_ingress.deny) == 1 with input as inp(sg([ingress("22", "22", "tcp", ["0.0.0.0/0"])]))
}

test_flags_quoted_ports_on_vpc_ingress_rule if {
	values := {"from_port": "3389", "to_port": "3389", "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}
	count(admin_port_ingress.deny) == 1 with input as inp(res("aws_vpc_security_group_ingress_rule", values, []))
}

test_skips_non_numeric_ports if {
	count(admin_port_ingress.deny) == 0 with input as inp(sg([ingress("ssh", "ssh", "tcp", ["0.0.0.0/0"])]))
}

test_flags_protocol_all_in_any_case if {
	count(admin_port_ingress.deny) == 1 with input as inp(sg([ingress(0, 0, "ALL", ["0.0.0.0/0"])]))
}
