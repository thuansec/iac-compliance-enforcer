package iace.rules.azure.storage.min_tls_version_test

import data.iace.rules.azure.storage.min_tls_version

account(values, unknown) := {
	"address": "azurerm_storage_account.data",
	"type": "azurerm_storage_account",
	"mode": "managed",
	"provider": "registry.terraform.io/hashicorp/azurerm",
	"values": values,
	"unknown": unknown,
	"references": {},
}

test_fails_on_tls_1_0 if {
	inp := {"resources": [account({"min_tls_version": "TLS1_0"}, [])]}
	count(min_tls_version.deny) == 1 with input as inp
	some v in min_tls_version.deny with input as inp
	v.attribute_path == ["min_tls_version"]
}

test_fails_on_tls_1_1 if {
	inp := {"resources": [account({"min_tls_version": "TLS1_1"}, [])]}
	count(min_tls_version.deny) == 1 with input as inp
}

test_passes_on_tls_1_2 if {
	inp := {"resources": [account({"min_tls_version": "TLS1_2"}, [])]}
	count(min_tls_version.deny) == 0 with input as inp
}

test_passes_when_absent if {
	inp := {"resources": [account({"name": "examplestorage"}, [])]}
	count(min_tls_version.deny) == 0 with input as inp
}

test_skips_unknown if {
	inp := {"resources": [account({"min_tls_version": null}, [["min_tls_version"]])]}
	count(min_tls_version.deny) == 0 with input as inp
}

test_ignores_data_sources if {
	data_account := object.union(account({"min_tls_version": "TLS1_0"}, []), {"mode": "data"})
	count(min_tls_version.deny) == 0 with input as {"resources": [data_account]}
}

# The unknown guard decides even when a weak placeholder value sits at the unknown path.
test_skips_unknown_with_a_placeholder_value if {
	inp := {"resources": [account({"min_tls_version": "TLS1_0"}, [["min_tls_version"]])]}
	count(min_tls_version.deny) == 0 with input as inp
}
