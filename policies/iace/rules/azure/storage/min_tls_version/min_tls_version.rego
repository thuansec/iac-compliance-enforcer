# METADATA
# title: Storage accounts must require TLS 1.2
# description: >-
#   Accepting TLS 1.0 or 1.1 lets clients reach the account's data over protocols with known
#   weaknesses that an attacker on the network path can downgrade to.
# scope: package
# related_resources:
#   - ref: https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version
#     description: Enforce a minimum required version of TLS for requests to a storage account
# custom:
#   id: IACE-AZURE-STORAGE-001
#   severity: medium
#   csp: azure
#   service: storage
#   resource_types: [azurerm_storage_account]
#   remediation: Set min_tls_version = "TLS1_2" (or remove the attribute; TLS1_2 is the default).
package iace.rules.azure.storage.min_tls_version

import data.iace.lib.tf

weak := {"TLS1_0", "TLS1_1"}

deny contains violation if {
	some r in tf.resources("azurerm_storage_account")
	not tf.is_unknown(r, ["min_tls_version"])

	# Absent means TLS1_2 on azurerm 4.x and 5.x (5.x accepts only TLS1_2), so only an explicit
	# older version is a violation.
	tf.value_or(r, ["min_tls_version"], "TLS1_2") in weak
	violation := {
		"address": r.address,
		"attribute_path": ["min_tls_version"],
		"message": sprintf("%s accepts TLS versions older than 1.2", [r.address]),
	}
}
