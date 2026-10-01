# Azure control catalog

Defaults were checked against the azurerm docs at **4.81.0** (last 4.x) and **5.7.0** on
2026-10-01. MCSB mappings are candidates and must be confirmed against the Microsoft cloud security
benchmark pages before being added to metadata (see frameworks.md). Items marked `(verify)` need
checking.

## Renames and default changes that rules must handle (4.x → 5.x)
| resource | 4.x | 5.x |
|---|---|---|
| `azurerm_storage_account` | `allow_nested_items_to_be_public` default **true** | default **false** |
| `azurerm_storage_account` | `min_tls_version` accepts TLS1_0/1_1/1_2 (default TLS1_2) | only `TLS1_2` |
| `azurerm_storage_account` | `public_network_access_enabled` (bool, default true) | `public_network_access` (`Enabled`/`Disabled`/`SecuredByPerimeter`, default `Enabled`) |
| `azurerm_key_vault` | `rbac_authorization_enabled` optional, default false (`enable_rbac_authorization` deprecated) | `rbac_authorization_enabled` **required**; old name removed |
| `azurerm_mssql_server` | `minimum_tls_version` ∈ 1.0/1.1/1.2/Disabled (default 1.2) | only `1.2` |
| several (mysql flexible, logic app, …) | `public_network_access_enabled` | `public_network_access` |

Rules read both forms and pick the default by `tf.provider_major(r)`. With an unknown provider
version, assume **4.x** (the conservative, older defaults).

## P1 (M2 / M7)

### IACE-AZURE-STORAGE-001 · Storage accounts must require TLS 1.2 (P1 · medium) — M2
- resources: `azurerm_storage_account.min_tls_version`
- check: explicit `TLS1_0` or `TLS1_1` (only possible on 4.x); absent ⇒ `TLS1_2` on both majors ⇒ compliant
- MCSB candidate: DP-3

### IACE-AZURE-STORAGE-002 · Storage accounts must accept HTTPS only (P1 · medium)
- resources: `azurerm_storage_account.https_traffic_only_enabled` (3.x name `enable_https_traffic_only` is not supported)
- check: explicit `false`. Absent ⇒ default `true` (verify the wording on both majors)
- MCSB candidate: DP-3

### IACE-AZURE-STORAGE-003 · No anonymous blob access (P1 · high)
- resources: `azurerm_storage_account.allow_nested_items_to_be_public`; `azurerm_storage_container.container_access_type`
- check: account allows nested public items (explicit `true`, **or absent on 4.x / unknown version**),
  or any container with `container_access_type` ∈ {`blob`, `container`} (default `private`)
  linked to the account (by `storage_account_id`, or by the 4.x `storage_account_name` (verify per major))
- MCSB candidate: NS-2 / DP-? (verify)

### IACE-AZURE-KV-001 · Key Vault purge protection must be enabled (P1 · medium)
- resources: `azurerm_key_vault.purge_protection_enabled`
- defaults: optional bool with no stated default ⇒ `false` (verify); once enabled it cannot be disabled
- MCSB candidate: DP-8

### IACE-AZURE-KV-002 · Key Vault network access must be restricted (P1 · medium)
- resources: `azurerm_key_vault.public_network_access_enabled` (default `true` on 4.81 and 5.7), `network_acls[0].default_action`
- check: public access enabled **and** (`network_acls` absent, or `default_action = "Allow"`)
- MCSB candidate: NS-2

### IACE-AZURE-NET-001 · NSGs must not allow internet SSH/RDP (P1 · high)
- resources: inline `azurerm_network_security_group.security_rule[*]`; `azurerm_network_security_rule`
- check: `direction = "Inbound"`, `access = "Allow"`, `protocol` ∈ {`Tcp`, `*`}, a source
  (`source_address_prefix` or any of `source_address_prefixes`) ∈ {`*`, `0.0.0.0/0`, `0.0.0.0`,
  `Internet`, `Any`} (case-insensitive), and a destination port (`destination_port_range` or
  `destination_port_ranges`, values like `22`, `20-30`, `*`) covering 22 or 3389
- one violation per offending rule entry
- MCSB candidate: NS-1 / NS-2

### IACE-AZURE-NET-002 · NSGs must not allow internet ingress on all ports (P1 · high)
- same resources; check: internet source, inbound allow, and destination port `*` or `0-65535`

### IACE-AZURE-SQL-001 · SQL servers must require TLS 1.2 (P1 · medium)
- resources: `azurerm_mssql_server.minimum_tls_version`
- check: explicit `1.0`, `1.1` or `Disabled` (4.x only); absent ⇒ `1.2` ⇒ compliant
- MCSB candidate: DP-3

### IACE-AZURE-SQL-002 · SQL servers must disable public network access (P1 · medium)
- resources: `azurerm_mssql_server.public_network_access_enabled` (default `true` on 4.81 and 5.7)
- check: absent or `true` ⇒ violation; the message suggests private endpoints
- MCSB candidate: NS-2

### IACE-AZURE-SQL-003 · No allow-all SQL firewall rules (P1 · critical)
- resources: `azurerm_mssql_firewall_rule` (`start_ip_address`, `end_ip_address`)
- check: `0.0.0.0` to `255.255.255.255`. (The `0.0.0.0`–`0.0.0.0` "allow Azure services" rule
  is a separate P2 rule, because it admits other tenants' Azure resources.)
- MCSB candidate: NS-2

### IACE-AZURE-AKS-001 · AKS API server must not be open to the internet (P1 · high)
- resources: `azurerm_kubernetes_cluster.private_cluster_enabled`,
  `api_server_access_profile[0].authorized_ip_ranges`
- check: violation unless `private_cluster_enabled = true` or `authorized_ip_ranges` is non-empty
  and does not contain `0.0.0.0/0`
- MCSB candidate: NS-2

### IACE-AZURE-APP-001 · Web and function apps must require HTTPS (P1 · medium)
- resources: `azurerm_linux_web_app`, `azurerm_windows_web_app`, `azurerm_linux_function_app`,
  `azurerm_windows_function_app` (and `*_slot` variants), `https_only`
- defaults: `https_only` defaults to `false` (4.81 and 5.7), so absent ⇒ violation
- MCSB candidate: DP-3

### IACE-AZURE-APP-002 · Web and function apps must require TLS 1.2+ (P1 · medium)
- resources: same, `site_config[0].minimum_tls_version` (default `1.2`; allowed `1.0`–`1.3`)
- check: explicit `1.0` or `1.1`

### IACE-AZURE-VM-001 · Linux VMs must disable password authentication (P1 · high)
- resources: `azurerm_linux_virtual_machine.disable_password_authentication` (default `true`)
- check: explicit `false` (which is required whenever `admin_password` is set)
- MCSB candidate: IM-? (verify)

## P2 (next wave)
| ID | control | key resources / check |
|---|---|---|
| IACE-AZURE-STORAGE-004 | storage public network access restricted | `public_network_access_enabled` (4.x) / `public_network_access` (5.x), `network_rules[0].default_action` |
| IACE-AZURE-STORAGE-005 | shared key access disabled | `shared_access_key_enabled = false` |
| IACE-AZURE-KV-003 | Key Vault uses RBAC authorization | `rbac_authorization_enabled` (4.x default false) |
| IACE-AZURE-SQL-004 | "allow Azure services" firewall rule | `azurerm_mssql_firewall_rule` 0.0.0.0–0.0.0.0 |
| IACE-AZURE-SQL-005 | SQL auditing enabled | `azurerm_mssql_server_extended_auditing_policy` |
| IACE-AZURE-AKS-002 | AKS local accounts disabled | `local_account_disabled = true` |
| IACE-AZURE-AKS-003 | AKS RBAC enabled | `role_based_access_control_enabled` (default true; explicit false violates) |
| IACE-AZURE-APP-003 | FTP disabled | `site_config[0].ftps_state` ∈ {`Disabled`, `FtpsOnly`} (verify the default) |
| IACE-AZURE-PG-001 | PostgreSQL flexible server not public | `public_network_access_enabled` / `public_network_access` |

## P3 (candidates)
Defender for Cloud plans (`azurerm_security_center_subscription_pricing` tier `Standard`),
subscription activity-log diagnostic settings, VM encryption at host, Cosmos DB local auth
disabled and public access, Container Registry admin user disabled, Event Hub/Service Bus minimum
TLS, App Service remote debugging off, managed identities instead of credentials.
