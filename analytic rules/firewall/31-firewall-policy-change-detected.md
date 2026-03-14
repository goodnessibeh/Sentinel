**Author:** Goodness Caleb Ibeh

# Firewall Policy Change Detected

Detects modifications to firewall policies including security policy changes, address object changes, service group modifications, and VIP or IP pool updates. Firewall policy changes are among the most security-sensitive configuration modifications — an attacker with admin access will modify policies to allow their traffic, disable inspection, or create backdoor access rules. All policy changes should be correlated against authorized change requests.

**Importance:** Unauthorized firewall policy changes can silently open network access paths for attackers, disable security inspection, or create persistent backdoor rules that survive other remediation efforts.

**MITRE:** T1562.004 — Impair Defenses: Disable or Modify System Firewall
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Log ID 0100032102 (Config Change) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/32102/32102
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Filter for configuration change event IDs
| where DeviceEventClassID in ("32102", "0100032102")
// Key filter: narrow to policy-related configuration changes
| where Message has_any ("policy", "firewall policy", "security policy",
    "address", "address-group", "service", "service-group",
    "schedule", "vip", "ip-pool", "central-nat")
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a5c1f8a2-4e6b-4a9c-b7d3-1e2f5a8b0c9d
name: "Firewall Policy Change Detected"
description: |
  Detects modifications to firewall policies including security policy changes, address object changes, service group modifications, and VIP or IP pool updates. Unauthorized firewall policy changes can silently open network access paths for attackers, disable security inspection, or create persistent backdoor rules. Designed for Fortinet FortiGate firewalls.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1562.004
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries
  | where Activity has "system"
  // Filter for configuration change event IDs
  | where DeviceEventClassID in ("32102", "0100032102")
  // Key filter: narrow to policy-related configuration changes
  | where Message has_any ("policy", "firewall policy", "security policy",
      "address", "address-group", "service", "service-group",
      "schedule", "vip", "ip-pool", "central-nat")
  | project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
  | order by TimeGenerated desc
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
version: 1.0.0
kind: Scheduled
```

## References

- **Config Change (Log ID 0100032102):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/32102/32102
- **Firewall Policies:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/954635/firewall-policies
- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
