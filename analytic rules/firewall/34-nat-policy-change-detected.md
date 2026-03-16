**Author:** Goodness Caleb Ibeh

# NAT Policy Change Detected

Detects changes to NAT configurations including SNAT, DNAT, virtual IPs, IP pools, and central NAT policies. NAT policy changes can expose internal services to the internet, redirect traffic to attacker-controlled hosts, or create hidden access paths that bypass firewall inspection. An attacker modifying NAT rules can effectively create a backdoor that maps an external IP directly to an internal resource.

**Importance:** NAT policy modifications can silently expose internal services to the internet or redirect traffic to attacker-controlled infrastructure, creating persistent backdoor access.

**MITRE:** T1562 — Impair Defenses
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Event Log Trigger — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match NAT-related configuration changes
| where Message has_any (
    "central-nat", "nat", "snat", "dnat",
    "virtual-ip", "vip", "ip-pool",
    "nat-policy", "nat46", "nat64"
  )
| extend
    AlertTitle = "NAT Policy Change Detected",
    AlertDescription = "NAT configuration change detected, which can silently expose internal services to the internet or redirect traffic to attacker-controlled infrastructure.",
    AlertSeverity = "Medium"
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d8f4c1d5-7b9e-4d2a-e0a6-4b5c8d1e3f2a
name: "NAT Policy Change Detected"
description: |
  Detects changes to NAT configurations including SNAT, DNAT, virtual IPs, IP pools, and central NAT policies. NAT policy modifications can silently expose internal services to the internet or redirect traffic to attacker-controlled infrastructure, creating persistent backdoor access. Designed for Fortinet FortiGate firewalls.
severity: Medium
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
  - T1562
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries
  | where Activity has "system"
  // Key filter: match NAT-related configuration changes
  | where Message has_any (
      "central-nat", "nat", "snat", "dnat",
      "virtual-ip", "vip", "ip-pool",
      "nat-policy", "nat46", "nat64"
    )
  | extend
      AlertTitle = "NAT Policy Change Detected",
      AlertDescription = "NAT configuration change detected, which can silently expose internal services to the internet or redirect traffic to attacker-controlled infrastructure.",
      AlertSeverity = "Medium"
  | project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
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
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
- **Firewall Policies:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/954635/firewall-policies
