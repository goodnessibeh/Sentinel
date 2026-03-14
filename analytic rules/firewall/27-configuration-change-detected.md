**Author:** Goodness Caleb Ibeh

# Configuration Change Detected

Detects any configuration change event on FortiGate devices. Every configuration change should be tracked for audit purposes, and unexpected changes — especially outside maintenance windows or by unfamiliar admin accounts — can indicate an attacker who has gained admin access and is modifying security policies to facilitate their attack. Configuration change monitoring is also a compliance requirement under most security frameworks.

**Importance:** Unauthorized configuration changes can silently disable security controls, open backdoor access, or weaken policies, making change tracking essential for both security and compliance.

**MITRE:** T1562 — Impair Defenses
**Severity:** Medium

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
// Key filter: FortiGate event ID for configuration changes
| where DeviceEventClassID in ("32102", "0100032102")
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: c1e7b4c8-0f2a-4a5d-d3e9-7f8a1b4c6d5e
name: "Configuration Change Detected"
description: |
  Detects any configuration change event on FortiGate devices. Unauthorized configuration changes can silently disable security controls, open backdoor access, or weaken policies, making change tracking essential for both security and compliance. Designed for Fortinet FortiGate firewalls.
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
  // Key filter: FortiGate event ID for configuration changes
  | where DeviceEventClassID in ("32102", "0100032102")
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
- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
