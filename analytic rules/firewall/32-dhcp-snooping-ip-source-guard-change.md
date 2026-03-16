**Author:** Goodness Caleb Ibeh

# DHCP Snooping / IP Source Guard Configuration Change

Detects changes to DHCP snooping, IP source guard, ARP inspection, or DHCP server/relay configurations. These Layer 2/3 security features prevent IP spoofing, DHCP starvation, and ARP poisoning attacks. Disabling or weakening these features could allow an attacker to perform man-in-the-middle attacks, hijack IP addresses, or disrupt network connectivity. Changes to these settings are security-critical and should be closely monitored.

**Importance:** Weakening DHCP snooping or ARP inspection opens the door to man-in-the-middle and IP spoofing attacks that can compromise entire network segments without generating traditional alerts.

**MITRE:** T1562 — Impair Defenses
**Severity:** High

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
// Key filter: match DHCP snooping, IP source guard, ARP inspection, and related config changes
| where Message has_any (
    "dhcp-snooping", "dhcp snooping",
    "ip-source-guard", "ip source guard",
    "arp-inspection", "arp inspection",
    "trusted", "untrusted",
    "dhcp server", "dhcp relay"
  )
| extend
    AlertTitle = "DHCP Snooping / IP Source Guard Configuration Change",
    AlertDescription = "Changes to DHCP snooping, IP source guard, or ARP inspection detected, which can enable man-in-the-middle and IP spoofing attacks.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b6d2a9b3-5f7c-4b0d-c8e4-2f3a6b9c1d0e
name: "DHCP Snooping / IP Source Guard Configuration Change"
description: |
  Detects changes to DHCP snooping, IP source guard, ARP inspection, or DHCP server/relay configurations. Weakening DHCP snooping or ARP inspection opens the door to man-in-the-middle and IP spoofing attacks that can compromise entire network segments. Designed for Fortinet FortiGate firewalls.
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
  // Key filter: match DHCP snooping, IP source guard, ARP inspection, and related config changes
  | where Message has_any (
      "dhcp-snooping", "dhcp snooping",
      "ip-source-guard", "ip source guard",
      "arp-inspection", "arp inspection",
      "trusted", "untrusted",
      "dhcp server", "dhcp relay"
    )
  | extend
      AlertTitle = "DHCP Snooping / IP Source Guard Configuration Change",
      AlertDescription = "Changes to DHCP snooping, IP source guard, or ARP inspection detected, which can enable man-in-the-middle and IP spoofing attacks.",
      AlertSeverity = "High"
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
- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
