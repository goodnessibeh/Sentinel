**Author:** Goodness Caleb Ibeh

# Firmware Upgrade Event

Detects firmware upgrade or downgrade events on FortiGate devices. While firmware updates are routine, they should only occur during planned maintenance windows by authorized personnel. An unexpected firmware change could indicate a supply chain compromise, an attacker attempting to install a backdoored firmware, or a downgrade attack to reintroduce known vulnerabilities. Firmware downgrades are especially suspicious and should always be investigated.

**Importance:** Unexpected firmware changes — especially downgrades — can reintroduce known vulnerabilities or indicate a supply chain compromise, and must be validated against the change management record.

**MITRE:** T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain
**Severity:** Informational

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Event Log Trigger — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
let lookback = 7d;
CommonSecurityLog
// Filter to the last 7 days — firmware upgrades are infrequent events
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: look for firmware-related messages including upgrades and downgrades
| where Message has "firmware" and Message has_any ("upgraded", "upgrade", "downgrade")
| extend
    AlertTitle = "Firmware Upgrade Event",
    AlertDescription = "Firmware upgrade or downgrade detected on a FortiGate device, which must be validated against the change management record.",
    AlertSeverity = "Informational"
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP,
          Message, DeviceVersion, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d2f8c5d9-1a3b-4b6e-e4f0-8a9b2c5d7e6f
name: "Firmware Upgrade Event"
description: |
  Detects firmware upgrade or downgrade events on FortiGate devices. Unexpected firmware changes — especially downgrades — can reintroduce known vulnerabilities or indicate a supply chain compromise, and must be validated against the change management record. Designed for Fortinet FortiGate firewalls.
severity: Informational
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1d
queryPeriod: 7d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
relevantTechniques:
  - T1195.002
query: |
  let lookback = 7d;
  CommonSecurityLog
  // Filter to the last 7 days — firmware upgrades are infrequent events
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries
  | where Activity has "system"
  // Key filter: look for firmware-related messages including upgrades and downgrades
  | where Message has "firmware" and Message has_any ("upgraded", "upgrade", "downgrade")
  | extend
      AlertTitle = "Firmware Upgrade Event",
      AlertDescription = "Firmware upgrade or downgrade detected on a FortiGate device, which must be validated against the change management record.",
      AlertSeverity = "Informational"
  | project TimeGenerated, DeviceName, DestinationUserName, SourceIP,
            Message, DeviceVersion, AlertTitle, AlertDescription, AlertSeverity
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
  DeviceVersion: DeviceVersion
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
