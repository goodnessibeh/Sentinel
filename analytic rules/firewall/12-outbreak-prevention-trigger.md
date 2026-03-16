**Author:** Goodness Caleb Ibeh

# Outbreak Prevention Trigger

Detects FortiGate outbreak prevention events, which fire when FortiGuard identifies a zero-day or rapidly spreading malware sample that has not yet received a full AV signature. Outbreak prevention uses heuristic and behavioral signatures pushed by FortiGuard in real-time to block emerging threats before traditional AV signatures are available. These events indicate your environment is being targeted by very recent or zero-day malware.

**Importance:** Outbreak prevention triggers indicate zero-day or emerging malware targeting your environment before traditional signatures exist, requiring immediate threat intelligence correlation and host investigation.

**MITRE:** T1204 — User Execution
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log ID 0204008202 (Outbreak Prevention) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/8202/8202
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for virus activity specifically related to outbreak prevention
| where Activity has "virus" and Activity has "outbreak"
| extend
    AlertTitle = "Outbreak Prevention Trigger",
    AlertDescription = "FortiGuard outbreak prevention event detected, indicating zero-day or rapidly spreading malware targeting the environment before traditional AV signatures are available.",
    AlertSeverity = "High"
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction,
          ApplicationProtocol, Message, DestinationUserName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f6b2d9c3-5e7a-4f0d-a8b4-2c3d6e9f1a0b
name: "Outbreak Prevention Trigger"
description: |
  Detects FortiGate outbreak prevention events, which fire when FortiGuard identifies a zero-day or rapidly spreading malware sample. Outbreak prevention triggers indicate zero-day or emerging malware targeting your environment before traditional signatures exist, requiring immediate threat intelligence correlation and host investigation. Designed for Fortinet FortiGate firewalls.
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
  - Execution
relevantTechniques:
  - T1204
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for virus activity specifically related to outbreak prevention
  | where Activity has "virus" and Activity has "outbreak"
  | extend
      AlertTitle = "Outbreak Prevention Trigger",
      AlertDescription = "FortiGuard outbreak prevention event detected, indicating zero-day or rapidly spreading malware targeting the environment before traditional AV signatures are available.",
      AlertSeverity = "High"
  | project TimeGenerated, SourceIP, DestinationIP, DeviceAction,
            ApplicationProtocol, Message, DestinationUserName, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  DeviceAction: DeviceAction
  ApplicationProtocol: ApplicationProtocol
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=virus):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Outbreak Prevention Log ID 0204008202:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/8202/8202
