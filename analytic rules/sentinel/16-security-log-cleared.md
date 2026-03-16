**Author:** Goodness Caleb Ibeh

# Security Log Cleared

This detection identifies when Windows Security event logs are cleared, either through the Event Log service (Event ID 1102) or via the wevtutil command-line tool. Clearing security logs is a hallmark of attackers attempting to cover their tracks after performing malicious actions. This is almost never done legitimately in production environments and should be treated as a strong indicator of compromise.

**Importance:** A SOC analyst should treat this as high priority because log clearing is a deliberate anti-forensic technique — an attacker is actively trying to destroy evidence of their activity.

**MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | SubjectAccount |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for log clearing events
| where TimeGenerated > ago(24h)
// Event ID 1102 = The audit log was cleared
| where EventID == 1102
| project TimeGenerated, Computer, SubjectAccount = Account, Activity
| union (
    // Also detect command-line log clearing via wevtutil
    DeviceProcessEvents
    | where TimeGenerated > ago(24h)
    // Filter for wevtutil.exe usage
    | where FileName =~ "wevtutil.exe"
    // Key filter: detect clear-log commands
    | where ProcessCommandLine has_any ("cl", "clear-log")
| extend
    AlertTitle = "Security Log Cleared",
    AlertDescription = "This detection identifies when Windows Security event logs are cleared, either through the Event Log service (Event ID 1102) or via the wevtutil command-line tool.",
    AlertSeverity = "High"
    | project TimeGenerated, Computer = DeviceName, SubjectAccount = AccountName,
              Activity = strcat("wevtutil ", ProcessCommandLine)
), AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 16d7e8f9-a0b1-4c2d-3e4f-5a6b7c8d9e0c
name: "Security Log Cleared"
description: |
  This detection identifies when Windows Security event logs are cleared, either through the Event Log service (Event ID 1102) or via the wevtutil command-line tool. Clearing security logs is a hallmark of attackers attempting to cover their tracks after performing malicious actions.
  A SOC analyst should treat this as high priority because log clearing is a deliberate anti-forensic technique — an attacker is actively trying to destroy evidence of their activity.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1070.001
query: |
  SecurityEvent
  // 24-hour lookback for log clearing events
  | where TimeGenerated > ago(24h)
  // Event ID 1102 = The audit log was cleared
  | where EventID == 1102
  | project TimeGenerated, Computer, SubjectAccount = Account, Activity
  | union (
      // Also detect command-line log clearing via wevtutil
      DeviceProcessEvents
      | where TimeGenerated > ago(24h)
      // Filter for wevtutil.exe usage
      | where FileName =~ "wevtutil.exe"
      // Key filter: detect clear-log commands
      | where ProcessCommandLine has_any ("cl", "clear-log")
  | extend
      AlertTitle = "Security Log Cleared",
      AlertDescription = "This detection identifies when Windows Security event logs are cleared, either through the Event Log service (Event ID 1102) or via the wevtutil command-line tool.",
      AlertSeverity = "High"
      | project TimeGenerated, Computer = DeviceName, SubjectAccount = AccountName,
                Activity = strcat("wevtutil ", ProcessCommandLine)
  ), AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: SubjectAccount
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: Computer
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
