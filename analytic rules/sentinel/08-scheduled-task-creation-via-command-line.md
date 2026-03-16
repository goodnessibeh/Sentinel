**Author:** Goodness Caleb Ibeh

# Scheduled Task Creation via Command Line

This detection identifies the creation of scheduled tasks via the command line using schtasks.exe. Adversaries commonly create scheduled tasks for persistence, privilege escalation, or delayed execution of malicious payloads. While scheduled tasks have legitimate uses, creation via command line (especially from unusual parent processes) warrants investigation.

**Importance:** A SOC analyst should investigate because command-line scheduled task creation is a primary persistence mechanism that attackers use to survive reboots and maintain access.

**MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
DeviceProcessEvents
// 24-hour lookback for scheduled task creation
| where TimeGenerated > ago(24h)
// Filter for schtasks.exe execution
| where FileName =~ "schtasks.exe"
// Key filter: only task creation, not queries or deletions
| where ProcessCommandLine has "/create"
// Parse out the task name and command for analyst review
| parse ProcessCommandLine with * "/tn " TaskName " " *
| parse ProcessCommandLine with * "/tr " TaskCommand " " *
| extend
    AlertTitle = "Scheduled Task Creation via Command Line",
    AlertDescription = "This detection identifies the creation of scheduled tasks via the command line using schtasks.exe.",
    AlertSeverity = "Medium"
| project TimeGenerated, DeviceName, AccountName, TaskName, TaskCommand,
          ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 08b9c0d1-e2f3-4a4b-5c6d-7e8f90a1b2c4
name: "Scheduled Task Creation via Command Line"
description: |
  This detection identifies the creation of scheduled tasks via the command line using schtasks.exe. Adversaries commonly create scheduled tasks for persistence, privilege escalation, or delayed execution of malicious payloads.
  A SOC analyst should investigate because command-line scheduled task creation is a primary persistence mechanism that attackers use to survive reboots and maintain access.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1053.005
query: |
  DeviceProcessEvents
  // 24-hour lookback for scheduled task creation
  | where TimeGenerated > ago(24h)
  // Filter for schtasks.exe execution
  | where FileName =~ "schtasks.exe"
  // Key filter: only task creation, not queries or deletions
  | where ProcessCommandLine has "/create"
  // Parse out the task name and command for analyst review
  | parse ProcessCommandLine with * "/tn " TaskName " " *
  | parse ProcessCommandLine with * "/tr " TaskCommand " " *
  | extend
      AlertTitle = "Scheduled Task Creation via Command Line",
      AlertDescription = "This detection identifies the creation of scheduled tasks via the command line using schtasks.exe.",
      AlertSeverity = "Medium"
  | project TimeGenerated, DeviceName, AccountName, TaskName, TaskCommand,
            ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
