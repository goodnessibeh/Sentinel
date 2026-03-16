**Author:** Goodness Caleb Ibeh

# Process Masquerading — Suspicious Process Path

This detection identifies critical Windows system processes (such as svchost.exe, lsass.exe, and csrss.exe) running from unexpected file paths. These processes should only ever run from specific system directories. When an attacker names their malware after a legitimate system process but places it in a different directory, it is a clear masquerading attempt designed to hide in plain sight.

**Importance:** A SOC analyst should investigate because a system process name running from a non-standard path is a near-certain indicator of malware masquerading as a trusted process.

**MITRE:** T1036.005 — Masquerading: Match Legitimate Name or Location

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Process | CommandLine | ProcessCommandLine |

```kql
// Define the legitimate paths for critical system processes
let SystemProcesses = datatable(ProcessName:string, LegitPaths:dynamic) [
    "svchost.exe",   dynamic([@"C:\Windows\System32\", @"C:\Windows\SysWOW64\"]),
    "lsass.exe",     dynamic([@"C:\Windows\System32\"]),
    "csrss.exe",     dynamic([@"C:\Windows\System32\"]),
    "services.exe",  dynamic([@"C:\Windows\System32\"]),
    "smss.exe",      dynamic([@"C:\Windows\System32\"]),
    "winlogon.exe",  dynamic([@"C:\Windows\System32\"]),
    "taskhost.exe",  dynamic([@"C:\Windows\System32\"]),
    "explorer.exe",  dynamic([@"C:\Windows\", @"C:\Windows\SysWOW64\"])
];
DeviceProcessEvents
// 24-hour lookback for process execution
| where TimeGenerated > ago(24h)
// Filter for processes using critical system process names
| where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                       "smss.exe", "winlogon.exe", "taskhost.exe", "explorer.exe")
// Join with legitimate paths to compare
| join kind=inner (SystemProcesses) on $left.FileName == $right.ProcessName
// Key filter: flag processes NOT running from their legitimate paths
| where not(FolderPath has_any (LegitPaths))
| extend
    AlertTitle = "Process Masquerading — Suspicious Process Path",
    AlertDescription = "This detection identifies critical Windows system processes running from unexpected file paths.",
    AlertSeverity = "Medium"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 18f9a0b1-c2d3-4e4f-5a6b-7c8d9e0f1a2e
name: "Process Masquerading — Suspicious Process Path"
description: |
  This detection identifies critical Windows system processes running from unexpected file paths. These processes should only ever run from specific system directories. When an attacker names their malware after a legitimate system process but places it in a different directory, it is a clear masquerading attempt.
  A SOC analyst should investigate because a system process name running from a non-standard path is a near-certain indicator of malware masquerading as a trusted process.
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
  - DefenseEvasion
relevantTechniques:
  - T1036.005
query: |
  // Define the legitimate paths for critical system processes
  let SystemProcesses = datatable(ProcessName:string, LegitPaths:dynamic) [
      "svchost.exe",   dynamic([@"C:\Windows\System32\", @"C:\Windows\SysWOW64\"]),
      "lsass.exe",     dynamic([@"C:\Windows\System32\"]),
      "csrss.exe",     dynamic([@"C:\Windows\System32\"]),
      "services.exe",  dynamic([@"C:\Windows\System32\"]),
      "smss.exe",      dynamic([@"C:\Windows\System32\"]),
      "winlogon.exe",  dynamic([@"C:\Windows\System32\"]),
      "taskhost.exe",  dynamic([@"C:\Windows\System32\"]),
      "explorer.exe",  dynamic([@"C:\Windows\", @"C:\Windows\SysWOW64\"])
  ];
  DeviceProcessEvents
  // 24-hour lookback for process execution
  | where TimeGenerated > ago(24h)
  // Filter for processes using critical system process names
  | where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                         "smss.exe", "winlogon.exe", "taskhost.exe", "explorer.exe")
  // Join with legitimate paths to compare
  | join kind=inner (SystemProcesses) on $left.FileName == $right.ProcessName
  // Key filter: flag processes NOT running from their legitimate paths
  | where not(FolderPath has_any (LegitPaths))
  | extend
      AlertTitle = "Process Masquerading — Suspicious Process Path",
      AlertDescription = "This detection identifies critical Windows system processes running from unexpected file paths.",
      AlertSeverity = "Medium"
  | project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
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
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: ProcessCommandLine
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
