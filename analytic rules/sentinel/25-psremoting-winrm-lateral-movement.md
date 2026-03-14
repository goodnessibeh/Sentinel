**Author:** Goodness Caleb Ibeh

# PSRemoting / WinRM Lateral Movement

This detection identifies processes spawned by the Windows Remote Management (WinRM) host process (wsmprovhost.exe), which indicates remote command execution via PowerShell Remoting. PSRemoting is a powerful legitimate administration tool, but it is also heavily abused by attackers for fileless lateral movement because commands execute entirely in memory on the target host. The query filters out normal WinRM child processes to surface suspicious activity.

**Importance:** A SOC analyst should investigate because PSRemoting-based lateral movement is fileless and leaves minimal disk artifacts, making it a preferred technique for sophisticated attackers.

**MITRE:** T1021.006 — Remote Services: Windows Remote Management

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
DeviceProcessEvents
// 24-hour lookback for WinRM-spawned processes
| where TimeGenerated > ago(24h)
// Key filter: process was spawned by the WinRM host process
| where InitiatingProcessFileName =~ "wsmprovhost.exe"  // WinRM host process
// Exclude expected WinRM child processes
| where FileName !in~ ("wsmprovhost.exe", "conhost.exe")
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
// Aggregate to summarize remote execution activity per host
| summarize
    CommandCount = count(),
    Processes = make_set(FileName, 10),
    Commands = make_set(ProcessCommandLine, 10)
  by DeviceName, AccountName, bin(TimeGenerated, 1h)
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 25a6b7c8-d9e0-4f1a-2b3c-4d5e6f7a8b95
name: "PSRemoting / WinRM Lateral Movement"
description: |
  This detection identifies processes spawned by the Windows Remote Management (WinRM) host process (wsmprovhost.exe), which indicates remote command execution via PowerShell Remoting. PSRemoting is a powerful legitimate administration tool, but it is also heavily abused by attackers for fileless lateral movement.
  A SOC analyst should investigate because PSRemoting-based lateral movement is fileless and leaves minimal disk artifacts, making it a preferred technique for sophisticated attackers.
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
  - LateralMovement
relevantTechniques:
  - T1021.006
query: |
  DeviceProcessEvents
  // 24-hour lookback for WinRM-spawned processes
  | where TimeGenerated > ago(24h)
  // Key filter: process was spawned by the WinRM host process
  | where InitiatingProcessFileName =~ "wsmprovhost.exe"  // WinRM host process
  // Exclude expected WinRM child processes
  | where FileName !in~ ("wsmprovhost.exe", "conhost.exe")
  | project TimeGenerated, DeviceName, AccountName, FileName,
            ProcessCommandLine, InitiatingProcessCommandLine
  // Aggregate to summarize remote execution activity per host
  | summarize
      CommandCount = count(),
      Processes = make_set(FileName, 10),
      Commands = make_set(ProcessCommandLine, 10)
    by DeviceName, AccountName, bin(TimeGenerated, 1h)
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
version: 1.0.0
kind: Scheduled
```
