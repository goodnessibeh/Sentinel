**Author:** Goodness Caleb Ibeh

# Critical Service Stopped

This detection identifies attempts to stop critical Windows services such as security tools, databases, backup systems, and management infrastructure. Stopping critical services is a common precursor to ransomware deployment (to prevent backup recovery) and a defense evasion technique (to disable security monitoring). The query monitors for service stop commands targeting a curated list of high-value services.

**Importance:** A SOC analyst should respond urgently because stopping critical services — especially security and backup services — is a hallmark of ransomware operators preparing to encrypt the environment.

**MITRE:** T1489 — Service Stop

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Define the list of critical services to monitor
let CriticalServices = dynamic([
    "WinDefend", "MpsSvc", "wscsvc", "Sense",      // Security
    "MSSQLSERVER", "SQLSERVERAGENT",                  // Database
    "VSS", "wbengine", "SamSs",                       // Backup/Recovery
    "EventLog", "Winmgmt",                             // Management
    "W3SVC", "WAS"                                     // Web
]);
DeviceProcessEvents
// 24-hour lookback for service stop commands
| where TimeGenerated > ago(24h)
// Filter for tools commonly used to stop services
| where FileName in~ ("net.exe", "net1.exe", "sc.exe", "taskkill.exe")
// Key filter: detect stop or force-kill commands
| where ProcessCommandLine has "stop" or ProcessCommandLine has "/f"
// Extract the service name from the command line
| extend StoppedService = extract("(?:stop|/f)\\s+[\"']?(\\S+)", 1, ProcessCommandLine)
// Only alert on critical services, not routine service management
| where StoppedService in~ (CriticalServices)
| extend
    AlertTitle = "Critical Service Stopped",
    AlertDescription = "This detection identifies attempts to stop critical Windows services such as security tools, databases, backup systems, and management infrastructure.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, AccountName, FileName,
          StoppedService, ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 35e6f7a8-b9c0-4d1e-2f3a-4b5c6d7e8f55
name: "Critical Service Stopped"
description: |
  This detection identifies attempts to stop critical Windows services such as security tools, databases, backup systems, and management infrastructure. Stopping critical services is a common precursor to ransomware deployment and a defense evasion technique.
  A SOC analyst should respond urgently because stopping critical services — especially security and backup services — is a hallmark of ransomware operators preparing to encrypt the environment.
severity: High
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
  - Impact
relevantTechniques:
  - T1489
query: |
  // Define the list of critical services to monitor
  let CriticalServices = dynamic([
      "WinDefend", "MpsSvc", "wscsvc", "Sense",      // Security
      "MSSQLSERVER", "SQLSERVERAGENT",                  // Database
      "VSS", "wbengine", "SamSs",                       // Backup/Recovery
      "EventLog", "Winmgmt",                             // Management
      "W3SVC", "WAS"                                     // Web
  ]);
  DeviceProcessEvents
  // 24-hour lookback for service stop commands
  | where TimeGenerated > ago(24h)
  // Filter for tools commonly used to stop services
  | where FileName in~ ("net.exe", "net1.exe", "sc.exe", "taskkill.exe")
  // Key filter: detect stop or force-kill commands
  | where ProcessCommandLine has "stop" or ProcessCommandLine has "/f"
  // Extract the service name from the command line
  | extend StoppedService = extract("(?:stop|/f)\\s+[\"']?(\\S+)", 1, ProcessCommandLine)
  // Only alert on critical services, not routine service management
  | where StoppedService in~ (CriticalServices)
  | extend
      AlertTitle = "Critical Service Stopped",
      AlertDescription = "This detection identifies attempts to stop critical Windows services such as security tools, databases, backup systems, and management infrastructure.",
      AlertSeverity = "High"
  | project TimeGenerated, DeviceName, AccountName, FileName,
            StoppedService, ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
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
