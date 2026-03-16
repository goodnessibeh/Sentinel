**Author:** Goodness Caleb Ibeh

# Registry Run Key Persistence

This detection monitors for modifications to Windows Registry Run keys, which are one of the oldest and most commonly used persistence mechanisms. When a value is added to a Run key, the associated program executes automatically every time the user logs in. Attackers use this to ensure their malware or backdoor survives system reboots.

**Importance:** A SOC analyst should investigate because Registry Run key modifications are a classic persistence technique that allows malware to automatically execute on every user logon.

**MITRE:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Define the registry paths commonly abused for persistence
let RunKeyPaths = dynamic([
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    @"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
]);
DeviceRegistryEvents
// 24-hour lookback for registry modifications
| where TimeGenerated > ago(24h)
// Filter for registry value set operations only
| where ActionType == "RegistryValueSet"
// Key filter: only Run key paths that enable auto-start persistence
| where RegistryKey has_any (RunKeyPaths)
| extend
    AlertTitle = "Registry Run Key Persistence",
    AlertDescription = "This detection monitors for modifications to Windows Registry Run keys, which are one of the oldest and most commonly used persistence mechanisms.",
    AlertSeverity = "Medium"
| project TimeGenerated, DeviceName, AccountName,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 11e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f7
name: "Registry Run Key Persistence"
description: |
  This detection monitors for modifications to Windows Registry Run keys, which are one of the oldest and most commonly used persistence mechanisms. When a value is added to a Run key, the associated program executes automatically every time the user logs in.
  A SOC analyst should investigate because Registry Run key modifications are a classic persistence technique that allows malware to automatically execute on every user logon.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceRegistryEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1547.001
query: |
  // Define the registry paths commonly abused for persistence
  let RunKeyPaths = dynamic([
      @"\Software\Microsoft\Windows\CurrentVersion\Run",
      @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
      @"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
      @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
      @"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
  ]);
  DeviceRegistryEvents
  // 24-hour lookback for registry modifications
  | where TimeGenerated > ago(24h)
  // Filter for registry value set operations only
  | where ActionType == "RegistryValueSet"
  // Key filter: only Run key paths that enable auto-start persistence
  | where RegistryKey has_any (RunKeyPaths)
  | extend
      AlertTitle = "Registry Run Key Persistence",
      AlertDescription = "This detection monitors for modifications to Windows Registry Run keys, which are one of the oldest and most commonly used persistence mechanisms.",
      AlertSeverity = "Medium"
  | project TimeGenerated, DeviceName, AccountName,
            RegistryKey, RegistryValueName, RegistryValueData,
            InitiatingProcessFileName, InitiatingProcessCommandLine, AlertTitle, AlertDescription, AlertSeverity
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
