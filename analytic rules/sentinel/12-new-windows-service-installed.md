**Author:** Goodness Caleb Ibeh

# New Windows Service Installed

This detection identifies the installation of new Windows services (Event ID 7045) where the service binary path references suspicious locations or known LOLBins. Attackers commonly install malicious services for persistence and privilege escalation because services run with SYSTEM-level privileges. Filtering on suspicious binary paths significantly reduces false positives from legitimate software installations.

**Importance:** A SOC analyst should investigate because a malicious Windows service provides SYSTEM-level persistent access — one of the most powerful persistence mechanisms available on Windows.

**MITRE:** T1543.003 — Create or Modify System Process: Windows Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for new service installations
| where TimeGenerated > ago(24h)
// Event ID 7045 = A new service was installed
| where EventID == 7045
| extend
    AlertTitle = "New Windows Service Installed",
    AlertDescription = "This detection identifies the installation of new Windows services (Event ID 7045) where the service binary path references suspicious locations or known LOLBins.",
    AlertSeverity = "Medium"
| project TimeGenerated, Computer, ServiceName = tostring(EventData.ServiceName),
          ServiceFileName = tostring(EventData.ImagePath),
          ServiceType = tostring(EventData.ServiceType),
          ServiceStartType = tostring(EventData.StartType),
          ServiceAccount = tostring(EventData.AccountName), AlertTitle, AlertDescription, AlertSeverity
// Key filter: only flag services with suspicious binary paths or LOLBin references
| where ServiceFileName has_any ("cmd", "powershell", "wscript", "cscript", "mshta",
          "\\Temp\\", "\\tmp\\", "\\AppData\\", "\\Users\\Public\\")
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 12f3a4b5-c6d7-4e8f-90a1-b2c3d4e5f6a8
name: "New Windows Service Installed"
description: |
  This detection identifies the installation of new Windows services (Event ID 7045) where the service binary path references suspicious locations or known LOLBins. Attackers commonly install malicious services for persistence and privilege escalation because services run with SYSTEM-level privileges.
  A SOC analyst should investigate because a malicious Windows service provides SYSTEM-level persistent access — one of the most powerful persistence mechanisms available on Windows.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1543.003
query: |
  SecurityEvent
  // 24-hour lookback for new service installations
  | where TimeGenerated > ago(24h)
  // Event ID 7045 = A new service was installed
  | where EventID == 7045
  | extend
      AlertTitle = "New Windows Service Installed",
      AlertDescription = "This detection identifies the installation of new Windows services (Event ID 7045) where the service binary path references suspicious locations or known LOLBins.",
      AlertSeverity = "Medium"
  | project TimeGenerated, Computer, ServiceName = tostring(EventData.ServiceName),
            ServiceFileName = tostring(EventData.ImagePath),
            ServiceType = tostring(EventData.ServiceType),
            ServiceStartType = tostring(EventData.StartType),
            ServiceAccount = tostring(EventData.AccountName), AlertTitle, AlertDescription, AlertSeverity
  // Key filter: only flag services with suspicious binary paths or LOLBin references
  | where ServiceFileName has_any ("cmd", "powershell", "wscript", "cscript", "mshta",
            "\\Temp\\", "\\tmp\\", "\\AppData\\", "\\Users\\Public\\")
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
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
