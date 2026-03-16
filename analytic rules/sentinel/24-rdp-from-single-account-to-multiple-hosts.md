**Author:** Goodness Caleb Ibeh

# RDP from Single Account to Multiple Hosts

This detection identifies a single user account establishing Remote Desktop Protocol sessions to multiple distinct hosts within a short timeframe. While administrators may legitimately RDP to several servers, an attacker with compromised credentials will rapidly pivot across many systems via RDP to expand their access. The number of distinct target hosts is the key detection signal.

**Importance:** A SOC analyst should investigate because a single account RDP-ing to many hosts in rapid succession is a strong indicator of credential-based lateral movement across the network.

**MITRE:** T1021.001 — Remote Services: Remote Desktop Protocol

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | AccountName |
| IP | Address | RemoteIP |

```kql
let threshold = 3;
DeviceLogonEvents
// 24-hour lookback for RDP sessions
| where TimeGenerated > ago(24h)
// Filter for Remote Desktop (RemoteInteractive) logon type
| where LogonType == "RemoteInteractive"
// Aggregate: count distinct target hosts per account and source IP
| summarize
    TargetCount = dcount(DeviceName),
    Targets = make_set(DeviceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by AccountName, RemoteIP
// Threshold: flag accounts connecting to 3+ distinct hosts
| where TargetCount >= threshold
| extend
    AlertTitle = "RDP from Single Account to Multiple Hosts",
    AlertDescription = "This detection identifies a single user account establishing Remote Desktop Protocol sessions to multiple distinct hosts within a short timeframe.",
    AlertSeverity = "Medium"
| project AccountName, RemoteIP, TargetCount, Targets, FirstSeen, LastSeen, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 24f5a6b7-c8d9-4e0f-1a2b-3c4d5e6f7a84
name: "RDP from Single Account to Multiple Hosts"
description: |
  This detection identifies a single user account establishing Remote Desktop Protocol sessions to multiple distinct hosts within a short timeframe. While administrators may legitimately RDP to several servers, an attacker with compromised credentials will rapidly pivot across many systems via RDP.
  A SOC analyst should investigate because a single account RDP-ing to many hosts in rapid succession is a strong indicator of credential-based lateral movement across the network.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceLogonEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - LateralMovement
relevantTechniques:
  - T1021.001
query: |
  let threshold = 3;
  DeviceLogonEvents
  // 24-hour lookback for RDP sessions
  | where TimeGenerated > ago(24h)
  // Filter for Remote Desktop (RemoteInteractive) logon type
  | where LogonType == "RemoteInteractive"
  // Aggregate: count distinct target hosts per account and source IP
  | summarize
      TargetCount = dcount(DeviceName),
      Targets = make_set(DeviceName, 20),
      FirstSeen = min(TimeGenerated),
      LastSeen = max(TimeGenerated)
    by AccountName, RemoteIP
  // Threshold: flag accounts connecting to 3+ distinct hosts
  | where TargetCount >= threshold
  | extend
      AlertTitle = "RDP from Single Account to Multiple Hosts",
      AlertDescription = "This detection identifies a single user account establishing Remote Desktop Protocol sessions to multiple distinct hosts within a short timeframe.",
      AlertSeverity = "Medium"
  | project AccountName, RemoteIP, TargetCount, Targets, FirstSeen, LastSeen, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
