**Author:** Goodness Caleb Ibeh

# Inbox Rule Creation (Email Persistence)

This detection identifies the creation or modification of Outlook inbox rules that forward, redirect, or delete emails. Attackers who compromise email accounts frequently create inbox rules to maintain persistent access to communications, exfiltrate sensitive data, or hide evidence of their activity by deleting security notifications. Rules that forward to external addresses or move messages to obscure folders are especially suspicious.

**Importance:** A SOC analyst should investigate because malicious inbox rules allow attackers to silently intercept emails, hide breach notifications, and exfiltrate data long after the initial compromise.

**MITRE:** T1137.005 — Office Application Startup: Outlook Rules

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserId |

```kql
OfficeActivity
// 24-hour lookback for inbox rule changes
| where TimeGenerated > ago(24h)
// Filter for inbox rule creation or modification
| where Operation in ("New-InboxRule", "Set-InboxRule")
// Parse the rule parameters to extract key fields
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| extend MoveToFolder = tostring(parse_json(Parameters)[3].Value)
| extend ForwardTo = tostring(parse_json(Parameters)[4].Value)
| extend DeleteMessage = tostring(parse_json(Parameters)[5].Value)
// Key filter: only flag rules that forward, delete, or move to suspicious folders
| where isnotempty(ForwardTo) or isnotempty(DeleteMessage) or MoveToFolder has_any ("RSS", "Deleted", "Junk")
| extend
    AlertTitle = "Inbox Rule Creation (Email Persistence)",
    AlertDescription = "This detection identifies the creation or modification of Outlook inbox rules that forward, redirect, or delete emails.",
    AlertSeverity = "Medium"
| project TimeGenerated, UserId, ClientIP, Operation, RuleName, ForwardTo, DeleteMessage, MoveToFolder, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 13a4b5c6-d7e8-4f90-a1b2-c3d4e5f6a7b9
name: "Inbox Rule Creation (Email Persistence)"
description: |
  This detection identifies the creation or modification of Outlook inbox rules that forward, redirect, or delete emails. Attackers who compromise email accounts frequently create inbox rules to maintain persistent access to communications, exfiltrate sensitive data, or hide evidence of their activity.
  A SOC analyst should investigate because malicious inbox rules allow attackers to silently intercept emails, hide breach notifications, and exfiltrate data long after the initial compromise.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1137.005
query: |
  OfficeActivity
  // 24-hour lookback for inbox rule changes
  | where TimeGenerated > ago(24h)
  // Filter for inbox rule creation or modification
  | where Operation in ("New-InboxRule", "Set-InboxRule")
  // Parse the rule parameters to extract key fields
  | extend RuleName = tostring(parse_json(Parameters)[0].Value)
  | extend MoveToFolder = tostring(parse_json(Parameters)[3].Value)
  | extend ForwardTo = tostring(parse_json(Parameters)[4].Value)
  | extend DeleteMessage = tostring(parse_json(Parameters)[5].Value)
  // Key filter: only flag rules that forward, delete, or move to suspicious folders
  | where isnotempty(ForwardTo) or isnotempty(DeleteMessage) or MoveToFolder has_any ("RSS", "Deleted", "Junk")
  | extend
      AlertTitle = "Inbox Rule Creation (Email Persistence)",
      AlertDescription = "This detection identifies the creation or modification of Outlook inbox rules that forward, redirect, or delete emails.",
      AlertSeverity = "Medium"
  | project TimeGenerated, UserId, ClientIP, Operation, RuleName, ForwardTo, DeleteMessage, MoveToFolder, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserId
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
