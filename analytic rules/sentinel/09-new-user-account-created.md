**Author:** Goodness Caleb Ibeh

# New User Account Created

This detection monitors for the creation of new local user accounts on Windows systems via Security Event 4720. While account creation is a normal administrative activity, attackers frequently create new accounts to establish persistent backdoor access. Unexpected account creation, especially outside of change windows or by non-admin users, is a strong indicator of compromise.

**Importance:** A SOC analyst should review this alert because unauthorized account creation is one of the simplest and most effective persistence techniques attackers use to maintain access.

**MITRE:** T1136.001 — Create Account: Local Account

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetAccount |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for account creation events
| where TimeGenerated > ago(24h)
// Event ID 4720 = A user account was created
| where EventID == 4720
| extend
    AlertTitle = "New User Account Created",
    AlertDescription = "This detection monitors for the creation of new local user accounts on Windows systems via Security Event 4720.",
    AlertSeverity = "Low"
| project TimeGenerated, Computer, TargetAccount, TargetUserName, TargetDomainName,
          SubjectAccount, SubjectUserName, SubjectDomainName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 09c0d1e2-f3a4-4b5c-6d7e-8f90a1b2c3d5
name: "New User Account Created"
description: |
  This detection monitors for the creation of new local user accounts on Windows systems via Security Event 4720. While account creation is a normal administrative activity, attackers frequently create new accounts to establish persistent backdoor access.
  A SOC analyst should review this alert because unauthorized account creation is one of the simplest and most effective persistence techniques attackers use to maintain access.
severity: Low
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
  - T1136.001
query: |
  SecurityEvent
  // 24-hour lookback for account creation events
  | where TimeGenerated > ago(24h)
  // Event ID 4720 = A user account was created
  | where EventID == 4720
  | extend
      AlertTitle = "New User Account Created",
      AlertDescription = "This detection monitors for the creation of new local user accounts on Windows systems via Security Event 4720.",
      AlertSeverity = "Low"
  | project TimeGenerated, Computer, TargetAccount, TargetUserName, TargetDomainName,
            SubjectAccount, SubjectUserName, SubjectDomainName, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: TargetAccount
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
