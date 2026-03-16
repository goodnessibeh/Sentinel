**Author:** Goodness Caleb Ibeh

# Password Spray Attack

This detection identifies password spray attacks by finding single IP addresses that attempt to authenticate against many different user accounts. Unlike brute force, password spraying tries a small number of common passwords across a large number of accounts to avoid lockout thresholds. The query aggregates failed authentication attempts by source IP and flags those targeting an unusually high number of distinct users.

**Importance:** A SOC analyst should investigate because password spraying is a stealthy technique designed to fly under lockout thresholds — even a single successful login out of many attempts gives the attacker a foothold.

**MITRE:** T1110.003 — Brute Force: Password Spraying

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | IPAddress |

```kql
let timeframe = 1h;
let userThreshold = 10;
// Common failure codes for invalid credentials
let failureCode = dynamic([50126, 50053, 50055, 50056]);
SigninLogs
// Short detection window for spray activity
| where TimeGenerated > ago(timeframe)
// Filter for authentication failure result codes
| where ResultType in (failureCode)
// Aggregate by source IP to detect one IP targeting many users
| summarize
    TargetedUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 50),
    AttemptCount = count(),
    Apps = make_set(AppDisplayName, 5),
    FailureCodes = make_set(ResultType)
  by IPAddress
// Threshold: flag IPs targeting more users than normal
| where TargetedUsers >= userThreshold
| extend SuccessCheck = toscalar(
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where IPAddress == IPAddress and ResultType == 0
    | summarize count()
  )
| extend
    AlertTitle = "Password Spray Attack",
    AlertDescription = "This detection identifies password spray attacks by finding single IP addresses that attempt to authenticate against many different user accounts.",
    AlertSeverity = "Medium"
| project IPAddress, TargetedUsers, AttemptCount, UserList, Apps, FailureCodes, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 21c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d51
name: "Password Spray Attack"
description: |
  This detection identifies password spray attacks by finding single IP addresses that attempt to authenticate against many different user accounts. Unlike brute force, password spraying tries a small number of common passwords across a large number of accounts to avoid lockout thresholds.
  A SOC analyst should investigate because password spraying is a stealthy technique designed to fly under lockout thresholds — even a single successful login out of many attempts gives the attacker a foothold.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110.003
query: |
  let timeframe = 1h;
  let userThreshold = 10;
  // Common failure codes for invalid credentials
  let failureCode = dynamic([50126, 50053, 50055, 50056]);
  SigninLogs
  // Short detection window for spray activity
  | where TimeGenerated > ago(timeframe)
  // Filter for authentication failure result codes
  | where ResultType in (failureCode)
  // Aggregate by source IP to detect one IP targeting many users
  | summarize
      TargetedUsers = dcount(UserPrincipalName),
      UserList = make_set(UserPrincipalName, 50),
      AttemptCount = count(),
      Apps = make_set(AppDisplayName, 5),
      FailureCodes = make_set(ResultType)
    by IPAddress
  // Threshold: flag IPs targeting more users than normal
  | where TargetedUsers >= userThreshold
  | extend SuccessCheck = toscalar(
      SigninLogs
      | where TimeGenerated > ago(timeframe)
      | where IPAddress == IPAddress and ResultType == 0
      | summarize count()
    )
  | extend
      AlertTitle = "Password Spray Attack",
      AlertDescription = "This detection identifies password spray attacks by finding single IP addresses that attempt to authenticate against many different user accounts.",
      AlertSeverity = "Medium"
  | project IPAddress, TargetedUsers, AttemptCount, UserList, Apps, FailureCodes, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
