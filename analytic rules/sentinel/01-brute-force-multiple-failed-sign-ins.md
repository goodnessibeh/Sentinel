**Author:** Goodness Caleb Ibeh

# Brute Force — Multiple Failed Sign-ins Followed by Success

This detection identifies accounts that experience a high volume of failed sign-in attempts followed by a successful login within the same time window. Brute force attacks are one of the most common initial access techniques, where adversaries systematically try passwords until they find the correct one. A successful login after many failures strongly suggests credential compromise.

**Importance:** A SOC analyst should prioritize this alert because it indicates an attacker likely guessed or cracked a user's password and now has authenticated access to the environment.

**MITRE:** T1110 — Brute Force

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |
| IP | Address | IPAddress |

```kql
let threshold = 10;
let timeframe = 1h;
SigninLogs
// Filter to the detection window
| where TimeGenerated > ago(timeframe)
// Aggregate both failed and successful sign-ins per user
| summarize
    FailureCount = countif(ResultType != 0),
    SuccessCount = countif(ResultType == 0),
    IPAddresses = make_set(IPAddress, 100),
    AppList = make_set(AppDisplayName, 10),
    FailureReasons = make_set(ResultDescription, 5),
    FirstFailure = minif(TimeGenerated, ResultType != 0),
    LastSuccess = maxif(TimeGenerated, ResultType == 0)
  by UserPrincipalName
// Threshold: require at least N failures AND at least one success
| where FailureCount >= threshold and SuccessCount > 0
// Ensure the success came AFTER the failures (not before)
| where LastSuccess > FirstFailure
| extend TimeBetween = LastSuccess - FirstFailure
| project UserPrincipalName, FailureCount, SuccessCount, IPAddresses, AppList, FailureReasons, TimeBetween
```

**Tuning:** Adjust `threshold` based on environment. Exclude service accounts. Exclude known VPN/proxy IPs that cause legitimate failures.

---

## Sentinel Analytics Rule — YAML

```yaml
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
name: "Brute Force — Multiple Failed Sign-ins Followed by Success"
description: |
  This detection identifies accounts that experience a high volume of failed sign-in attempts followed by a successful login within the same time window. Brute force attacks are one of the most common initial access techniques, where adversaries systematically try passwords until they find the correct one. A successful login after many failures strongly suggests credential compromise.
  A SOC analyst should prioritize this alert because it indicates an attacker likely guessed or cracked a user's password and now has authenticated access to the environment.
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
  - InitialAccess
relevantTechniques:
  - T1110
query: |
  let threshold = 10;
  let timeframe = 1h;
  SigninLogs
  // Filter to the detection window
  | where TimeGenerated > ago(timeframe)
  // Aggregate both failed and successful sign-ins per user
  | summarize
      FailureCount = countif(ResultType != 0),
      SuccessCount = countif(ResultType == 0),
      IPAddresses = make_set(IPAddress, 100),
      AppList = make_set(AppDisplayName, 10),
      FailureReasons = make_set(ResultDescription, 5),
      FirstFailure = minif(TimeGenerated, ResultType != 0),
      LastSuccess = maxif(TimeGenerated, ResultType == 0)
    by UserPrincipalName
  // Threshold: require at least N failures AND at least one success
  | where FailureCount >= threshold and SuccessCount > 0
  // Ensure the success came AFTER the failures (not before)
  | where LastSuccess > FirstFailure
  | extend TimeBetween = LastSuccess - FirstFailure
  | project UserPrincipalName, FailureCount, SuccessCount, IPAddresses, AppList, FailureReasons, TimeBetween
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
version: 1.0.0
kind: Scheduled
```
