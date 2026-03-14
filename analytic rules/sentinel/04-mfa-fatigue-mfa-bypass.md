**Author:** Goodness Caleb Ibeh

# MFA Fatigue / MFA Bypass

This detection identifies accounts receiving an unusually high number of MFA push requests in a short period, which is characteristic of MFA fatigue attacks. Adversaries who have obtained valid credentials will repeatedly trigger MFA prompts, hoping the user eventually approves one out of frustration or confusion. The query also checks whether the attacker ultimately succeeded in bypassing MFA.

**Importance:** A SOC analyst should treat this as urgent because if MFA was bypassed after the fatigue attack, the attacker has full authenticated access despite the second factor.

**MITRE:** T1621 — Multi-Factor Authentication Request Generation

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |
| IP | Address | IPAddress |

```kql
let mfaThreshold = 5;
SigninLogs
// Short detection window — MFA fatigue happens in bursts
| where TimeGenerated > ago(1h)
// Filter for MFA-required result codes
| where ResultType == 50074 or ResultType == 50076  // MFA required
// Aggregate MFA requests per user to find abnormal volumes
| summarize
    MFARequests = count(),
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Apps = make_set(AppDisplayName, 5),
    LastAttempt = max(TimeGenerated)
  by UserPrincipalName
// Threshold: flag users with excessive MFA prompts
| where MFARequests >= mfaThreshold
// Check if eventually succeeded — indicates MFA was bypassed
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize SuccessTime = min(TimeGenerated) by UserPrincipalName
  ) on UserPrincipalName
| extend MFABypassed = isnotnull(SuccessTime) and SuccessTime > LastAttempt
| project UserPrincipalName, MFARequests, DistinctIPs, IPList, Apps, MFABypassed
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
name: "MFA Fatigue / MFA Bypass"
description: |
  This detection identifies accounts receiving an unusually high number of MFA push requests in a short period, which is characteristic of MFA fatigue attacks. Adversaries who have obtained valid credentials will repeatedly trigger MFA prompts, hoping the user eventually approves one out of frustration or confusion.
  A SOC analyst should treat this as urgent because if MFA was bypassed after the fatigue attack, the attacker has full authenticated access despite the second factor.
severity: High
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
  - T1621
query: |
  let mfaThreshold = 5;
  SigninLogs
  // Short detection window — MFA fatigue happens in bursts
  | where TimeGenerated > ago(1h)
  // Filter for MFA-required result codes
  | where ResultType == 50074 or ResultType == 50076  // MFA required
  // Aggregate MFA requests per user to find abnormal volumes
  | summarize
      MFARequests = count(),
      DistinctIPs = dcount(IPAddress),
      IPList = make_set(IPAddress, 10),
      Apps = make_set(AppDisplayName, 5),
      LastAttempt = max(TimeGenerated)
    by UserPrincipalName
  // Threshold: flag users with excessive MFA prompts
  | where MFARequests >= mfaThreshold
  // Check if eventually succeeded — indicates MFA was bypassed
  | join kind=leftouter (
      SigninLogs
      | where TimeGenerated > ago(1h)
      | where ResultType == 0
      | where AuthenticationRequirement == "multiFactorAuthentication"
      | summarize SuccessTime = min(TimeGenerated) by UserPrincipalName
    ) on UserPrincipalName
  | extend MFABypassed = isnotnull(SuccessTime) and SuccessTime > LastAttempt
  | project UserPrincipalName, MFARequests, DistinctIPs, IPList, Apps, MFABypassed
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
