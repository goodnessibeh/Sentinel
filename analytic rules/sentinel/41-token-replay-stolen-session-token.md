**Author:** Goodness Caleb Ibeh

# Token Replay / Stolen Session Token

This detection identifies potential token replay attacks by finding the same authentication token (identified by OriginalRequestId) being used from multiple distinct IP addresses within a short time window. When a session token is stolen (via malware, network interception, or browser exploitation), the attacker replays it from their own infrastructure. Seeing the same token appear from different IPs is a strong indicator that the token has been compromised.

**Importance:** A SOC analyst should treat this as high priority because token replay bypasses all authentication controls including MFA — the attacker has a fully authenticated session without needing credentials.

**MITRE:** T1528 — Steal Application Access Token

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |

```kql
// Detect the same authentication token used from multiple IP addresses
SigninLogs
// 24-hour lookback for token reuse analysis
| where TimeGenerated > ago(24h)
// Only analyze successful authentications
| where ResultType == 0
// Filter for entries with a request ID to track token reuse
| where isnotempty(OriginalRequestId)
// Aggregate: count distinct IPs per token per user
| summarize
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Locations = make_set(tostring(LocationDetails.city), 10),
    AppList = make_set(AppDisplayName, 5)
  by UserPrincipalName, OriginalRequestId, bin(TimeGenerated, 1h)
// Detection logic: same token from more than one IP = stolen token
| where DistinctIPs > 1
| project TimeGenerated, UserPrincipalName, DistinctIPs, IPList, Locations, AppList
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 41e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f51
name: "Token Replay / Stolen Session Token"
description: |
  This detection identifies potential token replay attacks by finding the same authentication token being used from multiple distinct IP addresses within a short time window. When a session token is stolen, the attacker replays it from their own infrastructure.
  A SOC analyst should treat this as high priority because token replay bypasses all authentication controls including MFA — the attacker has a fully authenticated session without needing credentials.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1528
query: |
  // Detect the same authentication token used from multiple IP addresses
  SigninLogs
  // 24-hour lookback for token reuse analysis
  | where TimeGenerated > ago(24h)
  // Only analyze successful authentications
  | where ResultType == 0
  // Filter for entries with a request ID to track token reuse
  | where isnotempty(OriginalRequestId)
  // Aggregate: count distinct IPs per token per user
  | summarize
      DistinctIPs = dcount(IPAddress),
      IPList = make_set(IPAddress, 10),
      Locations = make_set(tostring(LocationDetails.city), 10),
      AppList = make_set(AppDisplayName, 5)
    by UserPrincipalName, OriginalRequestId, bin(TimeGenerated, 1h)
  // Detection logic: same token from more than one IP = stolen token
  | where DistinctIPs > 1
  | project TimeGenerated, UserPrincipalName, DistinctIPs, IPList, Locations, AppList
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
version: 1.0.0
kind: Scheduled
```
