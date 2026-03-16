**Author:** Goodness Caleb Ibeh

# Full Attack Chain — Compromised Account to Data Exfiltration

This detection correlates three stages of a typical business email compromise (BEC) attack chain: a suspicious sign-in (initial access), inbox rule creation (persistence), and mass file downloads (collection/exfiltration). By joining these events for the same user account within a time window, the query surfaces complete attack chains that individual detections might miss. This multi-signal correlation produces very high-fidelity alerts.

**Importance:** A SOC analyst should treat this as the highest priority because a correlated three-stage attack chain — risky login, mail rule, and data download — is strong evidence of an active, ongoing compromise with data exfiltration.

**MITRE:** Multiple

**Severity:** High

```kql
// Stage 1: Identify suspicious sign-ins (risky logins that succeeded)
let SuspiciousSignins = SigninLogs
| where TimeGenerated > ago(24h)
// Filter for medium or high risk successful sign-ins
| where RiskLevelDuringSignIn in ("high", "medium")
| where ResultType == 0
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevel = RiskLevelDuringSignIn;
// Stage 2: Identify inbox rule creation (persistence)
let MailRules = OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project RuleTime = TimeGenerated, UserId, Operation;
// Stage 3: Identify mass file downloads (collection/exfiltration)
let Downloads = OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation == "FileDownloaded"
| summarize DownloadCount = count(), Files = make_set(SourceFileName, 10)
  by UserId, bin(TimeGenerated, 1h);
// Correlate: join all three stages for the same user account
SuspiciousSignins
| join kind=inner (MailRules) on $left.UserPrincipalName == $right.UserId
// Rule must be created within 4 hours of suspicious sign-in
| where RuleTime between (SigninTime .. (SigninTime + 4h))
| join kind=leftouter (Downloads) on $left.UserPrincipalName == $right.UserId
| extend
    AlertTitle = "Full Attack Chain — Compromised Account to Data Exfiltration",
    AlertDescription = "This detection correlates three stages of a typical business email compromise (BEC) attack chain: a suspicious sign-in (initial access), inbox rule creation (persistence), and mass file downloads (collection/exfiltration).",
    AlertSeverity = "High"
| project SigninTime, RuleTime, UserPrincipalName, IPAddress, RiskLevel,
          Operation, DownloadCount, Files, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 37a8b9c0-d1e2-4f3a-4b5c-6d7e8f9a0b77
name: "Full Attack Chain — Compromised Account to Data Exfiltration"
description: |
  This detection correlates three stages of a typical business email compromise (BEC) attack chain: a suspicious sign-in (initial access), inbox rule creation (persistence), and mass file downloads (collection/exfiltration). By joining these events for the same user account within a time window, the query surfaces complete attack chains.
  A SOC analyst should treat this as the highest priority because a correlated three-stage attack chain — risky login, mail rule, and data download — is strong evidence of an active, ongoing compromise with data exfiltration.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
  - Persistence
  - Collection
  - Exfiltration
relevantTechniques:
  - T1078
  - T1137.005
  - T1213.002
query: |
  // Stage 1: Identify suspicious sign-ins (risky logins that succeeded)
  let SuspiciousSignins = SigninLogs
  | where TimeGenerated > ago(24h)
  // Filter for medium or high risk successful sign-ins
  | where RiskLevelDuringSignIn in ("high", "medium")
  | where ResultType == 0
  | project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevel = RiskLevelDuringSignIn;
  // Stage 2: Identify inbox rule creation (persistence)
  let MailRules = OfficeActivity
  | where TimeGenerated > ago(24h)
  | where Operation in ("New-InboxRule", "Set-InboxRule")
  | project RuleTime = TimeGenerated, UserId, Operation;
  // Stage 3: Identify mass file downloads (collection/exfiltration)
  let Downloads = OfficeActivity
  | where TimeGenerated > ago(24h)
  | where Operation == "FileDownloaded"
  | summarize DownloadCount = count(), Files = make_set(SourceFileName, 10)
    by UserId, bin(TimeGenerated, 1h);
  // Correlate: join all three stages for the same user account
  SuspiciousSignins
  | join kind=inner (MailRules) on $left.UserPrincipalName == $right.UserId
  // Rule must be created within 4 hours of suspicious sign-in
  | where RuleTime between (SigninTime .. (SigninTime + 4h))
  | join kind=leftouter (Downloads) on $left.UserPrincipalName == $right.UserId
  | extend
      AlertTitle = "Full Attack Chain — Compromised Account to Data Exfiltration",
      AlertDescription = "This detection correlates three stages of a typical business email compromise (BEC) attack chain: a suspicious sign-in (initial access), inbox rule creation (persistence), and mass file downloads (collection/exfiltration).",
      AlertSeverity = "High"
  | project SigninTime, RuleTime, UserPrincipalName, IPAddress, RiskLevel,
            Operation, DownloadCount, Files, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
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
