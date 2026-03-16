**Author:** Goodness Caleb Ibeh

# Suspicious Azure AD Application Registration

This detection monitors for the creation of new Azure AD applications and the addition of credentials (secrets or certificates) to existing applications. Attackers who gain administrative access frequently register new applications or add credentials to existing ones to create persistent backdoor access. Application credentials allow API-based access that bypasses MFA and user-based conditional access policies.

**Importance:** A SOC analyst should investigate because malicious application registrations and credential additions provide persistent, MFA-bypassing access to tenant resources that survives password resets.

**MITRE:** T1098.001 — Account Manipulation: Additional Cloud Credentials

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Initiator |

```kql
AuditLogs
// 24-hour lookback for application changes
| where TimeGenerated > ago(24h)
// Key filter: operations related to app creation or credential management
| where OperationName in ("Add application", "Add service principal credentials",
                           "Update application – Certificates and secrets management")
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend TargetAppId = tostring(TargetResources[0].id)
| extend
    AlertTitle = "Suspicious Azure AD Application Registration",
    AlertDescription = "This detection monitors for the creation of new Azure AD applications and the addition of credentials (secrets or certificates) to existing applications.",
    AlertSeverity = "Medium"
| project TimeGenerated, Initiator, OperationName, TargetApp, TargetAppId, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 40d1e2f3-a4b5-4c6d-7e8f-9a0b1c2d3e40
name: "Suspicious Azure AD Application Registration"
description: |
  This detection monitors for the creation of new Azure AD applications and the addition of credentials (secrets or certificates) to existing applications. Attackers who gain administrative access frequently register new applications or add credentials to existing ones to create persistent backdoor access.
  A SOC analyst should investigate because malicious application registrations and credential additions provide persistent, MFA-bypassing access to tenant resources that survives password resets.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1098.001
query: |
  AuditLogs
  // 24-hour lookback for application changes
  | where TimeGenerated > ago(24h)
  // Key filter: operations related to app creation or credential management
  | where OperationName in ("Add application", "Add service principal credentials",
                             "Update application – Certificates and secrets management")
  | extend Initiator = coalesce(
      tostring(InitiatedBy.user.userPrincipalName),
      tostring(InitiatedBy.app.displayName))
  | extend TargetApp = tostring(TargetResources[0].displayName)
  | extend TargetAppId = tostring(TargetResources[0].id)
  | extend
      AlertTitle = "Suspicious Azure AD Application Registration",
      AlertDescription = "This detection monitors for the creation of new Azure AD applications and the addition of credentials (secrets or certificates) to existing applications.",
      AlertSeverity = "Medium"
  | project TimeGenerated, Initiator, OperationName, TargetApp, TargetAppId, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: Initiator
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
