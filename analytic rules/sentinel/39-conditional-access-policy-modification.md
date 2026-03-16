**Author:** Goodness Caleb Ibeh

# Conditional Access Policy Modification

This detection monitors for modifications, deletions, or disabling of Conditional Access policies in Entra ID. Conditional Access policies are a critical security control that enforces MFA requirements, device compliance, and access restrictions. An attacker who compromises an administrator account will often weaken or remove these policies to make subsequent access easier and avoid MFA challenges.

**Importance:** A SOC analyst should investigate immediately because weakening Conditional Access policies removes security guardrails and opens the door for unrestricted access to the entire cloud environment.

**MITRE:** T1562 — Impair Defenses

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Initiator |

```kql
AuditLogs
// 24-hour lookback for policy changes
| where TimeGenerated > ago(24h)
// Filter for Conditional Access policy operations
| where OperationName has "conditional access policy"
// Key filter: only flag modifications, deletions, and disabling — not creation
| where OperationName has_any ("Update", "Delete", "Disable")
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend PolicyName = tostring(TargetResources[0].displayName)
// Expand modified properties to show what changed
| mv-expand ModifiedProp = TargetResources[0].modifiedProperties
| extend PropertyName = tostring(ModifiedProp.displayName)
| extend OldValue = tostring(ModifiedProp.oldValue)
| extend NewValue = tostring(ModifiedProp.newValue)
| extend
    AlertTitle = "Conditional Access Policy Modification",
    AlertDescription = "This detection monitors for modifications, deletions, or disabling of Conditional Access policies in Entra ID.",
    AlertSeverity = "High"
| project TimeGenerated, Initiator, OperationName, PolicyName,
          PropertyName, OldValue, NewValue, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 39c0d1e2-f3a4-4b5c-6d7e-8f9a0b1c2d99
name: "Conditional Access Policy Modification"
description: |
  This detection monitors for modifications, deletions, or disabling of Conditional Access policies in Entra ID. Conditional Access policies are a critical security control that enforces MFA requirements, device compliance, and access restrictions.
  A SOC analyst should investigate immediately because weakening Conditional Access policies removes security guardrails and opens the door for unrestricted access to the entire cloud environment.
severity: High
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
  - DefenseEvasion
relevantTechniques:
  - T1562
query: |
  AuditLogs
  // 24-hour lookback for policy changes
  | where TimeGenerated > ago(24h)
  // Filter for Conditional Access policy operations
  | where OperationName has "conditional access policy"
  // Key filter: only flag modifications, deletions, and disabling — not creation
  | where OperationName has_any ("Update", "Delete", "Disable")
  | extend Initiator = coalesce(
      tostring(InitiatedBy.user.userPrincipalName),
      tostring(InitiatedBy.app.displayName))
  | extend PolicyName = tostring(TargetResources[0].displayName)
  // Expand modified properties to show what changed
  | mv-expand ModifiedProp = TargetResources[0].modifiedProperties
  | extend PropertyName = tostring(ModifiedProp.displayName)
  | extend OldValue = tostring(ModifiedProp.oldValue)
  | extend NewValue = tostring(ModifiedProp.newValue)
  | extend
      AlertTitle = "Conditional Access Policy Modification",
      AlertDescription = "This detection monitors for modifications, deletions, or disabling of Conditional Access policies in Entra ID.",
      AlertSeverity = "High"
  | project TimeGenerated, Initiator, OperationName, PolicyName,
            PropertyName, OldValue, NewValue, AlertTitle, AlertDescription, AlertSeverity
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
