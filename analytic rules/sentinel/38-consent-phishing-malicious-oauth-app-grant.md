**Author:** Goodness Caleb Ibeh

# Consent Phishing — Malicious OAuth App Grant

This detection identifies users granting consent to OAuth applications that request sensitive permissions such as mail access, file access, or directory enumeration. Consent phishing is an increasingly common attack where users are tricked into authorizing a malicious application that then uses delegated permissions to access their data. The query flags consent events where the requested permissions match a list of commonly abused permission scopes.

**Importance:** A SOC analyst should investigate because a malicious OAuth app with consent-granted permissions can silently access the user's email, files, and directory data without needing the user's password.

**MITRE:** T1550.001 — Application Access Token

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |

```kql
// Define permission scopes commonly requested by malicious OAuth apps
let SuspiciousPermissions = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.Read.All", "Files.ReadWrite.All",
    "User.Read.All", "Directory.Read.All",
    "offline_access"
]);
AuditLogs
// 24-hour lookback for OAuth consent events
| where TimeGenerated > ago(24h)
// Filter for application consent operations
| where OperationName == "Consent to application"
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
// Expand modified properties to inspect granted permissions
| mv-expand ModifiedProp = TargetResources[0].modifiedProperties
| where tostring(ModifiedProp.displayName) == "ConsentAction.Permissions"
| extend Permissions = tostring(ModifiedProp.newValue)
// Key filter: only flag apps requesting sensitive/suspicious permissions
| where Permissions has_any (SuspiciousPermissions)
| extend
    AlertTitle = "Consent Phishing — Malicious OAuth App Grant",
    AlertDescription = "This detection identifies users granting consent to OAuth applications that request sensitive permissions such as mail access, file access, or directory enumeration.",
    AlertSeverity = "High"
| project TimeGenerated, UserPrincipalName, AppName, AppId, Permissions, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 38b9c0d1-e2f3-4a4b-5c6d-7e8f9a0b1c88
name: "Consent Phishing — Malicious OAuth App Grant"
description: |
  This detection identifies users granting consent to OAuth applications that request sensitive permissions such as mail access, file access, or directory enumeration. Consent phishing is an increasingly common attack where users are tricked into authorizing a malicious application.
  A SOC analyst should investigate because a malicious OAuth app with consent-granted permissions can silently access the user's email, files, and directory data without needing the user's password.
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
  - CredentialAccess
  - InitialAccess
relevantTechniques:
  - T1550.001
query: |
  // Define permission scopes commonly requested by malicious OAuth apps
  let SuspiciousPermissions = dynamic([
      "Mail.Read", "Mail.ReadWrite", "Mail.Send",
      "Files.Read.All", "Files.ReadWrite.All",
      "User.Read.All", "Directory.Read.All",
      "offline_access"
  ]);
  AuditLogs
  // 24-hour lookback for OAuth consent events
  | where TimeGenerated > ago(24h)
  // Filter for application consent operations
  | where OperationName == "Consent to application"
  | extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
  | extend AppName = tostring(TargetResources[0].displayName)
  | extend AppId = tostring(TargetResources[0].id)
  // Expand modified properties to inspect granted permissions
  | mv-expand ModifiedProp = TargetResources[0].modifiedProperties
  | where tostring(ModifiedProp.displayName) == "ConsentAction.Permissions"
  | extend Permissions = tostring(ModifiedProp.newValue)
  // Key filter: only flag apps requesting sensitive/suspicious permissions
  | where Permissions has_any (SuspiciousPermissions)
  | extend
      AlertTitle = "Consent Phishing — Malicious OAuth App Grant",
      AlertDescription = "This detection identifies users granting consent to OAuth applications that request sensitive permissions such as mail access, file access, or directory enumeration.",
      AlertSeverity = "High"
  | project TimeGenerated, UserPrincipalName, AppName, AppId, Permissions, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
