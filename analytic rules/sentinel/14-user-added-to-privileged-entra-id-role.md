**Author:** Goodness Caleb Ibeh

# User Added to Privileged Entra ID Role

This detection monitors for users being assigned to high-privilege Entra ID (Azure AD) roles such as Global Administrator, Security Administrator, or Exchange Administrator. Privilege escalation via role assignment is a critical step in cloud-based attacks, as these roles grant broad access to tenant resources. Unauthorized role assignments often indicate an attacker has compromised an admin account and is elevating privileges.

**Importance:** A SOC analyst should treat this as high priority because assignment to a privileged Entra ID role grants sweeping control over the cloud tenant, and unauthorized assignments indicate active privilege escalation.

**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetUPN |

```kql
// Define the list of privileged roles to monitor
let PrivilegedRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Conditional Access Administrator", "Authentication Administrator",
    "Privileged Authentication Administrator", "Billing Administrator"
]);
AuditLogs
// 24-hour lookback for role assignment events
| where TimeGenerated > ago(24h)
// Filter for role member additions
| where OperationName has "Add member to role"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = replace_string(tostring(TargetResources[0].modifiedProperties[1].newValue), '"', '')
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
// Key filter: only alert on privileged roles, not low-impact ones
| where RoleName in (PrivilegedRoles)
| extend
    AlertTitle = "User Added to Privileged Entra ID Role",
    AlertDescription = "This detection monitors for users being assigned to high-privilege Entra ID (Azure AD) roles such as Global Administrator, Security Administrator, or Exchange Administrator.",
    AlertSeverity = "High"
| project TimeGenerated, TargetUPN, RoleName, Initiator, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 14b5c6d7-e8f9-4a0b-1c2d-3e4f5a6b7c8a
name: "User Added to Privileged Entra ID Role"
description: |
  This detection monitors for users being assigned to high-privilege Entra ID (Azure AD) roles such as Global Administrator, Security Administrator, or Exchange Administrator. Privilege escalation via role assignment is a critical step in cloud-based attacks.
  A SOC analyst should treat this as high priority because assignment to a privileged Entra ID role grants sweeping control over the cloud tenant, and unauthorized assignments indicate active privilege escalation.
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
  - PrivilegeEscalation
relevantTechniques:
  - T1078.004
query: |
  // Define the list of privileged roles to monitor
  let PrivilegedRoles = dynamic([
      "Global Administrator", "Privileged Role Administrator",
      "Security Administrator", "Exchange Administrator",
      "SharePoint Administrator", "User Administrator",
      "Application Administrator", "Cloud Application Administrator",
      "Conditional Access Administrator", "Authentication Administrator",
      "Privileged Authentication Administrator", "Billing Administrator"
  ]);
  AuditLogs
  // 24-hour lookback for role assignment events
  | where TimeGenerated > ago(24h)
  // Filter for role member additions
  | where OperationName has "Add member to role"
  | extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
  | extend RoleName = replace_string(tostring(TargetResources[0].modifiedProperties[1].newValue), '"', '')
  | extend Initiator = coalesce(
      tostring(InitiatedBy.user.userPrincipalName),
      tostring(InitiatedBy.app.displayName))
  // Key filter: only alert on privileged roles, not low-impact ones
  | where RoleName in (PrivilegedRoles)
  | extend
      AlertTitle = "User Added to Privileged Entra ID Role",
      AlertDescription = "This detection monitors for users being assigned to high-privilege Entra ID (Azure AD) roles such as Global Administrator, Security Administrator, or Exchange Administrator.",
      AlertSeverity = "High"
  | project TimeGenerated, TargetUPN, RoleName, Initiator, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: TargetUPN
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
