**Author:** Goodness Caleb Ibeh

# New Entra ID User Created with Immediate Role Assignment

This detection correlates two events: the creation of a new Entra ID (Azure AD) user account followed by an immediate privileged role assignment within a short time window. This pattern is characteristic of an attacker who has gained administrative access and is creating a backdoor account with elevated privileges. Legitimate onboarding typically has a longer delay between account creation and role assignment.

**Importance:** A SOC analyst should treat this as high priority because rapid account creation followed by role assignment suggests an attacker is establishing a persistent privileged foothold in the cloud environment.

**MITRE:** T1136.003 — Create Account: Cloud Account

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetUPN |

```kql
let timeWindow = 1h;
// Step 1: Identify user creation events
let UserCreation = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add user"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project CreationTime = TimeGenerated, TargetUPN, Initiator;
// Step 2: Identify role assignment events
let RoleAssignment = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| project AssignmentTime = TimeGenerated, TargetUPN, RoleName;
// Correlate: join creation with role assignment for the same user
UserCreation
| join kind=inner (RoleAssignment) on TargetUPN
// Threshold: role must be assigned within the time window after creation
| where (AssignmentTime - CreationTime) between (0s .. timeWindow)
| extend
    AlertTitle = "New Entra ID User Created with Immediate Role Assignment",
    AlertDescription = "This detection correlates two events: the creation of a new Entra ID (Azure AD) user account followed by an immediate privileged role assignment within a short time window.",
    AlertSeverity = "High"
| project CreationTime, AssignmentTime, TargetUPN, Initiator, RoleName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 10d1e2f3-a4b5-4c6d-7e8f-90a1b2c3d4e6
name: "New Entra ID User Created with Immediate Role Assignment"
description: |
  This detection correlates two events: the creation of a new Entra ID (Azure AD) user account followed by an immediate privileged role assignment within a short time window. This pattern is characteristic of an attacker who has gained administrative access and is creating a backdoor account with elevated privileges.
  A SOC analyst should treat this as high priority because rapid account creation followed by role assignment suggests an attacker is establishing a persistent privileged foothold in the cloud environment.
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
  - Persistence
relevantTechniques:
  - T1136.003
query: |
  let timeWindow = 1h;
  // Step 1: Identify user creation events
  let UserCreation = AuditLogs
  | where TimeGenerated > ago(24h)
  | where OperationName == "Add user"
  | extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
  | extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
  | project CreationTime = TimeGenerated, TargetUPN, Initiator;
  // Step 2: Identify role assignment events
  let RoleAssignment = AuditLogs
  | where TimeGenerated > ago(24h)
  | where OperationName has "Add member to role"
  | extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
  | extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
  | project AssignmentTime = TimeGenerated, TargetUPN, RoleName;
  // Correlate: join creation with role assignment for the same user
  UserCreation
  | join kind=inner (RoleAssignment) on TargetUPN
  // Threshold: role must be assigned within the time window after creation
  | where (AssignmentTime - CreationTime) between (0s .. timeWindow)
  | extend
      AlertTitle = "New Entra ID User Created with Immediate Role Assignment",
      AlertDescription = "This detection correlates two events: the creation of a new Entra ID (Azure AD) user account followed by an immediate privileged role assignment within a short time window.",
      AlertSeverity = "High"
  | project CreationTime, AssignmentTime, TargetUPN, Initiator, RoleName, AlertTitle, AlertDescription, AlertSeverity
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
