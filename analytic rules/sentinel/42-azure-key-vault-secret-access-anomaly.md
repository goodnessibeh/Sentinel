**Author:** Goodness Caleb Ibeh

# Azure Key Vault Secret Access Anomaly

This detection identifies anomalous access patterns to Azure Key Vault secrets, such as a single identity accessing an unusually high number of distinct secrets or making an excessive volume of secret retrieval calls. Key Vaults store sensitive credentials, API keys, and certificates, making them a high-value target for attackers. Abnormal access patterns may indicate an attacker enumerating and harvesting secrets after compromising a service principal or user identity.

**Importance:** A SOC analyst should investigate because Key Vault secrets contain the most sensitive credentials in the environment — mass retrieval likely indicates an attacker harvesting credentials for broader access.

**MITRE:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Identity |
| IP | Address | CallerIPAddress |

```kql
AzureDiagnostics
// 24-hour lookback for Key Vault access analysis
| where TimeGenerated > ago(24h)
// Filter for Key Vault resources
| where ResourceType == "VAULTS"
// Filter for secret retrieval operations
| where OperationName == "SecretGet"
// Aggregate: count access volume and distinct secrets per caller
| summarize
    AccessCount = count(),
    DistinctSecrets = dcount(id_s),
    SecretNames = make_set(id_s, 20),
    ResultTypes = make_set(ResultType)
  by CallerIPAddress, Identity = identity_claim_upn_s, bin(TimeGenerated, 1h)
// Threshold: flag high volume or high breadth of secret access
| where AccessCount > 20 or DistinctSecrets > 5
| extend
    AlertTitle = "Azure Key Vault Secret Access Anomaly",
    AlertDescription = "This detection identifies anomalous access patterns to Azure Key Vault secrets, such as a single identity accessing an unusually high number of distinct secrets or making an excessive volume of secret retrieval calls.",
    AlertSeverity = "Medium"
| project TimeGenerated, CallerIPAddress, Identity, AccessCount, DistinctSecrets, SecretNames, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 42f3a4b5-c6d7-4e8f-9a0b-1c2d3e4f5a62
name: "Azure Key Vault Secret Access Anomaly"
description: |
  This detection identifies anomalous access patterns to Azure Key Vault secrets, such as a single identity accessing an unusually high number of distinct secrets or making an excessive volume of secret retrieval calls. Key Vaults store sensitive credentials, API keys, and certificates, making them a high-value target for attackers.
  A SOC analyst should investigate because Key Vault secrets contain the most sensitive credentials in the environment — mass retrieval likely indicates an attacker harvesting credentials for broader access.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: AzureDiagnostics
    dataTypes:
      - AzureDiagnostics
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1552.005
query: |
  AzureDiagnostics
  // 24-hour lookback for Key Vault access analysis
  | where TimeGenerated > ago(24h)
  // Filter for Key Vault resources
  | where ResourceType == "VAULTS"
  // Filter for secret retrieval operations
  | where OperationName == "SecretGet"
  // Aggregate: count access volume and distinct secrets per caller
  | summarize
      AccessCount = count(),
      DistinctSecrets = dcount(id_s),
      SecretNames = make_set(id_s, 20),
      ResultTypes = make_set(ResultType)
    by CallerIPAddress, Identity = identity_claim_upn_s, bin(TimeGenerated, 1h)
  // Threshold: flag high volume or high breadth of secret access
  | where AccessCount > 20 or DistinctSecrets > 5
  | extend
      AlertTitle = "Azure Key Vault Secret Access Anomaly",
      AlertDescription = "This detection identifies anomalous access patterns to Azure Key Vault secrets, such as a single identity accessing an unusually high number of distinct secrets or making an excessive volume of secret retrieval calls.",
      AlertSeverity = "Medium"
  | project TimeGenerated, CallerIPAddress, Identity, AccessCount, DistinctSecrets, SecretNames, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: Identity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: CallerIPAddress
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
