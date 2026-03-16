**Author:** Goodness Caleb Ibeh

# Anomalous Email Forwarding Rule

This detection identifies the creation of email forwarding or redirect rules that send copies of emails to external addresses. This is a critical exfiltration technique where attackers set up auto-forwarding rules on compromised mailboxes to continuously receive copies of all incoming emails without needing to remain logged in. The query extracts the external domain being forwarded to, enabling analysts to quickly assess the severity.

**Importance:** A SOC analyst should treat this as high priority because email forwarding rules provide attackers with continuous, passive access to all emails in a compromised mailbox — often persisting long after the initial access is remediated.

**MITRE:** T1114.003 — Email Collection: Email Forwarding Rule

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserId |

```kql
OfficeActivity
// 24-hour lookback for email rule changes
| where TimeGenerated > ago(24h)
// Filter for inbox and transport rule creation/modification
| where Operation in ("New-InboxRule", "Set-InboxRule", "New-TransportRule", "Set-TransportRule")
| extend Parameters = parse_json(Parameters)
// Expand parameters to inspect each rule setting
| mv-expand Parameters
| extend ParamName = tostring(Parameters.Name), ParamValue = tostring(Parameters.Value)
// Key filter: only rules that forward, redirect, or forward-as-attachment
| where ParamName in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| where isnotempty(ParamValue)
// Extract the external domain for analyst review
| extend ExternalDomain = extract(@"@(.+)$", 1, ParamValue)
| extend
    AlertTitle = "Anomalous Email Forwarding Rule",
    AlertDescription = "This detection identifies the creation of email forwarding or redirect rules that send copies of emails to external addresses.",
    AlertSeverity = "High"
| project TimeGenerated, UserId, ClientIP, Operation, ParamName,
          ForwardTarget = ParamValue, ExternalDomain, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 33c4d5e6-f7a8-4b9c-0d1e-2f3a4b5c6d33
name: "Anomalous Email Forwarding Rule"
description: |
  This detection identifies the creation of email forwarding or redirect rules that send copies of emails to external addresses. This is a critical exfiltration technique where attackers set up auto-forwarding rules on compromised mailboxes to continuously receive copies of all incoming emails.
  A SOC analyst should treat this as high priority because email forwarding rules provide attackers with continuous, passive access to all emails in a compromised mailbox — often persisting long after the initial access is remediated.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Exfiltration
relevantTechniques:
  - T1114.003
query: |
  OfficeActivity
  // 24-hour lookback for email rule changes
  | where TimeGenerated > ago(24h)
  // Filter for inbox and transport rule creation/modification
  | where Operation in ("New-InboxRule", "Set-InboxRule", "New-TransportRule", "Set-TransportRule")
  | extend Parameters = parse_json(Parameters)
  // Expand parameters to inspect each rule setting
  | mv-expand Parameters
  | extend ParamName = tostring(Parameters.Name), ParamValue = tostring(Parameters.Value)
  // Key filter: only rules that forward, redirect, or forward-as-attachment
  | where ParamName in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
  | where isnotempty(ParamValue)
  // Extract the external domain for analyst review
  | extend ExternalDomain = extract(@"@(.+)$", 1, ParamValue)
  | extend
      AlertTitle = "Anomalous Email Forwarding Rule",
      AlertDescription = "This detection identifies the creation of email forwarding or redirect rules that send copies of emails to external addresses.",
      AlertSeverity = "High"
  | project TimeGenerated, UserId, ClientIP, Operation, ParamName,
            ForwardTarget = ParamValue, ExternalDomain, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserId
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
