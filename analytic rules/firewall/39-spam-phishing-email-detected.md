**Author:** Goodness Caleb Ibeh

# Spam/Phishing Email Detected

Detects spam and phishing emails identified by FortiGate's email filter engine. Phishing remains the most common initial access vector for cyberattacks, and tracking email filter events helps identify which users are being targeted, what types of phishing campaigns are active, and whether any malicious emails bypassed filtering. Even blocked phishing attempts provide valuable threat intelligence about current campaigns targeting your organization.

**Importance:** Phishing is the top initial access vector for most cyberattacks, and email filter detections reveal which users and campaigns are actively targeting your organization for prioritized security awareness.

**MITRE:** T1566 — Phishing
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log Message Reference (subtype=emailfilter) — https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for email filter log entries
| where Activity has "emailfilter"
| extend
    AlertTitle = "Spam/Phishing Email Detected",
    AlertDescription = "Spam or phishing email identified by FortiGate email filter engine, revealing active phishing campaigns targeting the organization.",
    AlertSeverity = "Medium"
| project TimeGenerated, SourceIP, DestinationIP,
          DeviceAction, Message, ApplicationProtocol,
          DestinationUserName, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: c3d9b6c0-2e4f-4c7a-d5f1-9a0b3c6d8e7f
name: "Spam/Phishing Email Detected"
description: |
  Detects spam and phishing emails identified by FortiGate's email filter engine. Phishing is the top initial access vector for most cyberattacks, and email filter detections reveal which users and campaigns are actively targeting your organization for prioritized security awareness. Designed for Fortinet FortiGate firewalls.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for email filter log entries
  | where Activity has "emailfilter"
  | extend
      AlertTitle = "Spam/Phishing Email Detected",
      AlertDescription = "Spam or phishing email identified by FortiGate email filter engine, revealing active phishing campaigns targeting the organization.",
      AlertSeverity = "Medium"
  | project TimeGenerated, SourceIP, DestinationIP,
            DeviceAction, Message, ApplicationProtocol,
            DestinationUserName, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  DeviceAction: DeviceAction
  ApplicationProtocol: ApplicationProtocol
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=emailfilter):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
