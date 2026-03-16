**Author:** Goodness Caleb Ibeh

# Access to Malicious/Phishing Websites

Detects web requests to URLs categorized by FortiGuard as malicious, phishing, spyware, spam, or command-and-control. These category IDs correspond to known threat infrastructure that hosts malware downloads, credential harvesting pages, or C2 panels. Whether the request was blocked or allowed, the fact that an internal host attempted to reach such a site indicates either a compromised host following C2 instructions or a user falling for a phishing lure.

**Importance:** Access attempts to known malicious or phishing sites indicate either user compromise via social engineering or an already-infected host reaching out to threat infrastructure.

**MITRE:** T1566 — Phishing
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| URL | Url | RequestURL |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
// Reference: FortiOS Log ID 0316013056 (Web Filter) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/13056/13056
let lookback = 24h;
// FortiGuard web filter category IDs for malicious content
let MaliciousCategories = dynamic([7, 8, 9, 26, 76, 90]); // Malware, Spyware, Phishing, Malicious, Spam URLs, C&C
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for web filter log entries
| where Activity has "webfilter"
// Extract the FortiGuard category ID and description
| extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
| extend CatDesc = coalesce(RequestContext, extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions))
// Only surface requests to categories associated with threats
| where Category in (MaliciousCategories)
| extend
    AlertTitle = "Access to Malicious/Phishing Websites",
    AlertDescription = "Web request detected to a URL categorized as malicious, phishing, spyware, spam, or command-and-control by FortiGuard.",
    AlertSeverity = "High"
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
          Category, CatDesc, DeviceAction, DestinationUserName,
          DestinationIP, Message, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a7c3e0d4-6f8b-4a1e-b9c5-3d4e7f0a2b1c
name: "Access to Malicious/Phishing Websites"
description: |
  Detects web requests to URLs categorized by FortiGuard as malicious, phishing, spyware, spam, or command-and-control. Access attempts to known malicious or phishing sites indicate either user compromise via social engineering or an already-infected host reaching out to threat infrastructure. Designed for Fortinet FortiGate firewalls.
severity: High
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
  // FortiGuard web filter category IDs for malicious content
  let MaliciousCategories = dynamic([7, 8, 9, 26, 76, 90]); // Malware, Spyware, Phishing, Malicious, Spam URLs, C&C
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for web filter log entries
  | where Activity has "webfilter"
  // Extract the FortiGuard category ID and description
  | extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
  | extend CatDesc = coalesce(RequestContext, extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions))
  // Only surface requests to categories associated with threats
  | where Category in (MaliciousCategories)
  | extend
      AlertTitle = "Access to Malicious/Phishing Websites",
      AlertDescription = "Web request detected to a URL categorized as malicious, phishing, spyware, spam, or command-and-control by FortiGuard.",
      AlertSeverity = "High"
  | project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
            Category, CatDesc, DeviceAction, DestinationUserName,
            DestinationIP, Message, AlertTitle, AlertDescription, AlertSeverity
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
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: RequestURL
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
customDetails:
  DeviceAction: DeviceAction
  CatDesc: CatDesc
  Category: Category
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=webfilter):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 0316013056:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/13056/13056
- **FortiGuard Category-Based Filter:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/898076/fortiguard-category-based-filter
