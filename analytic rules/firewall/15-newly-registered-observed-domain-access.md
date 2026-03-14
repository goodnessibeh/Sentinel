**Author:** Goodness Caleb Ibeh

# Newly Registered/Observed Domain Access

Detects internal hosts accessing domains that FortiGuard has classified as newly registered or newly observed. Attackers frequently register fresh domains for phishing campaigns, malware distribution, and C2 infrastructure because new domains have no reputation history and often bypass traditional blocklists. While some newly registered domains are legitimate, the overlap with attacker infrastructure is high enough to warrant monitoring.

**Importance:** Newly registered domains are disproportionately used for phishing and malware campaigns, and access to them should be correlated with other indicators to identify early-stage attacks.

**MITRE:** T1583.001 — Acquire Infrastructure: Domains
**Severity:** Low

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DestinationHostName |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log ID 0316013056 (Web Filter) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/13056/13056
let lookback = 24h;
// FortiGuard category IDs for newly observed/registered domains
let NewDomainCategories = dynamic([61, 62]); // Newly Observed Domain, Newly Registered Domain
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for web filter log entries
| where Activity has "webfilter"
// Extract and filter by new domain category IDs
| extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
| where Category in (NewDomainCategories)
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
          DeviceAction, DestinationUserName, Category
// Aggregate by domain to identify the most frequently accessed new domains
| summarize
    AccessCount = count(),
    Users = make_set(DestinationUserName, 10)
  by DestinationHostName
| order by AccessCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: c9e5a2f6-8b0d-4c3a-d1e7-5f6a9b2c4d3e
name: "Newly Registered/Observed Domain Access"
description: |
  Detects internal hosts accessing domains classified as newly registered or newly observed by FortiGuard. Newly registered domains are disproportionately used for phishing and malware campaigns, and access to them should be correlated with other indicators to identify early-stage attacks. Designed for Fortinet FortiGate firewalls.
severity: Low
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
  - Reconnaissance
relevantTechniques:
  - T1583.001
query: |
  let lookback = 24h;
  // FortiGuard category IDs for newly observed/registered domains
  let NewDomainCategories = dynamic([61, 62]); // Newly Observed Domain, Newly Registered Domain
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for web filter log entries
  | where Activity has "webfilter"
  // Extract and filter by new domain category IDs
  | extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
  | where Category in (NewDomainCategories)
  | project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
            DeviceAction, DestinationUserName, Category
  // Aggregate by domain to identify the most frequently accessed new domains
  | summarize
      AccessCount = count(),
      Users = make_set(DestinationUserName, 10)
    by DestinationHostName
  | order by AccessCount desc
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  DeviceAction: DeviceAction
  AccessCount: AccessCount
  Category: Category
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=webfilter):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 0316013056:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/13056/13056
- **FortiGuard Category-Based Filter:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/898076/fortiguard-category-based-filter
