**Author:** Goodness Caleb Ibeh

# Proxy Avoidance or Anonymizer Usage

Detects internal users accessing proxy avoidance services, anonymizers, dynamic DNS services, or cryptocurrency-related sites. These categories are commonly used by insiders attempting to bypass corporate security controls, hide their browsing activity, or access restricted content. Attackers also use these services to obscure C2 communications or exfiltrate data through anonymous channels.

**Importance:** Proxy avoidance and anonymizer usage signals deliberate attempts to bypass security controls, which may indicate insider threat activity or an attacker using evasion techniques.

**MITRE:** T1090 — Proxy
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
// Reference: FortiOS Log ID 0316013056 (Web Filter) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/13056/13056
let lookback = 24h;
// FortiGuard category IDs for evasion-related sites
let EvasionCategories = dynamic([59, 71, 89]); // Proxy Avoidance, Dynamic DNS, Cryptocurrency
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
// Only surface requests to evasion-related categories
| where Category in (EvasionCategories)
// Aggregate access counts per source IP and category for pattern analysis
| summarize
    AccessCount = count(),
    Domains = make_set(DestinationHostName, 20),
    Users = make_set(DestinationUserName, 10)
  by SourceIP, CatDesc
| extend
    AlertTitle = "Proxy Avoidance or Anonymizer Usage",
    AlertDescription = "Internal user detected accessing proxy avoidance services, anonymizers, or similar evasion tools, indicating deliberate attempts to bypass security controls.",
    AlertSeverity = "Medium"
| order by AccessCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b8d4f1e5-7a9c-4b2f-c0d6-4e5f8a1b3c2d
name: "Proxy Avoidance or Anonymizer Usage"
description: |
  Detects internal users accessing proxy avoidance services, anonymizers, dynamic DNS services, or cryptocurrency-related sites. Proxy avoidance and anonymizer usage signals deliberate attempts to bypass security controls, which may indicate insider threat activity or an attacker using evasion techniques. Designed for Fortinet FortiGate firewalls.
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
  - DefenseEvasion
relevantTechniques:
  - T1090
query: |
  let lookback = 24h;
  // FortiGuard category IDs for evasion-related sites
  let EvasionCategories = dynamic([59, 71, 89]); // Proxy Avoidance, Dynamic DNS, Cryptocurrency
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
  // Only surface requests to evasion-related categories
  | where Category in (EvasionCategories)
  // Aggregate access counts per source IP and category for pattern analysis
  | summarize
      AccessCount = count(),
      Domains = make_set(DestinationHostName, 20),
      Users = make_set(DestinationUserName, 10)
    by SourceIP, CatDesc
  | extend
      AlertTitle = "Proxy Avoidance or Anonymizer Usage",
      AlertDescription = "Internal user detected accessing proxy avoidance services, anonymizers, or similar evasion tools, indicating deliberate attempts to bypass security controls.",
      AlertSeverity = "Medium"
  | order by AccessCount desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
customDetails:
  AccessCount: AccessCount
  CatDesc: CatDesc
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
