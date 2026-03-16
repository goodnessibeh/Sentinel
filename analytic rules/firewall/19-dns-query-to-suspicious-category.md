**Author:** Goodness Caleb Ibeh

# DNS Query to Suspicious Category

Detects DNS queries that were blocked or redirected by FortiGate's DNS filter due to the queried domain falling into a suspicious category. This covers a broader range of threats than just botnet C2, including domains associated with malware hosting, phishing, and other malicious activities. The aggregation by source IP and category helps identify hosts that are repeatedly attempting to resolve suspicious domains.

**Importance:** Repeated blocked DNS queries to suspicious categories from a single host suggest persistent malware infection or ongoing phishing compromise that the endpoint security may have missed.

**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DestinationHostName |

```kql
// Reference: FortiOS Log ID 1501054600 (DNS Filter) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/54600/54600
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for DNS-related log entries
| where Activity has "dns"
// Key filter: only look at DNS queries that were blocked or redirected
| where DeviceAction in ("block", "redirect")
// Extract category information for context
| extend Category = extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions)
| extend CatDesc = extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions)
// Aggregate blocked DNS queries per source IP and category for pattern detection
| summarize
    BlockCount = count(),
    Domains = make_set(DestinationHostName, 20)
  by SourceIP, CatDesc, DeviceAction
| extend
    AlertTitle = "DNS Query to Suspicious Category",
    AlertDescription = "DNS queries blocked or redirected due to suspicious domain categories, suggesting persistent malware infection or ongoing phishing compromise.",
    AlertSeverity = "Medium"
| order by BlockCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a3c9e6f0-2d4b-4a7e-b5c1-9d0e3f6a8b7c
name: "DNS Query to Suspicious Category"
description: |
  Detects DNS queries blocked or redirected by FortiGate's DNS filter due to suspicious domain categories. Repeated blocked DNS queries to suspicious categories from a single host suggest persistent malware infection or ongoing phishing compromise that the endpoint security may have missed. Designed for Fortinet FortiGate firewalls.
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
  - CommandAndControl
relevantTechniques:
  - T1071.004
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for DNS-related log entries
  | where Activity has "dns"
  // Key filter: only look at DNS queries that were blocked or redirected
  | where DeviceAction in ("block", "redirect")
  // Extract category information for context
  | extend Category = extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions)
  | extend CatDesc = extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions)
  // Aggregate blocked DNS queries per source IP and category for pattern detection
  | summarize
      BlockCount = count(),
      Domains = make_set(DestinationHostName, 20)
    by SourceIP, CatDesc, DeviceAction
  | extend
      AlertTitle = "DNS Query to Suspicious Category",
      AlertDescription = "DNS queries blocked or redirected due to suspicious domain categories, suggesting persistent malware infection or ongoing phishing compromise.",
      AlertSeverity = "Medium"
  | order by BlockCount desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
customDetails:
  DeviceAction: DeviceAction
  CatDesc: CatDesc
  BlockCount: BlockCount
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=dns):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 1501054600:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/54600/54600
