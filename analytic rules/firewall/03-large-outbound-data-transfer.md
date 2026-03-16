**Author:** Goodness Caleb Ibeh

# Large Outbound Data Transfer — Exfiltration Indicator

Detects unusually large volumes of data being sent from internal hosts to external destinations. Attackers who have gained access to sensitive data will often stage and exfiltrate it in bulk transfers, sometimes over legitimate protocols to blend in. A single host sending hundreds of megabytes or more in a short window is a strong exfiltration signal, especially when the destination is unusual.

**Importance:** Large outbound transfers from LAN/DMZ hosts can indicate active data exfiltration, and rapid response can prevent the loss of sensitive intellectual property or customer data.

**MITRE:** T1048 — Exfiltration Over Alternative Protocol
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Traffic Log — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
let lookback = 1h;
// 500MB threshold — adjust based on normal business traffic patterns
let bytesThreshold = 500000000; // 500MB
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections
| where DeviceAction in ("accept", "close")
// Extract the source interface role to identify internal-origin traffic
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// Only consider traffic originating from internal (LAN) or DMZ networks
| where SrcIntfRole == "lan" or SrcIntfRole == "dmz"
// Aggregate total bytes sent per source IP in 1-hour windows
| summarize
    TotalBytesSent = sum(SentBytes),
    SessionCount = count(),
    DistinctDestinations = dcount(DestinationIP),
    Destinations = make_set(DestinationIP, 10),
    Ports = make_set(DestinationPort, 10)
  by SourceIP, bin(TimeGenerated, 1h)
// Only alert when the total bytes sent exceeds the exfiltration threshold
| where TotalBytesSent > bytesThreshold
| extend TotalMB = round(todouble(TotalBytesSent) / 1048576.0, 2)
| extend
    AlertTitle = "Large Outbound Data Transfer — Exfiltration Indicator",
    AlertDescription = "Unusually large volume of data sent from an internal host to an external destination, indicating potential data exfiltration.",
    AlertSeverity = "High"
| project TimeGenerated, SourceIP, TotalMB, SessionCount, DistinctDestinations, Destinations, Ports, AlertTitle, AlertDescription, AlertSeverity
| order by TotalMB desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: c5e3a0f4-6b8d-4c1a-d9e5-3f4a7b0c2d1e
name: "Large Outbound Data Transfer — Exfiltration Indicator"
description: |
  Detects unusually large volumes of data being sent from internal hosts to external destinations. Large outbound transfers from LAN/DMZ hosts can indicate active data exfiltration, and rapid response can prevent the loss of sensitive intellectual property or customer data. Designed for Fortinet FortiGate firewalls.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Exfiltration
relevantTechniques:
  - T1048
query: |
  let lookback = 1h;
  // 500MB threshold — adjust based on normal business traffic patterns
  let bytesThreshold = 500000000; // 500MB
  CommonSecurityLog
  // Filter to the last 1 hour of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Only look at allowed/completed connections
  | where DeviceAction in ("accept", "close")
  // Extract the source interface role to identify internal-origin traffic
  | extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
  // Only consider traffic originating from internal (LAN) or DMZ networks
  | where SrcIntfRole == "lan" or SrcIntfRole == "dmz"
  // Aggregate total bytes sent per source IP in 1-hour windows
  | summarize
      TotalBytesSent = sum(SentBytes),
      SessionCount = count(),
      DistinctDestinations = dcount(DestinationIP),
      Destinations = make_set(DestinationIP, 10),
      Ports = make_set(DestinationPort, 10)
    by SourceIP, bin(TimeGenerated, 1h)
  // Only alert when the total bytes sent exceeds the exfiltration threshold
  | where TotalBytesSent > bytesThreshold
  | extend TotalMB = round(todouble(TotalBytesSent) / 1048576.0, 2)
  | extend
      AlertTitle = "Large Outbound Data Transfer — Exfiltration Indicator",
      AlertDescription = "Unusually large volume of data sent from an internal host to an external destination, indicating potential data exfiltration.",
      AlertSeverity = "High"
  | project TimeGenerated, SourceIP, TotalMB, SessionCount, DistinctDestinations, Destinations, Ports, AlertTitle, AlertDescription, AlertSeverity
  | order by TotalMB desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  TotalMB: TotalMB
  SessionCount: SessionCount
  DistinctDestinations: DistinctDestinations
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log Types and Subtypes:** https://docs.fortinet.com/document/fortigate/7.6.2/fortios-log-message-reference/670197/log-types-and-subtypes
- **Traffic Logging:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
