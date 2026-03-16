**Author:** Goodness Caleb Ibeh

# Large Outbound Data Transfer

This detection identifies hosts sending unusually large volumes of data to public IP addresses, which may indicate data exfiltration. Attackers who have collected sensitive data will transfer it out of the network, often using legitimate protocols to blend in. A threshold-based approach on total bytes sent to external IPs per time window helps surface these bulk transfers.

**Importance:** A SOC analyst should investigate because large outbound data transfers to public IPs are a primary indicator of active data exfiltration, which represents the final stage of many attack chains.

**MITRE:** T1048 — Exfiltration Over Alternative Protocol

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | RemoteIP |

```kql
let bytesThreshold = 100000000; // 100MB
DeviceNetworkEvents
// 24-hour lookback for outbound transfer analysis
| where TimeGenerated > ago(24h)
// Filter for successful outbound connections
| where ActionType == "ConnectionSuccess"
// Only analyze transfers to public (external) IPs
| where RemoteIPType == "Public"
// Aggregate: total bytes sent per device, destination, and time window
| summarize
    TotalBytesSent = sum(SentBytes),
    ConnectionCount = count(),
    Ports = make_set(RemotePort, 10),
    Processes = make_set(InitiatingProcessFileName, 10)
  by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
// Threshold: flag transfers exceeding 100MB
| where TotalBytesSent > bytesThreshold
| extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
| extend
    AlertTitle = "Large Outbound Data Transfer",
    AlertDescription = "This detection identifies hosts sending unusually large volumes of data to public IP addresses, which may indicate data exfiltration.",
    AlertSeverity = "Medium"
| project TimeGenerated, DeviceName, RemoteIP, TotalMB, ConnectionCount, Ports, Processes, AlertTitle, AlertDescription, AlertSeverity
| order by TotalMB desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 32b3c4d5-e6f7-4a8b-9c0d-1e2f3a4b5c22
name: "Large Outbound Data Transfer"
description: |
  This detection identifies hosts sending unusually large volumes of data to public IP addresses, which may indicate data exfiltration. Attackers who have collected sensitive data will transfer it out of the network, often using legitimate protocols to blend in.
  A SOC analyst should investigate because large outbound data transfers to public IPs are a primary indicator of active data exfiltration, which represents the final stage of many attack chains.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Exfiltration
relevantTechniques:
  - T1048
query: |
  let bytesThreshold = 100000000; // 100MB
  DeviceNetworkEvents
  // 24-hour lookback for outbound transfer analysis
  | where TimeGenerated > ago(24h)
  // Filter for successful outbound connections
  | where ActionType == "ConnectionSuccess"
  // Only analyze transfers to public (external) IPs
  | where RemoteIPType == "Public"
  // Aggregate: total bytes sent per device, destination, and time window
  | summarize
      TotalBytesSent = sum(SentBytes),
      ConnectionCount = count(),
      Ports = make_set(RemotePort, 10),
      Processes = make_set(InitiatingProcessFileName, 10)
    by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
  // Threshold: flag transfers exceeding 100MB
  | where TotalBytesSent > bytesThreshold
  | extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
  | extend
      AlertTitle = "Large Outbound Data Transfer",
      AlertDescription = "This detection identifies hosts sending unusually large volumes of data to public IP addresses, which may indicate data exfiltration.",
      AlertSeverity = "Medium"
  | project TimeGenerated, DeviceName, RemoteIP, TotalMB, ConnectionCount, Ports, Processes, AlertTitle, AlertDescription, AlertSeverity
  | order by TotalMB desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
