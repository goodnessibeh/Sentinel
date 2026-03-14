**Author:** Goodness Caleb Ibeh

# Beaconing Detection — Regular Interval Callbacks

This detection identifies network beaconing behavior by analyzing the regularity of outbound connections from a host to a specific remote IP. Command and control implants typically call back to their C2 server at regular intervals (beaconing), and this periodic pattern can be detected by measuring the standard deviation of time intervals between connections. A low standard deviation relative to the average interval indicates a high degree of regularity consistent with automated beaconing.

**Importance:** A SOC analyst should investigate because regular-interval network callbacks are the signature behavior of C2 implants, and identifying beaconing early can stop an attack before data exfiltration or lateral movement.

**MITRE:** T1071 — Application Layer Protocol

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | RemoteIP |

```kql
let minConnections = 20;
DeviceNetworkEvents
// 24-hour lookback for connection pattern analysis
| where TimeGenerated > ago(24h)
// Filter for successful outbound connections
| where ActionType == "ConnectionSuccess"
// Only analyze connections to public IPs (not internal)
| where RemoteIPType == "Public"
// Aggregate connection timestamps per unique communication pair
| summarize
    ConnectionTimes = make_list(TimeGenerated, 1000),
    ConnectionCount = count()
  by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
// Threshold: need enough connections for statistical analysis
| where ConnectionCount >= minConnections
// Calculate time deltas between consecutive connections
| mv-apply ct = ConnectionTimes to typeof(datetime) on (
    serialize
    | extend NextTime = next(ct)
    | where isnotnull(NextTime)
    | extend Delta = datetime_diff("second", NextTime, ct)
    | summarize AvgDelta = avg(Delta), StdevDelta = stdev(Delta), Deltas = count()
)
// Detection logic: low standard deviation = regular interval = beaconing
| where StdevDelta < AvgDelta * 0.2  // <20% variation
| where AvgDelta between (10 .. 3600)  // 10s to 1h intervals
| project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName,
          ConnectionCount, AvgDelta, StdevDelta
| order by StdevDelta asc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 30f1a2b3-c4d5-4e6f-7a8b-9c0d1e2f3a00
name: "Beaconing Detection — Regular Interval Callbacks"
description: |
  This detection identifies network beaconing behavior by analyzing the regularity of outbound connections from a host to a specific remote IP. Command and control implants typically call back to their C2 server at regular intervals (beaconing).
  A SOC analyst should investigate because regular-interval network callbacks are the signature behavior of C2 implants, and identifying beaconing early can stop an attack before data exfiltration or lateral movement.
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
  - CommandAndControl
relevantTechniques:
  - T1071
query: |
  let minConnections = 20;
  DeviceNetworkEvents
  // 24-hour lookback for connection pattern analysis
  | where TimeGenerated > ago(24h)
  // Filter for successful outbound connections
  | where ActionType == "ConnectionSuccess"
  // Only analyze connections to public IPs (not internal)
  | where RemoteIPType == "Public"
  // Aggregate connection timestamps per unique communication pair
  | summarize
      ConnectionTimes = make_list(TimeGenerated, 1000),
      ConnectionCount = count()
    by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
  // Threshold: need enough connections for statistical analysis
  | where ConnectionCount >= minConnections
  // Calculate time deltas between consecutive connections
  | mv-apply ct = ConnectionTimes to typeof(datetime) on (
      serialize
      | extend NextTime = next(ct)
      | where isnotnull(NextTime)
      | extend Delta = datetime_diff("second", NextTime, ct)
      | summarize AvgDelta = avg(Delta), StdevDelta = stdev(Delta), Deltas = count()
  )
  // Detection logic: low standard deviation = regular interval = beaconing
  | where StdevDelta < AvgDelta * 0.2  // <20% variation
  | where AvgDelta between (10 .. 3600)  // 10s to 1h intervals
  | project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName,
            ConnectionCount, AvgDelta, StdevDelta
  | order by StdevDelta asc
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
version: 1.0.0
kind: Scheduled
```
