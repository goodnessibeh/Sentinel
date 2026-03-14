**Author:** Goodness Caleb Ibeh

# Network Scanning Activity

This detection identifies hosts that are connecting to an unusually high number of distinct ports or remote hosts in a short time window, which is characteristic of network scanning and reconnaissance. Attackers perform network scanning after gaining initial access to map out the internal network, identify live hosts, and discover exploitable services. High port or host counts from a single source are strong indicators of automated scanning tools.

**Importance:** A SOC analyst should investigate because network scanning indicates an attacker is actively performing internal reconnaissance, which typically precedes lateral movement.

**MITRE:** T1046 — Network Service Discovery

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | LocalIP |

```kql
let portThreshold = 50;
let hostThreshold = 20;
DeviceNetworkEvents
// Short 1-hour window to detect scanning bursts
| where TimeGenerated > ago(1h)
// Filter for connection attempts (both successful and failed)
| where ActionType == "ConnectionAttempt" or ActionType == "ConnectionFailed"
// Aggregate: count distinct ports and hosts per source device
| summarize
    DistinctPorts = dcount(RemotePort),
    DistinctHosts = dcount(RemoteIP),
    PortList = make_set(RemotePort, 50),
    TargetHosts = make_set(RemoteIP, 20)
  by DeviceName, LocalIP, InitiatingProcessFileName
// Threshold: flag if port or host count exceeds normal levels
| where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
| project DeviceName, LocalIP, InitiatingProcessFileName,
          DistinctPorts, DistinctHosts, PortList, TargetHosts
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 22d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e62
name: "Network Scanning Activity"
description: |
  This detection identifies hosts that are connecting to an unusually high number of distinct ports or remote hosts in a short time window, which is characteristic of network scanning and reconnaissance.
  A SOC analyst should investigate because network scanning indicates an attacker is actively performing internal reconnaissance, which typically precedes lateral movement.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Discovery
relevantTechniques:
  - T1046
query: |
  let portThreshold = 50;
  let hostThreshold = 20;
  DeviceNetworkEvents
  // Short 1-hour window to detect scanning bursts
  | where TimeGenerated > ago(1h)
  // Filter for connection attempts (both successful and failed)
  | where ActionType == "ConnectionAttempt" or ActionType == "ConnectionFailed"
  // Aggregate: count distinct ports and hosts per source device
  | summarize
      DistinctPorts = dcount(RemotePort),
      DistinctHosts = dcount(RemoteIP),
      PortList = make_set(RemotePort, 50),
      TargetHosts = make_set(RemoteIP, 20)
    by DeviceName, LocalIP, InitiatingProcessFileName
  // Threshold: flag if port or host count exceeds normal levels
  | where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
  | project DeviceName, LocalIP, InitiatingProcessFileName,
            DistinctPorts, DistinctHosts, PortList, TargetHosts
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: LocalIP
version: 1.0.0
kind: Scheduled
```
