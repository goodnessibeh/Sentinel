**Author:** Goodness Caleb Ibeh

# Denied Traffic Spike — Possible Reconnaissance

Detects a sudden spike in denied (blocked) traffic from a single source IP within a short time window. A large volume of denied connections — especially to many distinct ports or hosts — is a strong indicator that an attacker or compromised host is performing network reconnaissance or port scanning. This is often the first phase of an attack chain before exploitation.

**Importance:** SOC analysts should investigate immediately because reconnaissance activity frequently precedes exploitation attempts, and early detection can stop an attack before it progresses.

**MITRE:** T1046 — Network Service Discovery
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Traffic Log — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
let lookback = 1h;
let threshold = 100;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Focus on denied/blocked connections — the reconnaissance signal
| where DeviceAction == "deny"
// Aggregate deny counts, distinct ports and targets per source IP in 5-minute bins
| summarize
    DenyCount = count(),
    DistinctPorts = dcount(DestinationPort),
    DistinctTargets = dcount(DestinationIP),
    TargetPorts = make_set(DestinationPort, 20),
    TargetIPs = make_set(DestinationIP, 10)
  by SourceIP, bin(TimeGenerated, 5m)
// Threshold filter: only alert when deny count exceeds the baseline
| where DenyCount > threshold
| project TimeGenerated, SourceIP, DenyCount, DistinctPorts, DistinctTargets, TargetPorts, TargetIPs
| order by DenyCount desc
```

**Tuning:** Adjust threshold for environment. Exclude known scanners (vulnerability assessment tools).

---

## Sentinel Analytics Rule — YAML

```yaml
id: a3c1e8d2-4f6b-4a9e-b7c3-1d2e5f8a9b0c
name: "Denied Traffic Spike — Possible Reconnaissance"
description: |
  Detects a sudden spike in denied (blocked) traffic from a single source IP within a short time window. A large volume of denied connections — especially to many distinct ports or hosts — is a strong indicator that an attacker or compromised host is performing network reconnaissance or port scanning. SOC analysts should investigate immediately because reconnaissance activity frequently precedes exploitation attempts, and early detection can stop an attack before it progresses. Designed for Fortinet FortiGate firewalls.
severity: Medium
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
  - Discovery
relevantTechniques:
  - T1046
query: |
  let lookback = 1h;
  let threshold = 100;
  CommonSecurityLog
  // Filter to the last 1 hour of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Focus on denied/blocked connections — the reconnaissance signal
  | where DeviceAction == "deny"
  // Aggregate deny counts, distinct ports and targets per source IP in 5-minute bins
  | summarize
      DenyCount = count(),
      DistinctPorts = dcount(DestinationPort),
      DistinctTargets = dcount(DestinationIP),
      TargetPorts = make_set(DestinationPort, 20),
      TargetIPs = make_set(DestinationIP, 10)
    by SourceIP, bin(TimeGenerated, 5m)
  // Threshold filter: only alert when deny count exceeds the baseline
  | where DenyCount > threshold
  | project TimeGenerated, SourceIP, DenyCount, DistinctPorts, DistinctTargets, TargetPorts, TargetIPs
  | order by DenyCount desc
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  DenyCount: DenyCount
  DistinctPorts: DistinctPorts
  DistinctTargets: DistinctTargets
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log Types and Subtypes:** https://docs.fortinet.com/document/fortigate/7.6.2/fortios-log-message-reference/670197/log-types-and-subtypes
- **Traffic Logging:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
