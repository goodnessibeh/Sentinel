**Author:** Goodness Caleb Ibeh

# DoS Anomaly Detection Triggered

Detects FortiGate DoS anomaly detection events, which fire when traffic patterns match known denial-of-service signatures such as SYN floods, UDP floods, ICMP floods, and other volumetric or protocol-based attacks. These events indicate that someone is actively attempting to overwhelm your network resources or specific services. The aggregation by source IP helps identify the top attacking hosts and their targets.

**Importance:** DoS anomaly events indicate active denial-of-service attacks that can disrupt critical services and may also serve as cover for simultaneous intrusion attempts occurring while the SOC is distracted.

**MITRE:** T1498 — Network Denial of Service
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Host | HostName | DeviceName |

```kql
// Reference: FortiOS Anomaly Log IDs 18432-18434 — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/18432/18432
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for anomaly detection log entries
| where Activity has "anomaly"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          DeviceAction, Message, DeviceName
// Aggregate anomaly events per source IP and device to identify top attackers
| summarize
    AnomalyCount = count(),
    Targets = make_set(DestinationIP, 10),
    Ports = make_set(DestinationPort, 10)
  by SourceIP, DeviceName
| order by AnomalyCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a1b7f4a8-0e2c-4a5d-b3d9-7e8f1a4b6c5d
name: "DoS Anomaly Detection Triggered"
description: |
  Detects FortiGate DoS anomaly detection events, which fire when traffic patterns match known denial-of-service signatures such as SYN floods, UDP floods, and ICMP floods. DoS anomaly events indicate active denial-of-service attacks that can disrupt critical services and may also serve as cover for simultaneous intrusion attempts. Designed for Fortinet FortiGate firewalls.
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
  - Impact
relevantTechniques:
  - T1498
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for anomaly detection log entries
  | where Activity has "anomaly"
  | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
            DeviceAction, Message, DeviceName
  // Aggregate anomaly events per source IP and device to identify top attackers
  | summarize
      AnomalyCount = count(),
      Targets = make_set(DestinationIP, 10),
      Ports = make_set(DestinationPort, 10)
    by SourceIP, DeviceName
  | order by AnomalyCount desc
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
  AnomalyCount: AnomalyCount
version: 1.0.0
kind: Scheduled
```

## References

- **DoS Protection:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/639498/dos-protection
- **Anomaly Log IDs 18432-18434:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/18432/18432
