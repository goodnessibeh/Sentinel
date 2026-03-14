**Author:** Goodness Caleb Ibeh

# Internal Port Scan Detection

Detects internal hosts that are scanning many ports or many hosts within a short time window. Internal port scanning is a hallmark of lateral movement — an attacker who has compromised one host will scan the internal network to discover additional services, open shares, or vulnerable systems. This detection focuses on denied connections from LAN hosts, which indicates probing of services that are not permitted by policy.

**Importance:** Internal port scanning from a LAN host is a strong indicator of a compromised machine performing lateral movement reconnaissance, requiring immediate host isolation and investigation.

**MITRE:** T1046 — Network Service Discovery
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Traffic Log — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
let lookback = 15m;
// Thresholds for distinct ports or hosts contacted — either triggers the detection
let portThreshold = 25;
let hostThreshold = 10;
CommonSecurityLog
// Filter to a short 15-minute window for real-time scan detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Focus on denied connections — the scan "noise" hitting policy blocks
| where DeviceAction == "deny"
// Extract source interface role to identify internal hosts
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// Only consider traffic originating from internal LAN hosts
| where SrcIntfRole == "lan"
// Count distinct ports and hosts contacted per source IP
| summarize
    DistinctPorts = dcount(DestinationPort),
    DistinctHosts = dcount(DestinationIP),
    PortList = make_set(DestinationPort, 50),
    HostList = make_set(DestinationIP, 20)
  by SourceIP
// Alert if the source touched too many ports OR too many hosts
| where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
| project SourceIP, DistinctPorts, DistinctHosts, PortList, HostList
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: e7a5c2b6-8d0f-4e3c-f1a7-5b6c9d2e4f3a
name: "Internal Port Scan Detection"
description: |
  Detects internal hosts that are scanning many ports or many hosts within a short time window. Internal port scanning from a LAN host is a strong indicator of a compromised machine performing lateral movement reconnaissance, requiring immediate host isolation and investigation. Designed for Fortinet FortiGate firewalls.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 15m
queryPeriod: 15m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Discovery
relevantTechniques:
  - T1046
query: |
  let lookback = 15m;
  // Thresholds for distinct ports or hosts contacted — either triggers the detection
  let portThreshold = 25;
  let hostThreshold = 10;
  CommonSecurityLog
  // Filter to a short 15-minute window for real-time scan detection
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Focus on denied connections — the scan "noise" hitting policy blocks
  | where DeviceAction == "deny"
  // Extract source interface role to identify internal hosts
  | extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
  // Only consider traffic originating from internal LAN hosts
  | where SrcIntfRole == "lan"
  // Count distinct ports and hosts contacted per source IP
  | summarize
      DistinctPorts = dcount(DestinationPort),
      DistinctHosts = dcount(DestinationIP),
      PortList = make_set(DestinationPort, 50),
      HostList = make_set(DestinationIP, 20)
    by SourceIP
  // Alert if the source touched too many ports OR too many hosts
  | where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
  | project SourceIP, DistinctPorts, DistinctHosts, PortList, HostList
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  DistinctPorts: DistinctPorts
  DistinctHosts: DistinctHosts
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log Types and Subtypes:** https://docs.fortinet.com/document/fortigate/7.6.2/fortios-log-message-reference/670197/log-types-and-subtypes
- **Traffic Logging:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
