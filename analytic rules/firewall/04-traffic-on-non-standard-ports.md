**Author:** Goodness Caleb Ibeh

# Traffic on Non-Standard Ports

Detects allowed outbound connections on non-standard ports (above 1024 and not in the common services list). Attackers frequently use non-standard ports to evade basic firewall rules and detection, tunneling C2 traffic or exfiltration channels over unusual port numbers. While some legitimate applications use high ports, repeated connections from LAN hosts to uncommon ports deserve scrutiny.

**Importance:** Non-standard port usage can indicate C2 channels, tunneling, or protocol abuse that bypasses traditional port-based security controls.

**MITRE:** T1571 — Non-Standard Port
**Severity:** Low

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
// Reference: FortiOS Traffic Log — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
let lookback = 24h;
// Define well-known legitimate service ports to exclude
let StandardPorts = dynamic([20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 8080, 8443]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections
| where DeviceAction in ("accept", "close")
// Exclude all well-known standard ports
| where DestinationPort !in (StandardPorts)
// Focus on ephemeral/high ports that are more suspicious
| where DestinationPort > 1024
// Extract source interface role to focus on LAN-originated traffic
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// Only consider traffic originating from internal LAN hosts
| where SrcIntfRole == "lan"
// Aggregate connection counts per destination IP/port combination in 1-hour bins
| summarize
    ConnectionCount = count(),
    DistinctSources = dcount(SourceIP),
    Sources = make_set(SourceIP, 10)
  by DestinationIP, DestinationPort, ApplicationProtocol, bin(TimeGenerated, 1h)
// Threshold filter: only flag ports with significant activity
| where ConnectionCount > 20
| order by ConnectionCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d6f4b1a5-7c9e-4d2b-e0f6-4a5b8c1d3e2f
name: "Traffic on Non-Standard Ports"
description: |
  Detects allowed outbound connections on non-standard ports (above 1024 and not in the common services list). Non-standard port usage can indicate C2 channels, tunneling, or protocol abuse that bypasses traditional port-based security controls. Designed for Fortinet FortiGate firewalls.
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
  - CommandAndControl
relevantTechniques:
  - T1571
query: |
  let lookback = 24h;
  // Define well-known legitimate service ports to exclude
  let StandardPorts = dynamic([20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 8080, 8443]);
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Only look at allowed/completed connections
  | where DeviceAction in ("accept", "close")
  // Exclude all well-known standard ports
  | where DestinationPort !in (StandardPorts)
  // Focus on ephemeral/high ports that are more suspicious
  | where DestinationPort > 1024
  // Extract source interface role to focus on LAN-originated traffic
  | extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
  // Only consider traffic originating from internal LAN hosts
  | where SrcIntfRole == "lan"
  // Aggregate connection counts per destination IP/port combination in 1-hour bins
  | summarize
      ConnectionCount = count(),
      DistinctSources = dcount(SourceIP),
      Sources = make_set(SourceIP, 10)
    by DestinationIP, DestinationPort, ApplicationProtocol, bin(TimeGenerated, 1h)
  // Threshold filter: only flag ports with significant activity
  | where ConnectionCount > 20
  | order by ConnectionCount desc
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
customDetails:
  DeviceAction: DeviceAction
  ConnectionCount: ConnectionCount
  ApplicationProtocol: ApplicationProtocol
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log Types and Subtypes:** https://docs.fortinet.com/document/fortigate/7.6.2/fortios-log-message-reference/670197/log-types-and-subtypes
- **Traffic Logging:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
