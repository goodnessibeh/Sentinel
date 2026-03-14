**Author:** Goodness Caleb Ibeh

# DMZ Lateral Movement — Unexpected Inter-Zone Traffic

Detects allowed connections from DMZ hosts into the LAN or between DMZ hosts. In a properly segmented network, DMZ servers should only accept inbound connections from the internet and respond — they should never initiate connections into the LAN. DMZ-to-LAN or DMZ-to-DMZ lateral traffic is a critical indicator that a DMZ-hosted server has been compromised and the attacker is pivoting deeper into the network.

**Importance:** DMZ-to-LAN traffic violates fundamental network segmentation principles and strongly suggests an attacker has compromised a public-facing server and is pivoting internally.

**MITRE:** T1021 — Remote Services
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
// Reference: FortiOS Traffic Log — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections — these are the dangerous ones
| where DeviceAction in ("accept", "close")
// Extract source and destination interface roles to determine traffic zones
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
| extend DstIntfRole = extract("FTNTFGTdstintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// DMZ to LAN is unexpected — also flag DMZ-to-DMZ lateral movement between different hosts
| where (SrcIntfRole == "dmz" and DstIntfRole == "lan")
   or (SrcIntfRole == "dmz" and DstIntfRole == "dmz" and SourceIP != DestinationIP)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          ApplicationProtocol, DeviceInboundInterface, DeviceOutboundInterface,
          SrcIntfRole, DstIntfRole, SentBytes, ReceivedBytes
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f8b6d3c7-9e1a-4f4d-a2b8-6c7d0e3f5a4b
name: "DMZ Lateral Movement — Unexpected Inter-Zone Traffic"
description: |
  Detects allowed connections from DMZ hosts into the LAN or between DMZ hosts. DMZ-to-LAN traffic violates fundamental network segmentation principles and strongly suggests an attacker has compromised a public-facing server and is pivoting internally. Designed for Fortinet FortiGate firewalls.
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
  - LateralMovement
relevantTechniques:
  - T1021
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Only look at allowed/completed connections — these are the dangerous ones
  | where DeviceAction in ("accept", "close")
  // Extract source and destination interface roles to determine traffic zones
  | extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
  | extend DstIntfRole = extract("FTNTFGTdstintfrole=([^;\\s]+)", 1, AdditionalExtensions)
  // DMZ to LAN is unexpected — also flag DMZ-to-DMZ lateral movement between different hosts
  | where (SrcIntfRole == "dmz" and DstIntfRole == "lan")
     or (SrcIntfRole == "dmz" and DstIntfRole == "dmz" and SourceIP != DestinationIP)
  | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
            ApplicationProtocol, DeviceInboundInterface, DeviceOutboundInterface,
            SrcIntfRole, DstIntfRole, SentBytes, ReceivedBytes
  | order by TimeGenerated desc
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
  SrcIntfRole: SrcIntfRole
  DstIntfRole: DstIntfRole
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log Types and Subtypes:** https://docs.fortinet.com/document/fortigate/7.6.2/fortios-log-message-reference/670197/log-types-and-subtypes
- **Traffic Logging:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
