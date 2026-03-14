**Author:** Goodness Caleb Ibeh

# MAC Address Movement — Potential ARP Spoofing

Detects when a MAC address rapidly moves between different switch ports, which may indicate ARP spoofing or MAC spoofing attacks. In a legitimate network, MAC addresses remain relatively stable on their connected ports. Frequent movement suggests an attacker is impersonating another device or that there is a network loop causing instability.

**Importance:** SOC analysts should investigate MAC movement patterns as they are a strong indicator of man-in-the-middle attacks via ARP cache poisoning.

**MITRE:** T1557.002 — ARP Cache Poisoning

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — FDB.MACTracking — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours of MAC tracking data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match FDB MAC tracking/movement events
| where SyslogMessage has "FDB.MACTracking"
// Extract the MAC address that moved
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
// Extract source and destination ports of the movement
| extend FromPort = extract(@"from port\s+(\S+)", 1, SyslogMessage)
| extend ToPort = extract(@"to port\s+(\S+)", 1, SyslogMessage)
// Extract VLAN context
| extend VLANName = extract(@"VLAN\s+\"([^\"]+)\"", 1, SyslogMessage)
// Aggregate movement events per MAC in 15-minute windows to detect rapid flapping
| summarize
    MoveCount = count(),
    SourcePorts = make_set(FromPort, 10),
    DestPorts = make_set(ToPort, 10)
  by HostName, MACAddress, VLANName, bin(TimeGenerated, 15m)
// Threshold: more than 3 moves in 15 minutes is suspicious
| where MoveCount > 3 // Frequent MAC movement is suspicious
| order by MoveCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 5544fcf8-8896-4bf1-967f-005687b9815e
name: "MAC Address Movement — Potential ARP Spoofing"
description: |
  Detects when a MAC address rapidly moves between different switch ports, which may indicate ARP spoofing or MAC spoofing attacks. In a legitimate network, MAC addresses remain relatively stable on their connected ports. Frequent movement suggests an attacker is impersonating another device or that there is a network loop causing instability.
  SOC analysts should investigate MAC movement patterns as they are a strong indicator of man-in-the-middle attacks via ARP cache poisoning.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1557.002
query: |
  // Lookback: 24 hours of MAC tracking data
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match FDB MAC tracking/movement events
  | where SyslogMessage has "FDB.MACTracking"
  // Extract the MAC address that moved
  | extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  // Extract source and destination ports of the movement
  | extend FromPort = extract(@"from port\s+(\S+)", 1, SyslogMessage)
  | extend ToPort = extract(@"to port\s+(\S+)", 1, SyslogMessage)
  // Extract VLAN context
  | extend VLANName = extract(@"VLAN\s+\"([^\"]+)\"", 1, SyslogMessage)
  // Aggregate movement events per MAC in 15-minute windows to detect rapid flapping
  | summarize
      MoveCount = count(),
      SourcePorts = make_set(FromPort, 10),
      DestPorts = make_set(ToPort, 10)
    by HostName, MACAddress, VLANName, bin(TimeGenerated, 15m)
  // Threshold: more than 3 moves in 15 minutes is suspicious
  | where MoveCount > 3 // Frequent MAC movement is suspicious
  | order by MoveCount desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  MACAddress: MACAddress
  VLANName: VLANName
  MoveCount: MoveCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — MAC Locking Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-19173DB1-1312-4576-BB1E-CA8A224AE14F.shtml)
- [Extreme Networks — FDB EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
