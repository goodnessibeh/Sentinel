**Author:** Goodness Caleb Ibeh

# DHCP Snooping Port/MAC Blocked

Detects when the switch's DHCP snooping feature actively blocks a port or MAC address due to a security violation. This means the switch has taken enforcement action against a device that violated DHCP security policy, such as sending unauthorized DHCP responses or exceeding rate limits. The block may be temporary or permanent depending on configuration.

**Importance:** SOC analysts should investigate blocked ports/MACs as they confirm that a security violation was severe enough to trigger automated enforcement, indicating an active threat or misconfigured device.

**MITRE:** T1557.003 — DHCP Spoofing

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — ipSecur.blkPort / ipSecur.blkMac — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours of DHCP snooping block events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match port-blocked or MAC-blocked events from IP security
| where SyslogMessage has_any ("ipSecur.blkPort", "ipSecur.blkMac")
// Extract port, MAC, and block duration for triage
| extend Port = extract(@"[Pp]ort\s+(\S+)", 1, SyslogMessage)
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| extend BlockDuration = extract(@"(\d+)\s+seconds", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, MACAddress, BlockDuration, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 63860ca2-ae25-4f9b-bb77-dc5e7ced66b7
name: "DHCP Snooping Port/MAC Blocked"
description: |
  Detects when the switch's DHCP snooping feature actively blocks a port or MAC address due to a security violation. This means the switch has taken enforcement action against a device that violated DHCP security policy, such as sending unauthorized DHCP responses or exceeding rate limits. The block may be temporary or permanent depending on configuration.
  SOC analysts should investigate blocked ports/MACs as they confirm that a security violation was severe enough to trigger automated enforcement, indicating an active threat or misconfigured device.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
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
  - T1557.003
query: |
  // Lookback: 24 hours of DHCP snooping block events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match port-blocked or MAC-blocked events from IP security
  | where SyslogMessage has_any ("ipSecur.blkPort", "ipSecur.blkMac")
  // Extract port, MAC, and block duration for triage
  | extend Port = extract(@"[Pp]ort\s+(\S+)", 1, SyslogMessage)
  | extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  | extend BlockDuration = extract(@"(\d+)\s+seconds", 1, SyslogMessage)
  | project TimeGenerated, HostName, Port, MACAddress, BlockDuration, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Port: Port
  MACAddress: MACAddress
  BlockDuration: BlockDuration
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — DHCP Snooping Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — IP Security Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — ipSecur EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
