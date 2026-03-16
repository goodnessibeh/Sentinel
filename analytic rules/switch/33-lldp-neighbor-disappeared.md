**Author:** Goodness Caleb Ibeh

# LLDP Neighbor Disappeared — Link Loss

Detects when an LLDP (Link Layer Discovery Protocol) neighbor is removed from the switch's neighbor table, indicating that a previously connected device is no longer reachable. LLDP neighbor disappearances can indicate a physical link failure, a device being powered off or rebooted, or a cable being disconnected. Multiple simultaneous disappearances may indicate a larger infrastructure failure.

**Importance:** SOC analysts should investigate LLDP neighbor disappearances because they may indicate physical tampering, unauthorized device removal, or infrastructure failures that affect network connectivity.

**MITRE:** T1200 — Hardware Additions

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — LLDP.NbrRemove — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for LLDP neighbor removal events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match LLDP neighbor removal events
| where SyslogMessage has "LLDP.NbrRemove"
// Extract the port where the neighbor was lost
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, SyslogMessage
// Aggregate lost neighbors per switch in 30-minute bins to detect mass losses
| summarize
    LostNeighbors = count(),
    AffectedPorts = make_set(Port, 20)
  by HostName, bin(TimeGenerated, 30m)
| extend
    AlertTitle = "LLDP Neighbor Disappeared — Link Loss",
    AlertDescription = "An LLDP neighbor was removed from the switch neighbor table, indicating a previously connected device is no longer reachable.",
    AlertSeverity = "Medium"
| order by LostNeighbors desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: e166e335-c456-4707-8eda-dd08559f3e00
name: "LLDP Neighbor Disappeared — Link Loss"
description: |
  Detects when an LLDP (Link Layer Discovery Protocol) neighbor is removed from the switch's neighbor table, indicating that a previously connected device is no longer reachable. LLDP neighbor disappearances can indicate a physical link failure, a device being powered off or rebooted, or a cable being disconnected. Multiple simultaneous disappearances may indicate a larger infrastructure failure.
  SOC analysts should investigate LLDP neighbor disappearances because they may indicate physical tampering, unauthorized device removal, or infrastructure failures that affect network connectivity.
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
  - InitialAccess
relevantTechniques:
  - T1200
query: |
  // Lookback: 24 hours for LLDP neighbor removal events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match LLDP neighbor removal events
  | where SyslogMessage has "LLDP.NbrRemove"
  // Extract the port where the neighbor was lost
  | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, Port, SyslogMessage
  // Aggregate lost neighbors per switch in 30-minute bins to detect mass losses
  | summarize
      LostNeighbors = count(),
      AffectedPorts = make_set(Port, 20)
    by HostName, bin(TimeGenerated, 30m)
  | extend
      AlertTitle = "LLDP Neighbor Disappeared — Link Loss",
      AlertDescription = "An LLDP neighbor was removed from the switch neighbor table, indicating a previously connected device is no longer reachable.",
      AlertSeverity = "Medium"
  | order by LostNeighbors desc

alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  LostNeighbors: LostNeighbors
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — LLDP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
