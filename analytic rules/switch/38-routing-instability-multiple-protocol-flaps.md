**Author:** Goodness Caleb Ibeh

# Routing Instability — Multiple Protocol Flaps

Detects when multiple routing protocol events (OSPF, BGP, IS-IS, RIP) occur in rapid succession on the same switch, indicating widespread routing instability. When multiple protocols flap simultaneously, it typically indicates a systemic issue such as a control plane overload, a route redistribution loop, or a targeted attack against the switch's routing processes.

**Importance:** SOC analysts should escalate routing instability alerts because simultaneous multi-protocol flapping can lead to widespread traffic blackholing and network partitioning.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — OSPF.NbrStateChg / BGP.event / ISIS.AdjState — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 30-minute window for detecting routing instability
let lookback = 30m;
// Threshold: more than 5 routing events in 15 minutes indicates instability
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match routing protocol state change events across all protocols
| where SyslogMessage has_any (
    "OSPF.NbrStateChg", "OSPF.IntfStateChg",
    "BGP.event", "BGP.misc",
    "ISIS.AdjState",
    "RIP.Config"
  )
// Parse component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Aggregate routing events per switch in 15-minute bins, tracking which protocols are affected
| summarize
    EventCount = count(),
    Protocols = make_set(TopComponent = tostring(split(Component, ".")[0]), 5),
    Messages = make_set(SyslogMessage, 10)
  by HostName, bin(TimeGenerated, 15m)
// Detection logic: alert when event count exceeds instability threshold
| where EventCount > threshold
| project TimeGenerated, HostName, EventCount, Protocols, Messages
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 941ba1aa-69bb-4d33-8ab0-8ea4008c0885
name: "Routing Instability — Multiple Protocol Flaps"
description: |
  Detects when multiple routing protocol events (OSPF, BGP, IS-IS, RIP) occur in rapid succession on the same switch, indicating widespread routing instability. When multiple protocols flap simultaneously, it typically indicates a systemic issue such as a control plane overload, a route redistribution loop, or a targeted attack against the switch's routing processes.
  SOC analysts should escalate routing instability alerts because simultaneous multi-protocol flapping can lead to widespread traffic blackholing and network partitioning.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 30m
queryPeriod: 30m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 30-minute window for detecting routing instability
  let lookback = 30m;
  // Threshold: more than 5 routing events in 15 minutes indicates instability
  let threshold = 5;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match routing protocol state change events across all protocols
  | where SyslogMessage has_any (
      "OSPF.NbrStateChg", "OSPF.IntfStateChg",
      "BGP.event", "BGP.misc",
      "ISIS.AdjState",
      "RIP.Config"
    )
  // Parse component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Aggregate routing events per switch in 15-minute bins, tracking which protocols are affected
  | summarize
      EventCount = count(),
      Protocols = make_set(TopComponent = tostring(split(Component, ".")[0]), 5),
      Messages = make_set(SyslogMessage, 10)
    by HostName, bin(TimeGenerated, 15m)
  // Detection logic: alert when event count exceeds instability threshold
  | where EventCount > threshold
  | project TimeGenerated, HostName, EventCount, Protocols, Messages

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  EventCount: EventCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — OSPF Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — BGP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
