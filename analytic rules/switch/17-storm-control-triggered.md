**Author:** Goodness Caleb Ibeh

# Storm Control Triggered

Detects when the switch's storm control (bandwidth management) feature triggers because broadcast, multicast, or unknown unicast traffic has exceeded the configured threshold on a port. Traffic storms consume all available bandwidth and processing capacity, causing network-wide disruption. Storm control triggers often coincide with loop conditions, broadcast amplification attacks, or malfunctioning NICs.

**Importance:** SOC analysts should investigate storm control triggers as they may indicate an active broadcast storm, network loop, or deliberate traffic amplification attack.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — bwMgr.Warning / bwMgr.Critical — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for storm control events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match bandwidth manager warnings/critical events or storm-related keywords
| where SyslogMessage has_any ("bwMgr.Warning", "bwMgr.Critical")
    or (SyslogMessage has "storm" and SyslogMessage has_any ("control", "detect", "threshold"))
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b02b3e32-50c0-4a80-8cc2-c4aa701c246e
name: "Storm Control Triggered"
description: |
  Detects when the switch's storm control (bandwidth management) feature triggers because broadcast, multicast, or unknown unicast traffic has exceeded the configured threshold on a port. Traffic storms consume all available bandwidth and processing capacity, causing network-wide disruption. Storm control triggers often coincide with loop conditions, broadcast amplification attacks, or malfunctioning NICs.
  SOC analysts should investigate storm control triggers as they may indicate an active broadcast storm, network loop, or deliberate traffic amplification attack.
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
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 24 hours for storm control events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match bandwidth manager warnings/critical events or storm-related keywords
  | where SyslogMessage has_any ("bwMgr.Warning", "bwMgr.Critical")
      or (SyslogMessage has "storm" and SyslogMessage has_any ("control", "detect", "threshold"))
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | project TimeGenerated, HostName, Severity, Component, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Component: Component
  Severity: Severity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Storm Control / Rate Limiting (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
