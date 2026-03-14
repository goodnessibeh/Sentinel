**Author:** Goodness Caleb Ibeh

# VOSS IS-IS/Fabric Connect Adjacency Change

Detects IS-IS adjacency state changes and Fabric Connect (SPBM) events on VOSS switches. IS-IS is the routing protocol that underpins Extreme's Fabric Connect architecture, and adjacency changes directly affect fabric connectivity and service reachability. A lost adjacency means traffic can no longer traverse that fabric link, potentially isolating network segments or services.

**Importance:** SOC analysts should investigate IS-IS/Fabric Connect adjacency changes because they can indicate fabric infrastructure failures, unauthorized topology modifications, or deliberate attacks against the fabric overlay network.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: Extreme Networks VOSS — ISIS.AdjState / SPBM — https://documentation.extremenetworks.com/VOSS/VSP8600/SW/80x/ConfigFabric_8.0_VSP86.pdf
// Lookback: 24 hours for IS-IS and SPBM adjacency events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Key filter: match IS-IS adjacency state, SPF calculation, and SPBM events (no Facility filter for VOSS)
| where SyslogMessage has_any ("ISIS.AdjState", "ISIS.SPF", "SPBM")
// Further filter to state disruption keywords
| where SyslogMessage has_any ("Down", "down", "Lost", "lost", "Change", "change")
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 4c8d5c42-be7f-4bb1-9097-27d6955992c7
name: "VOSS IS-IS/Fabric Connect Adjacency Change"
description: |
  Detects IS-IS adjacency state changes and Fabric Connect (SPBM) events on VOSS switches. IS-IS is the routing protocol that underpins Extreme's Fabric Connect architecture, and adjacency changes directly affect fabric connectivity and service reachability. A lost adjacency means traffic can no longer traverse that fabric link, potentially isolating network segments or services.
  SOC analysts should investigate IS-IS/Fabric Connect adjacency changes because they can indicate fabric infrastructure failures, unauthorized topology modifications, or deliberate attacks against the fabric overlay network.
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
  // Lookback: 24 hours for IS-IS and SPBM adjacency events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Key filter: match IS-IS adjacency state, SPF calculation, and SPBM events (no Facility filter for VOSS)
  | where SyslogMessage has_any ("ISIS.AdjState", "ISIS.SPF", "SPBM")
  // Further filter to state disruption keywords
  | where SyslogMessage has_any ("Down", "down", "Lost", "lost", "Change", "change")
  | project TimeGenerated, HostName, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — IS-IS / Fabric Connect Configuration (VSP 8600)](https://documentation.extremenetworks.com/VOSS/VSP8600/SW/80x/ConfigFabric_8.0_VSP86.pdf)
- [Extreme Networks — VOSS Logging Configuration (VSP 8600)](https://documentation.extremenetworks.com/VOSS/VSP8600/SW/80x/ConfigLogTech_8.0_VSP86.pdf)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
