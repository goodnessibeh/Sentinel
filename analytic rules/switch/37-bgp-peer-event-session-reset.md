**Author:** Goodness Caleb Ibeh

# BGP Peer Event — Session Reset

Detects BGP session resets, failures, and state transitions to down/idle states. BGP session disruptions can cause route withdrawals and reconvergence, leading to traffic blackholing or suboptimal routing. In a targeted attack, an adversary may send TCP RST packets or exploit BGP vulnerabilities to tear down peering sessions and disrupt network routing.

**Importance:** SOC analysts should investigate BGP session resets because they can indicate a targeted routing attack, peering misconfiguration, or infrastructure failure affecting upstream connectivity.

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — BGP.event / BGP.misc — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for BGP session events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match BGP event and miscellaneous messages
| where SyslogMessage has_any ("BGP.event", "BGP.misc")
// Further filter to session disruption keywords only
| where SyslogMessage has_any ("Down", "down", "Reset", "reset", "Idle", "idle", "cease")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: dab99e0f-689a-40e6-9d55-1671ffa41bbd
name: "BGP Peer Event — Session Reset"
description: |
  Detects BGP session resets, failures, and state transitions to down/idle states. BGP session disruptions can cause route withdrawals and reconvergence, leading to traffic blackholing or suboptimal routing. In a targeted attack, an adversary may send TCP RST packets or exploit BGP vulnerabilities to tear down peering sessions and disrupt network routing.
  SOC analysts should investigate BGP session resets because they can indicate a targeted routing attack, peering misconfiguration, or infrastructure failure affecting upstream connectivity.
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
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 24 hours for BGP session events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match BGP event and miscellaneous messages
  | where SyslogMessage has_any ("BGP.event", "BGP.misc")
  // Further filter to session disruption keywords only
  | where SyslogMessage has_any ("Down", "down", "Reset", "reset", "Idle", "idle", "cease")
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

- [Extreme Networks — BGP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
