**Author:** Goodness Caleb Ibeh

# CDP Neighbor Timeout

Detects when a CDP (Cisco Discovery Protocol) neighbor times out on the switch. In mixed-vendor environments, CDP timeouts indicate that a previously connected Cisco device is no longer reachable. This may indicate link failure, device failure, or physical disconnection. While CDP is primarily a Cisco protocol, Extreme switches can receive and process CDP frames.

**Importance:** SOC analysts should monitor CDP timeouts in multi-vendor environments to detect device disappearances that may indicate infrastructure issues or unauthorized disconnections.

**MITRE:** T1200 — Hardware Additions

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CDP.Timeout — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for CDP timeout events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match CDP neighbor timeout events
| where SyslogMessage has "CDP.Timeout"
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 5d9b2057-704d-482b-a4ac-9275ff0e9b10
name: "CDP Neighbor Timeout"
description: |
  Detects when a CDP (Cisco Discovery Protocol) neighbor times out on the switch. In mixed-vendor environments, CDP timeouts indicate that a previously connected Cisco device is no longer reachable. This may indicate link failure, device failure, or physical disconnection. While CDP is primarily a Cisco protocol, Extreme switches can receive and process CDP frames.
  SOC analysts should monitor CDP timeouts in multi-vendor environments to detect device disappearances that may indicate infrastructure issues or unauthorized disconnections.
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
  // Lookback: 24 hours for CDP timeout events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match CDP neighbor timeout events
  | where SyslogMessage has "CDP.Timeout"
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

- [Extreme Networks — CDP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
