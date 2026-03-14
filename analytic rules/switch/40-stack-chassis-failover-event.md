**Author:** Goodness Caleb Ibeh

# Stack/Chassis Failover Event

Detects failover events in stacked or chassis-based switch deployments, including master/backup transitions, slot failures, and power issues. Failover events indicate that the primary unit or component has failed and the backup has taken over. While failover is a designed resilience mechanism, unexpected failovers may indicate hardware failure, power issues, or an attacker deliberately crashing the primary unit to force a potentially less-secured backup to take over.

**Importance:** SOC analysts should investigate unexpected failover events because they may indicate hardware failure requiring immediate attention or deliberate sabotage of the primary switch unit.

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — cm.VSM / dm.Warn / ELSM.State — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for stack/chassis failover events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match stack management, device manager, and ELSM events
| where SyslogMessage has_any (
    "cm.VSM", "dm.Warn", "dm.Error",
    "ELSM.State", "ELSM.Transition",
    "epm.ProcCrash"
  )
// Further filter to failover-specific keywords
| where SyslogMessage has_any ("failover", "master", "backup", "standby",
    "stack", "slot", "power", "insufficient", "crash")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a6f192d1-ba6f-4082-a544-bd9689ba30e2
name: "Stack/Chassis Failover Event"
description: |
  Detects failover events in stacked or chassis-based switch deployments, including master/backup transitions, slot failures, and power issues. Failover events indicate that the primary unit or component has failed and the backup has taken over. While failover is a designed resilience mechanism, unexpected failovers may indicate hardware failure, power issues, or an attacker deliberately crashing the primary unit to force a potentially less-secured backup to take over.
  SOC analysts should investigate unexpected failover events because they may indicate hardware failure requiring immediate attention or deliberate sabotage of the primary switch unit.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Critical
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
  - T1499
query: |
  // Lookback: 24 hours for stack/chassis failover events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match stack management, device manager, and ELSM events
  | where SyslogMessage has_any (
      "cm.VSM", "dm.Warn", "dm.Error",
      "ELSM.State", "ELSM.Transition",
      "epm.ProcCrash"
    )
  // Further filter to failover-specific keywords
  | where SyslogMessage has_any ("failover", "master", "backup", "standby",
      "stack", "slot", "power", "insufficient", "crash")
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

- [Extreme Networks — Process Manager (EPM) (ExtremeXOS 22.5)](https://documentation.extremenetworks.com/exos_22.5/GUID-0353BCE6-5198-40D6-8E2A-31C8115FD13F.shtml)
- [Extreme Networks — EMS Severity Levels (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-D3F3B734-61C5-4F78-A6C6-198B56174DE2.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
