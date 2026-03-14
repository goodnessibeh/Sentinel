**Author:** Goodness Caleb Ibeh

# New LLDP Neighbor — Rogue Device Detection

Detects when a new LLDP neighbor appears on a switch port. While new neighbors are expected during legitimate deployments, unexpected neighbors may indicate a rogue device such as an unauthorized switch, access point, or network tap being connected to the infrastructure. Cross-referencing new neighbors against a known device inventory is essential for identifying unauthorized devices.

**Importance:** SOC analysts should investigate new LLDP neighbors that do not correspond to approved change requests, as they may indicate unauthorized device deployment or physical intrusion.

**MITRE:** T1200 — Hardware Additions

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — LLDP.NbrAdd — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for new LLDP neighbor events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match LLDP neighbor addition events
| where SyslogMessage has "LLDP.NbrAdd"
// Extract the port where the new neighbor was detected
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, SyslogMessage
| order by TimeGenerated desc
```

**Tuning:** Cross-reference new neighbors against a known device inventory to identify unauthorized devices.

---

## Sentinel Analytics Rule — YAML

```yaml
id: 74a8e8f1-576b-472a-9c63-842717581fe7
name: "New LLDP Neighbor — Rogue Device Detection"
description: |
  Detects when a new LLDP neighbor appears on a switch port. While new neighbors are expected during legitimate deployments, unexpected neighbors may indicate a rogue device such as an unauthorized switch, access point, or network tap being connected to the infrastructure. Cross-referencing new neighbors against a known device inventory is essential for identifying unauthorized devices.
  SOC analysts should investigate new LLDP neighbors that do not correspond to approved change requests, as they may indicate unauthorized device deployment or physical intrusion.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Low
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
  // Lookback: 24 hours for new LLDP neighbor events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match LLDP neighbor addition events
  | where SyslogMessage has "LLDP.NbrAdd"
  // Extract the port where the new neighbor was detected
  | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, Port, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Port: Port
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — LLDP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
