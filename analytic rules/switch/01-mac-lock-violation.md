**Author:** Goodness Caleb Ibeh

# MAC Lock Violation — Unauthorized Device

Detects when a device with an unauthorized MAC address attempts to connect to a MAC-locked port on the switch. MAC locking restricts which devices can communicate through specific ports, so a violation indicates a device that is not in the approved list is attempting network access. This is a common indicator of unauthorized device connections or potential network intrusion attempts.

**Importance:** SOC analysts should investigate immediately as this may indicate an attacker plugging a rogue device into a secured network port to gain unauthorized access.

**MITRE:** T1200 — Hardware Additions

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — FDB.MacLocking — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours of syslog data for MAC lock violations
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs via facility
| where Facility == "local7"
// Key filter: match FDB MAC locking violation EMS messages
| where SyslogMessage has "FDB.MacLocking"
// Parse out the severity, component, and port from the structured EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" * "Port " Port " " Rest
// Extract the offending MAC address using regex
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Severity, Port, MACAddress, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 213ede62-e7c7-499f-b3a5-b6e6d4cf0090
name: "MAC Lock Violation — Unauthorized Device"
description: |
  Detects when a device with an unauthorized MAC address attempts to connect to a MAC-locked port on the switch. MAC locking restricts which devices can communicate through specific ports, so a violation indicates a device that is not in the approved list is attempting network access. This is a common indicator of unauthorized device connections or potential network intrusion attempts.
  SOC analysts should investigate immediately as this may indicate an attacker plugging a rogue device into a secured network port to gain unauthorized access.
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
  - InitialAccess
relevantTechniques:
  - T1200
query: |
  // Lookback: 24 hours of syslog data for MAC lock violations
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs via facility
  | where Facility == "local7"
  // Key filter: match FDB MAC locking violation EMS messages
  | where SyslogMessage has "FDB.MacLocking"
  // Parse out the severity, component, and port from the structured EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" * "Port " Port " " Rest
  // Extract the offending MAC address using regex
  | extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, Severity, Port, MACAddress, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Port: Port
  MACAddress: MACAddress
  Severity: Severity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — MAC Locking Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-19173DB1-1312-4576-BB1E-CA8A224AE14F.shtml)
- [Extreme Networks — FDB EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
