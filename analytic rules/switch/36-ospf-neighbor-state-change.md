**Author:** Goodness Caleb Ibeh

# OSPF Neighbor State Change

Detects OSPF neighbor or interface state changes on the switch. OSPF adjacency changes affect routing convergence and traffic forwarding. A neighbor transitioning from Full to Down indicates a lost adjacency, which can result from link failure, configuration changes, or an attacker injecting malicious OSPF packets. Unexpected state changes in a stable environment are always worth investigating.

**Importance:** SOC analysts should investigate OSPF state changes in stable environments because they may indicate routing attacks, unauthorized route injection, or infrastructure failures affecting traffic forwarding.

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — OSPF.NbrStateChg / OSPF.IntfStateChg — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for OSPF state change events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match OSPF neighbor and interface state change events
| where SyslogMessage has_any ("OSPF.NbrStateChg", "OSPF.IntfStateChg")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| extend
    AlertTitle = "OSPF Neighbor State Change",
    AlertDescription = "OSPF neighbor or interface state change detected, which may indicate routing attacks or infrastructure failures.",
    AlertSeverity = "Medium"
| project TimeGenerated, HostName, Severity, Component, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 981893a6-2824-4f21-80f9-f494fdb021ed
name: "OSPF Neighbor State Change"
description: |
  Detects OSPF neighbor or interface state changes on the switch. OSPF adjacency changes affect routing convergence and traffic forwarding. A neighbor transitioning from Full to Down indicates a lost adjacency, which can result from link failure, configuration changes, or an attacker injecting malicious OSPF packets. Unexpected state changes in a stable environment are always worth investigating.
  SOC analysts should investigate OSPF state changes in stable environments because they may indicate routing attacks, unauthorized route injection, or infrastructure failures affecting traffic forwarding.
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
  - CredentialAccess
relevantTechniques:
  - T1557
query: |
  // Lookback: 24 hours for OSPF state change events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match OSPF neighbor and interface state change events
  | where SyslogMessage has_any ("OSPF.NbrStateChg", "OSPF.IntfStateChg")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | extend
      AlertTitle = "OSPF Neighbor State Change",
      AlertDescription = "OSPF neighbor or interface state change detected, which may indicate routing attacks or infrastructure failures.",
      AlertSeverity = "Medium"
  | project TimeGenerated, HostName, Severity, Component, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc

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
  Component: Component
  Severity: Severity
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — OSPF Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
