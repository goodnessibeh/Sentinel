**Author:** Goodness Caleb Ibeh

# STP Root Bridge Change — Potential Attack

Detects when the root bridge for a Spanning Tree domain changes. The root bridge is the central node that determines the entire Layer 2 forwarding topology. An attacker can inject BPDUs with a lower bridge priority to force themselves to become the root bridge, enabling them to intercept all traffic traversing the spanning tree. This is one of the most dangerous Layer 2 attacks.

**Importance:** SOC analysts must investigate root bridge changes immediately because an unauthorized root bridge change gives an attacker the ability to see and manipulate all switched traffic in the affected domain.

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — STP.State.RootChg — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for root bridge change events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match STP root change events or related root keywords
| where SyslogMessage has "STP.State.RootChg"
    or (SyslogMessage has "STP" and SyslogMessage has_any ("Root", "root bridge", "root change"))
| extend
    AlertTitle = "STP Root Bridge Change — Potential Attack",
    AlertDescription = "The root bridge for a Spanning Tree domain has changed, potentially indicating a Layer 2 man-in-the-middle attack.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 9899cc73-7123-449c-89da-42d65e81b996
name: "STP Root Bridge Change — Potential Attack"
description: |
  Detects when the root bridge for a Spanning Tree domain changes. The root bridge is the central node that determines the entire Layer 2 forwarding topology. An attacker can inject BPDUs with a lower bridge priority to force themselves to become the root bridge, enabling them to intercept all traffic traversing the spanning tree. This is one of the most dangerous Layer 2 attacks.
  SOC analysts must investigate root bridge changes immediately because an unauthorized root bridge change gives an attacker the ability to see and manipulate all switched traffic in the affected domain.
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
  - CredentialAccess
relevantTechniques:
  - T1557
query: |
  // Lookback: 24 hours for root bridge change events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match STP root change events or related root keywords
  | where SyslogMessage has "STP.State.RootChg"
      or (SyslogMessage has "STP" and SyslogMessage has_any ("Root", "root bridge", "root change"))
  | extend
      AlertTitle = "STP Root Bridge Change — Potential Attack",
      AlertDescription = "The root bridge for a Spanning Tree domain has changed, potentially indicating a Layer 2 man-in-the-middle attack.",
      AlertSeverity = "High"
  | project TimeGenerated, HostName, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
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
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — STP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — STP TCN Events (Knowledge Base)](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000081945)
- [Extreme Networks — STP EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
