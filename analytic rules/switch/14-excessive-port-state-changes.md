**Author:** Goodness Caleb Ibeh

# Excessive Port State Changes — Anomaly

Detects when a specific switch port undergoes an abnormally high number of link state transitions (up/down) within a short window. Unlike the built-in flap detection in detection #13, this rule catches rapid oscillation patterns across all port state change messages. Excessive state changes on a port generate heavy control plane load and can cause MAC table instability.

**Importance:** SOC analysts should investigate excessive port state changes because they may indicate a deliberate link-layer attack, a failing device, or a physical security breach where cables are being tampered with.

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — HAL.Port.LinkUp / HAL.Port.LinkDown — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 10-minute window for detecting rapid port state changes
let lookback = 10m;
// Threshold: more than 10 state changes in the window is anomalous
let threshold = 10;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all port link state change messages (both EXOS and HAL variants)
| where SyslogMessage has_any ("portLinkStateUp", "portLinkStateDown", "HAL.Port.LinkUp", "HAL.Port.LinkDown")
// Extract port identifier and determine state direction
| extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
| extend PortState = iff(SyslogMessage has_any ("Up", "UP"), "Up", "Down")
// Aggregate state changes per port to find oscillating ports
| summarize
    FlipCount = count(),
    UpCount = countif(PortState == "Up"),
    DownCount = countif(PortState == "Down")
  by HostName, Port
// Detection logic: alert when total state changes exceed threshold
| where FlipCount > threshold
| extend
    AlertTitle = "Excessive Port State Changes — Anomaly",
    AlertDescription = "A switch port is undergoing an abnormally high number of link state transitions, indicating potential link-layer attack or hardware failure.",
    AlertSeverity = "Medium"
| project HostName, Port, FlipCount, UpCount, DownCount, AlertTitle, AlertDescription, AlertSeverity
| order by FlipCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 884594b9-152a-439a-a671-e6b8dd361d04
name: "Excessive Port State Changes — Anomaly"
description: |
  Detects when a specific switch port undergoes an abnormally high number of link state transitions (up/down) within a short window. Unlike the built-in flap detection in detection #13, this rule catches rapid oscillation patterns across all port state change messages. Excessive state changes on a port generate heavy control plane load and can cause MAC table instability.
  SOC analysts should investigate excessive port state changes because they may indicate a deliberate link-layer attack, a failing device, or a physical security breach where cables are being tampered with.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 10m
queryPeriod: 10m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 10-minute window for detecting rapid port state changes
  let lookback = 10m;
  // Threshold: more than 10 state changes in the window is anomalous
  let threshold = 10;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match all port link state change messages (both EXOS and HAL variants)
  | where SyslogMessage has_any ("portLinkStateUp", "portLinkStateDown", "HAL.Port.LinkUp", "HAL.Port.LinkDown")
  // Extract port identifier and determine state direction
  | extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
  | extend PortState = iff(SyslogMessage has_any ("Up", "UP"), "Up", "Down")
  // Aggregate state changes per port to find oscillating ports
  | summarize
      FlipCount = count(),
      UpCount = countif(PortState == "Up"),
      DownCount = countif(PortState == "Down")
    by HostName, Port
  // Detection logic: alert when total state changes exceed threshold
  | where FlipCount > threshold
  | extend
      AlertTitle = "Excessive Port State Changes — Anomaly",
      AlertDescription = "A switch port is undergoing an abnormally high number of link state transitions, indicating potential link-layer attack or hardware failure.",
      AlertSeverity = "Medium"
  | project HostName, Port, FlipCount, UpCount, DownCount, AlertTitle, AlertDescription, AlertSeverity
  | order by FlipCount desc

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
  Port: Port
  FlipCount: FlipCount
  UpCount: UpCount
  DownCount: DownCount
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Link-Flap Detection (ExtremeXOS 30.2)](https://documentation.extremenetworks.com/exos_30.2.2/GUID-657A01D2-799F-4CF7-94FE-29996520AFBA.shtml)
- [Extreme Networks — HAL Port EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
