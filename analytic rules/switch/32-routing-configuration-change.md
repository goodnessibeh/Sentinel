**Author:** Goodness Caleb Ibeh

# Routing Configuration Change

Detects when routing protocol configurations (OSPF, BGP, RIP, IS-IS) or static routes are modified on the switch. Routing changes directly affect how traffic flows through the network. An attacker who modifies routing can redirect traffic through attacker-controlled paths for interception, create black holes to deny service, or inject malicious routes to intercept traffic destined for specific subnets.

**Importance:** SOC analysts should investigate routing configuration changes because unauthorized modifications can enable traffic interception, black hole routing, or route hijacking attacks.

**MITRE:** T1565 — Data Manipulation

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CLI.logRemoteCmd (ospf/bgp/isis) — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for routing configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match routing protocol configuration commands across all protocols
| where SyslogMessage has_any (
    "configure ospf", "enable ospf", "disable ospf",
    "configure bgp", "enable bgp", "disable bgp",
    "configure rip", "enable rip", "disable rip",
    "configure isis", "enable isis", "disable isis",
    "iproute", "static route", "route-map", "prefix-list",
    "configure ospf area", "configure bgp neighbor",
    "create ospf", "delete ospf",
    "create bgp", "delete bgp"
  )
| extend
    AlertTitle = "Routing Configuration Change",
    AlertDescription = "Routing protocol configurations or static routes were modified on the switch, which may enable traffic interception or route hijacking.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: ec3e1831-9f06-4c87-9d8b-369c419af4c3
name: "Routing Configuration Change"
description: |
  Detects when routing protocol configurations (OSPF, BGP, RIP, IS-IS) or static routes are modified on the switch. Routing changes directly affect how traffic flows through the network. An attacker who modifies routing can redirect traffic through attacker-controlled paths for interception, create black holes to deny service, or inject malicious routes to intercept traffic destined for specific subnets.
  SOC analysts should investigate routing configuration changes because unauthorized modifications can enable traffic interception, black hole routing, or route hijacking attacks.
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
  - T1565
query: |
  // Lookback: 24 hours for routing configuration changes
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // First filter: match CLI command log events
  | where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
  // Key filter: match routing protocol configuration commands across all protocols
  | where SyslogMessage has_any (
      "configure ospf", "enable ospf", "disable ospf",
      "configure bgp", "enable bgp", "disable bgp",
      "configure rip", "enable rip", "disable rip",
      "configure isis", "enable isis", "disable isis",
      "iproute", "static route", "route-map", "prefix-list",
      "configure ospf area", "configure bgp neighbor",
      "create ospf", "delete ospf",
      "create bgp", "delete bgp"
    )
  | extend
      AlertTitle = "Routing Configuration Change",
      AlertDescription = "Routing protocol configurations or static routes were modified on the switch, which may enable traffic interception or route hijacking.",
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

- [Extreme Networks — OSPF Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — BGP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
