**Author:** Goodness Caleb Ibeh

# DHCP Snooping Violation — Rogue DHCP Server

Detects DHCP snooping violations that occur when a DHCP server response is received on an untrusted port. This is a critical indicator of a rogue DHCP server on the network, which an attacker can use to distribute malicious DNS servers, default gateways, or IP configurations to redirect victim traffic. DHCP snooping is a first-line defense against this attack vector.

**Importance:** SOC analysts must investigate immediately because a rogue DHCP server can compromise every new device that joins the network, enabling widespread man-in-the-middle attacks.

**MITRE:** T1557.003 — DHCP Spoofing

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — ipSecur.dhcpViol — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours of DHCP snooping violation data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match DHCP snooping violation messages
| where SyslogMessage has "ipSecur.dhcpViol"
// Extract port, VLAN, and source MAC for incident context
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
| extend SourceMAC = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, VLANName, SourceMAC, SyslogMessage
// Aggregate violations per host per hour to identify persistent rogue servers
| summarize
    ViolationCount = count(),
    Ports = make_set(Port, 10),
    VLANs = make_set(VLANName, 5),
    MACs = make_set(SourceMAC, 10)
  by HostName, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "DHCP Snooping Violation — Rogue DHCP Server",
    AlertDescription = "DHCP snooping violation detected on an untrusted port, indicating a potential rogue DHCP server on the network.",
    AlertSeverity = "High"
| order by ViolationCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d5c66169-f0f7-4ca3-b308-7a7c4fb40de0
name: "DHCP Snooping Violation — Rogue DHCP Server"
description: |
  Detects DHCP snooping violations that occur when a DHCP server response is received on an untrusted port. This is a critical indicator of a rogue DHCP server on the network, which an attacker can use to distribute malicious DNS servers, default gateways, or IP configurations to redirect victim traffic. DHCP snooping is a first-line defense against this attack vector.
  SOC analysts must investigate immediately because a rogue DHCP server can compromise every new device that joins the network, enabling widespread man-in-the-middle attacks.
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
  - T1557.003
query: |
  // Lookback: 24 hours of DHCP snooping violation data
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match DHCP snooping violation messages
  | where SyslogMessage has "ipSecur.dhcpViol"
  // Extract port, VLAN, and source MAC for incident context
  | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
  | extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
  | extend SourceMAC = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, Port, VLANName, SourceMAC, SyslogMessage
  // Aggregate violations per host per hour to identify persistent rogue servers
  | summarize
      ViolationCount = count(),
      Ports = make_set(Port, 10),
      VLANs = make_set(VLANName, 5),
      MACs = make_set(SourceMAC, 10)
    by HostName, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "DHCP Snooping Violation — Rogue DHCP Server",
      AlertDescription = "DHCP snooping violation detected on an untrusted port, indicating a potential rogue DHCP server on the network.",
      AlertSeverity = "High"
  | order by ViolationCount desc

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
  ViolationCount: ViolationCount
  VLANName: VLANName
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — DHCP Snooping Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — IP Security Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — ipSecur EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
