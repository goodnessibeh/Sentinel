**Author:** Goodness Caleb Ibeh

# Dynamic ARP Inspection Violation

Detects ARP packets that fail Dynamic ARP Inspection (DAI) validation on the switch. DAI validates ARP packets against the DHCP snooping binding table to ensure the IP-to-MAC mapping is legitimate. Violations indicate that a device is sending ARP replies with forged IP-to-MAC mappings, which is the hallmark of ARP spoofing/poisoning attacks used for man-in-the-middle interception.

**Importance:** SOC analysts should treat DAI violations as strong evidence of an active ARP poisoning attack attempting to intercept traffic between hosts on the same VLAN.

**MITRE:** T1557.002 — ARP Cache Poisoning

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | IPAddress |

```kql
// Reference: ExtremeXOS EMS — ipSecur.arpViol — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours of ARP inspection violation data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match ARP violation messages from IP security subsystem
| where SyslogMessage has "ipSecur.arpViol"
// Extract port, VLAN, IP, and MAC for full incident context
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
| extend IPAddress = extract(@"IP\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, VLANName, IPAddress, MACAddress, SyslogMessage
// Aggregate violations per host/VLAN per hour to detect patterns
| summarize
    ViolationCount = count(),
    Ports = make_set(Port, 10),
    IPs = make_set(IPAddress, 10),
    MACs = make_set(MACAddress, 10)
  by HostName, VLANName, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "Dynamic ARP Inspection Violation",
    AlertDescription = "ARP packets failed Dynamic ARP Inspection validation, indicating potential ARP spoofing or poisoning attacks.",
    AlertSeverity = "High"
| order by ViolationCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: ec3f50b7-d7f1-42b1-aa2a-047dec682597
name: "Dynamic ARP Inspection Violation"
description: |
  Detects ARP packets that fail Dynamic ARP Inspection (DAI) validation on the switch. DAI validates ARP packets against the DHCP snooping binding table to ensure the IP-to-MAC mapping is legitimate. Violations indicate that a device is sending ARP replies with forged IP-to-MAC mappings, which is the hallmark of ARP spoofing/poisoning attacks used for man-in-the-middle interception.
  SOC analysts should treat DAI violations as strong evidence of an active ARP poisoning attack attempting to intercept traffic between hosts on the same VLAN.
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
  - CredentialAccess
relevantTechniques:
  - T1557.002
query: |
  // Lookback: 24 hours of ARP inspection violation data
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match ARP violation messages from IP security subsystem
  | where SyslogMessage has "ipSecur.arpViol"
  // Extract port, VLAN, IP, and MAC for full incident context
  | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
  | extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
  | extend IPAddress = extract(@"IP\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
  | extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, Port, VLANName, IPAddress, MACAddress, SyslogMessage
  // Aggregate violations per host/VLAN per hour to detect patterns
  | summarize
      ViolationCount = count(),
      Ports = make_set(Port, 10),
      IPs = make_set(IPAddress, 10),
      MACs = make_set(MACAddress, 10)
    by HostName, VLANName, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "Dynamic ARP Inspection Violation",
      AlertDescription = "ARP packets failed Dynamic ARP Inspection validation, indicating potential ARP spoofing or poisoning attacks.",
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
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
customDetails:
  VLANName: VLANName
  ViolationCount: ViolationCount
  IPAddress: IPAddress
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — ARP Validation / DAI Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — ipSecur EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
