**Author:** Goodness Caleb Ibeh

# IP Security Packet Drop

Detects when the switch's IP security feature drops packets that fail validation checks such as source IP verification, DHCP snooping binding table lookups, or ARP inspection. A high volume of dropped packets on specific ports indicates either persistent attack attempts or a misconfigured device that is generating invalid traffic.

**Importance:** SOC analysts should monitor drop rates as sustained packet drops may indicate an ongoing spoofing or injection attack that the switch is actively mitigating.

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — ipSecur.drpPkt — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 1 hour — shorter window for high-frequency packet drop events
let lookback = 1h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match IP security dropped packet messages
| where SyslogMessage has "ipSecur.drpPkt"
// Extract the port where drops are occurring
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
// Aggregate drops per switch in 5-minute bins to identify sustained activity
| summarize
    DropCount = count(),
    Ports = make_set(Port, 20)
  by HostName, bin(TimeGenerated, 5m)
// Threshold: more than 10 drops in 5 minutes warrants investigation
| where DropCount > 10
| order by DropCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: ccad8686-bb61-406d-8929-fa1214916848
name: "IP Security Packet Drop"
description: |
  Detects when the switch's IP security feature drops packets that fail validation checks such as source IP verification, DHCP snooping binding table lookups, or ARP inspection. A high volume of dropped packets on specific ports indicates either persistent attack attempts or a misconfigured device that is generating invalid traffic.
  SOC analysts should monitor drop rates as sustained packet drops may indicate an ongoing spoofing or injection attack that the switch is actively mitigating.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1557
query: |
  // Lookback: 1 hour — shorter window for high-frequency packet drop events
  let lookback = 1h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match IP security dropped packet messages
  | where SyslogMessage has "ipSecur.drpPkt"
  // Extract the port where drops are occurring
  | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
  // Aggregate drops per switch in 5-minute bins to identify sustained activity
  | summarize
      DropCount = count(),
      Ports = make_set(Port, 20)
    by HostName, bin(TimeGenerated, 5m)
  // Threshold: more than 10 drops in 5 minutes warrants investigation
  | where DropCount > 10
  | order by DropCount desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  DropCount: DropCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — DHCP Snooping Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — IP Security Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — ipSecur EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
