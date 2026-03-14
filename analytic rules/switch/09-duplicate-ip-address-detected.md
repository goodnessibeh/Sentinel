**Author:** Goodness Caleb Ibeh

# Duplicate IP Address Detected (DAD)

Detects when the switch's Duplicate Address Detection mechanism identifies two devices claiming the same IP address on the network. This can result from a misconfigured static IP, but it is also a technique used in ARP spoofing attacks where the attacker assumes the IP of a legitimate host (such as the default gateway) to intercept traffic.

**Importance:** SOC analysts should investigate duplicate IP alerts promptly because if the conflicting IP belongs to a gateway or critical server, it may indicate an active man-in-the-middle attack.

**MITRE:** T1557.002 — ARP Cache Poisoning

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | DuplicateIP |

```kql
// Reference: ExtremeXOS EMS — vlan.dad.IPAddrDup — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for duplicate address detection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match duplicate IP address detection messages
| where SyslogMessage has "vlan.dad.IPAddrDup"
// Extract the conflicting IP, neighbor MAC, and interface
| extend DuplicateIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend NeighborMAC = extract(@"Neighbor\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| extend Interface = extract(@"interface\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, DuplicateIP, NeighborMAC, Interface, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 023fc1df-7828-48ee-a975-f4275dddabd0
name: "Duplicate IP Address Detected (DAD)"
description: |
  Detects when the switch's Duplicate Address Detection mechanism identifies two devices claiming the same IP address on the network. This can result from a misconfigured static IP, but it is also a technique used in ARP spoofing attacks where the attacker assumes the IP of a legitimate host (such as the default gateway) to intercept traffic.
  SOC analysts should investigate duplicate IP alerts promptly because if the conflicting IP belongs to a gateway or critical server, it may indicate an active man-in-the-middle attack.
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
  // Lookback: 24 hours for duplicate address detection events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match duplicate IP address detection messages
  | where SyslogMessage has "vlan.dad.IPAddrDup"
  // Extract the conflicting IP, neighbor MAC, and interface
  | extend DuplicateIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
  | extend NeighborMAC = extract(@"Neighbor\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  | extend Interface = extract(@"interface\s+(\S+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, DuplicateIP, NeighborMAC, Interface, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DuplicateIP
customDetails:
  DuplicateIP: DuplicateIP
  NeighborMAC: NeighborMAC
  Interface: Interface
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — ARP Validation / DAI Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — VLAN DAD EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
