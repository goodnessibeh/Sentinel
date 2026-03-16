**Author:** Goodness Caleb Ibeh

# DHCP Snooping — Configuration Change and Violation Detection

Two-signal detection for DHCP snooping on Extreme Networks ExtremeXOS switches. Signal 1 detects when DHCP snooping configuration changes occur (enable/disable, trusted port changes) as an informational event. Signal 2 detects active DHCP snooping violations where a rogue DHCP server packet is dropped on an untrusted port, indicating an active attack. Both signals are combined in a single analytics rule using a `union` pattern with dynamic alert name, description, and severity.

**Importance:** SOC analysts must investigate Signal 2 immediately — a rogue DHCP server can compromise every new device joining the network by distributing malicious DNS servers and default gateways. Signal 1 provides change audit visibility to detect unauthorized snooping disablement.

**MITRE:** T1557.003 — DHCP Spoofing

**Severity:** Dynamic (Informational for config changes, High for violations)

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

**Custom Details:**

| Field | Column |
|---|---|
| AlertTitle | AlertTitle |
| AlertDescription | AlertDescription |
| AlertSeverity | AlertSeverity |
| VLANName | VLANName |
| ViolationCount | ViolationCount |
| AdminUser | AdminUser |
| ConfigCommand | ConfigCommand |

**Reference:** [Extreme Networks — How To: Configure DHCP Snooping on Switch Engine (EXOS), Article 000080865](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000080865)

```kql
// UC-NET-004 — DHCP Snooping: Configuration Change + Violation Detection
// Signal 1: DHCP snooping config changes (CLILOG) — Informational
// Signal 2: DHCP snooping violations (ipSecur) — High
// Reference: https://extreme-networks.my.site.com/ExtrArticleDetail?an=000080865
// Reference: https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml
let lookback = 24h;
// ── Signal 1: Configuration Changes ─────────────────────────────
let ConfigChanges =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility == "local7"
    // Match CLILOG entries for DHCP snooping and trusted port commands
    | where SyslogMessage has "CLILOG"
    | where SyslogMessage has_any (
        "ip-security dhcp-snooping",
        "trusted-port",
        "trusted-servers",
        "trust-for dhcp-server"
    )
    // Extract admin context from CLILOG format: <seq> GlobalRouter CLILOG INFO SSH:<ip> <user> <command>
    | extend AdminUser = extract(@"CLILOG\s+\w+\s+\S+\s+(\S+)", 1, SyslogMessage)
    | extend ConfigCommand = extract(@"CLILOG\s+\w+\s+\S+\s+\S+\s+(.*)", 1, SyslogMessage)
    | summarize
        ChangeCount = count(),
        Commands = make_set(ConfigCommand, 10),
        AdminUsers = make_set(AdminUser, 5)
      by HostName, bin(TimeGenerated, 1h)
    | extend
        AlertTitle = strcat("DHCP Snooping Configuration Changed on ", HostName),
        AlertDescription = strcat(
            "DHCP snooping configuration was modified on switch ", HostName,
            ". ", toint(ChangeCount), " change(s) detected. ",
            "Commands: ", tostring(Commands),
            ". Admin(s): ", tostring(AdminUsers), "."
        ),
        AlertSeverity = "Informational",
        VLANName = "",
        ViolationCount = ChangeCount,
        AdminUser = tostring(AdminUsers)
    | project
        TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
        VLANName, ViolationCount, AdminUser, ConfigCommand = tostring(Commands);
// ── Signal 2: Active DHCP Snooping Violations ───────────────────
let Violations =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility == "local7"
    // Match ipSecur violation events: rogue DHCP server detected + packet dropped
    | where SyslogMessage has_any ("ipSecur.dhcpViol", "ipSecur.drpPkt")
    // Extract rogue server details from: "A Rogue DHCP server on VLAN <vlan> with IP <ip> was detected on port <port>"
    | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
    | extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
    | extend RogueIP = extract(@"IP\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
    | extend SourceMAC = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
    | summarize
        ViolationCount = count(),
        Ports = make_set(Port, 10),
        VLANs = make_set(VLANName, 5),
        RogueIPs = make_set(RogueIP, 10),
        MACs = make_set(SourceMAC, 10)
      by HostName, bin(TimeGenerated, 1h)
    | extend VLANName = tostring(VLANs)
    | extend
        AlertTitle = strcat("Rogue DHCP Server Detected on ", HostName),
        AlertDescription = strcat(
            "DHCP snooping violation on switch ", HostName,
            ". ", toint(ViolationCount), " violation(s) in 1 hour. ",
            "Rogue server IP(s): ", tostring(RogueIPs),
            ". Affected VLAN(s): ", tostring(VLANs),
            ". Port(s): ", tostring(Ports),
            ". MAC(s): ", tostring(MACs), "."
        ),
        AlertSeverity = "High",
        AdminUser = "",
        ConfigCommand = ""
    | project
        TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
        VLANName, ViolationCount, AdminUser, ConfigCommand;
// ── Union both signals ──────────────────────────────────────────
union ConfigChanges, Violations
| order by TimeGenerated desc
```

**Tuning:** Signal 2 fires on any violation — adjust `ViolationCount` threshold if environment generates expected DHCP noise. Signal 1 is informational but should be reviewed if snooping is disabled unexpectedly. Exclude known maintenance windows for Signal 1.

**Infrastructure Prerequisite:** DHCP snooping must be enabled on the switches before this detection produces results. See UC-NET-004 PoC Discovery Walkthrough for enablement steps.

---

## Sentinel Analytics Rule — YAML

```yaml
id: 05a1b2c3-d4e5-4f6a-7b8c-9d0e1f2a3b4c
name: "DHCP Snooping — Configuration Change and Violation Detection"
description: |
  Two-signal detection for DHCP snooping on Extreme Networks ExtremeXOS switches. Signal 1 detects DHCP snooping configuration changes (enable/disable, trusted port modifications) as informational events. Signal 2 detects active DHCP snooping violations where rogue DHCP server packets are dropped on untrusted ports, indicating an active attack.
  SOC analysts must investigate Signal 2 immediately — a rogue DHCP server can compromise every new device joining the network. Signal 1 provides audit visibility for unauthorized snooping disablement.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
  Reference: https://extreme-networks.my.site.com/ExtrArticleDetail?an=000080865
  Reference: https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml
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
  - T1557.003
query: |
  // UC-NET-004 — DHCP Snooping: Configuration Change + Violation Detection
  // Signal 1: DHCP snooping config changes (CLILOG) — Informational
  // Signal 2: DHCP snooping violations (ipSecur) — High
  // Reference: Extreme Networks Article 000080865
  let lookback = 24h;
  // ── Signal 1: Configuration Changes ─────────────────────────────
  let ConfigChanges =
      Syslog
      | where TimeGenerated > ago(lookback)
      | where Facility == "local7"
      | where SyslogMessage has "CLILOG"
      | where SyslogMessage has_any (
          "ip-security dhcp-snooping",
          "trusted-port",
          "trusted-servers",
          "trust-for dhcp-server"
      )
      | extend AdminUser = extract(@"CLILOG\s+\w+\s+\S+\s+(\S+)", 1, SyslogMessage)
      | extend ConfigCommand = extract(@"CLILOG\s+\w+\s+\S+\s+\S+\s+(.*)", 1, SyslogMessage)
      | summarize
          ChangeCount = count(),
          Commands = make_set(ConfigCommand, 10),
          AdminUsers = make_set(AdminUser, 5)
        by HostName, bin(TimeGenerated, 1h)
      | extend
          AlertTitle = strcat("DHCP Snooping Configuration Changed on ", HostName),
          AlertDescription = strcat(
              "DHCP snooping configuration was modified on switch ", HostName,
              ". ", toint(ChangeCount), " change(s) detected. ",
              "Commands: ", tostring(Commands),
              ". Admin(s): ", tostring(AdminUsers), "."
          ),
          AlertSeverity = "Informational",
          VLANName = "",
          ViolationCount = ChangeCount,
          AdminUser = tostring(AdminUsers)
      | project
          TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
          VLANName, ViolationCount, AdminUser, ConfigCommand = tostring(Commands);
  // ── Signal 2: Active DHCP Snooping Violations ───────────────────
  let Violations =
      Syslog
      | where TimeGenerated > ago(lookback)
      | where Facility == "local7"
      | where SyslogMessage has_any ("ipSecur.dhcpViol", "ipSecur.drpPkt")
      | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
      | extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
      | extend RogueIP = extract(@"IP\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
      | extend SourceMAC = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
      | summarize
          ViolationCount = count(),
          Ports = make_set(Port, 10),
          VLANs = make_set(VLANName, 5),
          RogueIPs = make_set(RogueIP, 10),
          MACs = make_set(SourceMAC, 10)
        by HostName, bin(TimeGenerated, 1h)
      | extend VLANName = tostring(VLANs)
      | extend
          AlertTitle = strcat("Rogue DHCP Server Detected on ", HostName),
          AlertDescription = strcat(
              "DHCP snooping violation on switch ", HostName,
              ". ", toint(ViolationCount), " violation(s) in 1 hour. ",
              "Rogue server IP(s): ", tostring(RogueIPs),
              ". Affected VLAN(s): ", tostring(VLANs),
              ". Port(s): ", tostring(Ports),
              ". MAC(s): ", tostring(MACs), "."
          ),
          AlertSeverity = "High",
          AdminUser = "",
          ConfigCommand = ""
      | project
          TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
          VLANName, ViolationCount, AdminUser, ConfigCommand;
  // ── Union both signals ──────────────────────────────────────────
  union ConfigChanges, Violations
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
  VLANName: VLANName
  ViolationCount: ViolationCount
  AdminUser: AdminUser
  ConfigCommand: ConfigCommand
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — How To: Configure DHCP Snooping on Switch Engine (EXOS), Article 000080865](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000080865)
- [Extreme Networks — DHCP Snooping Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — IP Security Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — ipSecur EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
