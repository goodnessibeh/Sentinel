**Author:** Goodness Caleb Ibeh

# Port Mirroring — Configuration Change and Active Mirroring Detection

Two-signal detection for port mirroring on Extreme Networks ExtremeXOS switches. Signal 1 detects port mirroring configuration changes via CLILOG (create, enable, disable, delete, modify mirror commands) as a high-severity audit event. Signal 2 detects hardware-level mirror activation via HAL.Mirror EMS events and remote mirroring configurations (mirror to remote IP), which represent the highest risk of traffic interception and data exfiltration. Both signals are combined in a single analytics rule using a `union` pattern with dynamic alert name, description, and severity.

**Importance:** SOC analysts must investigate any port mirroring change immediately. While mirroring is a legitimate network troubleshooting tool, unauthorized mirroring is a primary technique for traffic interception. An attacker with switch access can mirror sensitive VLAN traffic to a capture device or — in the case of remote mirroring — exfiltrate traffic to an off-network IP address across router hops.

**MITRE:** T1040 — Network Sniffing

**Severity:** Dynamic (High for config changes, Critical for remote mirroring / HAL activation)

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
| Action | Action |
| MirrorName | MirrorName |
| AdminUser | AdminUser |
| ConfigCommand | ConfigCommand |
| ChangeCount | ChangeCount |

**Reference:** [Extreme Networks — ExtremeXOS Mirroring Configuration (v30.7)](https://documentation.extremenetworks.com/exos_30.7/GUID-FE0C3B2D-FC1E-4BDD-974A-D1FA67DDAD84.shtml)

```kql
// UC-NET-XXX — Port Mirroring: Configuration Change + Active Mirroring Detection
// Signal 1: Mirror config changes via CLILOG — High
// Signal 2: HAL.Mirror hardware events / remote mirroring — Critical
// Reference: https://documentation.extremenetworks.com/exos_30.7/GUID-FE0C3B2D-FC1E-4BDD-974A-D1FA67DDAD84.shtml
// Reference: https://documentation.extremenetworks.com/exos_31.7/GUID-9B9B74C4-7164-4EE4-B2E3-C290B1C07E5F.shtml
let lookback = 24h;
// ── Signal 1: Configuration Changes (CLILOG) ───────────────────
let ConfigChanges =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility == "local7"
    // Match CLILOG entries for mirror-related CLI commands
    | where SyslogMessage has_any ("CLILOG", "CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
    | where SyslogMessage has_any (
        "create mirror", "delete mirror",
        "enable mirror", "disable mirror",
        "configure mirror", "port-mirror",
        "monitor port", "analyzer port"
    )
    // Extract admin context from CLILOG format
    | extend AdminUser = extract(@"CLILOG\s+\w+\s+\S+\s+(\S+)", 1, SyslogMessage)
    | extend ConfigCommand = extract(@"CLILOG\s+\w+\s+\S+\s+\S+\s+(.*)", 1, SyslogMessage)
    // Extract mirror name from command (e.g., create mirror "MirrorName")
    | extend MirrorName = extract(@"mirror\s+[\"']?(\S+?)[\"']?\s", 1, SyslogMessage)
    // Classify action type for triage
    | extend Action = case(
        SyslogMessage has_any ("delete mirror", "disable mirror"), "DISABLED/DELETED",
        SyslogMessage has_any ("create mirror", "enable mirror"), "ENABLED/CREATED",
        SyslogMessage has "configure mirror", "MODIFIED",
        "CHANGED"
    )
    // Flag remote mirroring as critical (mirror to remote-ip)
    | extend IsRemote = SyslogMessage has_any ("remote-ip", "remote-tag", "erspan")
    | summarize
        ChangeCount = count(),
        Commands = make_set(ConfigCommand, 10),
        AdminUsers = make_set(AdminUser, 5),
        Actions = make_set(Action, 5),
        MirrorNames = make_set(MirrorName, 10),
        HasRemote = max(tolong(IsRemote))
      by HostName, bin(TimeGenerated, 1h)
    | extend MirrorName = tostring(MirrorNames)
    | extend AdminUser = tostring(AdminUsers)
    | extend Action = tostring(Actions)
    | extend ConfigCommand = tostring(Commands)
    | extend
        AlertTitle = iff(HasRemote == 1,
            strcat("Remote Port Mirroring Configured on ", HostName),
            strcat("Port Mirroring Configuration Changed on ", HostName)
        ),
        AlertDescription = iff(HasRemote == 1,
            strcat(
                "CRITICAL: Remote port mirroring configured on switch ", HostName,
                ". Traffic may be exfiltrated to a remote IP. ",
                toint(ChangeCount), " change(s). ",
                "Mirror(s): ", tostring(MirrorNames),
                ". Admin(s): ", tostring(AdminUsers),
                ". Commands: ", tostring(Commands), "."
            ),
            strcat(
                "Port mirroring configuration changed on switch ", HostName,
                ". ", toint(ChangeCount), " change(s). ",
                "Action(s): ", tostring(Actions),
                ". Mirror(s): ", tostring(MirrorNames),
                ". Admin(s): ", tostring(AdminUsers), "."
            )
        ),
        AlertSeverity = iff(HasRemote == 1, "High", "High"),
        ChangeCount = ChangeCount
    | project
        TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
        Action, MirrorName, AdminUser, ConfigCommand, ChangeCount;
// ── Signal 2: Hardware Mirror Activation (HAL.Mirror) ───────────
let HardwareEvents =
    Syslog
    | where TimeGenerated > ago(lookback)
    | where Facility == "local7"
    // Match HAL.Mirror EMS events — hardware-level mirror activation/errors
    | where SyslogMessage has "HAL.Mirror"
    // Extract mirror context from HAL event
    | extend MirrorName = extract(@"mirror\s+[\"']?(\S+?)[\"']?[\s,]", 1, SyslogMessage)
    | extend Action = case(
        SyslogMessage has_any ("activated", "enabled", "started", "created"), "ACTIVATED",
        SyslogMessage has_any ("deactivated", "disabled", "stopped", "removed"), "DEACTIVATED",
        SyslogMessage has "error", "ERROR",
        "EVENT"
    )
    | summarize
        ChangeCount = count(),
        Actions = make_set(Action, 5),
        MirrorNames = make_set(MirrorName, 10)
      by HostName, bin(TimeGenerated, 1h)
    | extend MirrorName = tostring(MirrorNames)
    | extend Action = tostring(Actions)
    | extend
        AlertTitle = strcat("Hardware Port Mirroring Active on ", HostName),
        AlertDescription = strcat(
            "Hardware-level port mirroring event on switch ", HostName,
            ". ", toint(ChangeCount), " HAL.Mirror event(s). ",
            "Action(s): ", tostring(Actions),
            ". Mirror(s): ", tostring(MirrorNames),
            ". HAL.Mirror events indicate active traffic duplication at the hardware level."
        ),
        AlertSeverity = "High",
        AdminUser = "",
        ConfigCommand = ""
    | project
        TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
        Action, MirrorName, AdminUser, ConfigCommand, ChangeCount;
// ── Union both signals ──────────────────────────────────────────
union ConfigChanges, HardwareEvents
| order by TimeGenerated desc
```

**Tuning:** Exclude known maintenance windows and authorized network monitoring activities. If the environment uses mirroring for legitimate IDS/IPS tap feeds, whitelist those specific mirror names. Remote mirroring (mirror to remote-ip) should always be investigated regardless of context.

---

## Sentinel Analytics Rule — YAML

```yaml
id: 28a1b2c3-d4e5-4f6a-7b8c-9d0e1f2a3b4d
name: "Port Mirroring — Configuration Change and Active Mirroring Detection"
description: |
  Two-signal detection for port mirroring on Extreme Networks ExtremeXOS switches. Signal 1 detects mirror configuration changes via CLILOG (create, enable, disable, delete, modify). Signal 2 detects hardware-level mirror activation via HAL.Mirror EMS events, indicating active traffic duplication.
  SOC analysts must investigate any port mirroring change immediately. Unauthorized mirroring is a primary technique for traffic interception and data exfiltration, especially remote mirroring which can exfiltrate traffic to off-network destinations.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
  Reference: https://documentation.extremenetworks.com/exos_30.7/GUID-FE0C3B2D-FC1E-4BDD-974A-D1FA67DDAD84.shtml
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
  - Collection
  - Exfiltration
relevantTechniques:
  - T1040
query: |
  // UC-NET-XXX — Port Mirroring: Configuration Change + Active Mirroring Detection
  // Signal 1: Mirror config changes via CLILOG — High
  // Signal 2: HAL.Mirror hardware events / remote mirroring — Critical
  // Reference: ExtremeXOS User Guide — Mirroring; EMS Catalog — HAL.Mirror
  let lookback = 24h;
  // ── Signal 1: Configuration Changes (CLILOG) ───────────────────
  let ConfigChanges =
      Syslog
      | where TimeGenerated > ago(lookback)
      | where Facility == "local7"
      | where SyslogMessage has_any ("CLILOG", "CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
      | where SyslogMessage has_any (
          "create mirror", "delete mirror",
          "enable mirror", "disable mirror",
          "configure mirror", "port-mirror",
          "monitor port", "analyzer port"
      )
      | extend AdminUser = extract(@"CLILOG\s+\w+\s+\S+\s+(\S+)", 1, SyslogMessage)
      | extend ConfigCommand = extract(@"CLILOG\s+\w+\s+\S+\s+\S+\s+(.*)", 1, SyslogMessage)
      | extend MirrorName = extract(@"mirror\s+[\"']?(\S+?)[\"']?\s", 1, SyslogMessage)
      | extend Action = case(
          SyslogMessage has_any ("delete mirror", "disable mirror"), "DISABLED/DELETED",
          SyslogMessage has_any ("create mirror", "enable mirror"), "ENABLED/CREATED",
          SyslogMessage has "configure mirror", "MODIFIED",
          "CHANGED"
      )
      | extend IsRemote = SyslogMessage has_any ("remote-ip", "remote-tag", "erspan")
      | summarize
          ChangeCount = count(),
          Commands = make_set(ConfigCommand, 10),
          AdminUsers = make_set(AdminUser, 5),
          Actions = make_set(Action, 5),
          MirrorNames = make_set(MirrorName, 10),
          HasRemote = max(tolong(IsRemote))
        by HostName, bin(TimeGenerated, 1h)
      | extend MirrorName = tostring(MirrorNames)
      | extend AdminUser = tostring(AdminUsers)
      | extend Action = tostring(Actions)
      | extend ConfigCommand = tostring(Commands)
      | extend
          AlertTitle = iff(HasRemote == 1,
              strcat("Remote Port Mirroring Configured on ", HostName),
              strcat("Port Mirroring Configuration Changed on ", HostName)
          ),
          AlertDescription = iff(HasRemote == 1,
              strcat(
                  "CRITICAL: Remote port mirroring configured on switch ", HostName,
                  ". Traffic may be exfiltrated to a remote IP. ",
                  toint(ChangeCount), " change(s). ",
                  "Mirror(s): ", tostring(MirrorNames),
                  ". Admin(s): ", tostring(AdminUsers),
                  ". Commands: ", tostring(Commands), "."
              ),
              strcat(
                  "Port mirroring configuration changed on switch ", HostName,
                  ". ", toint(ChangeCount), " change(s). ",
                  "Action(s): ", tostring(Actions),
                  ". Mirror(s): ", tostring(MirrorNames),
                  ". Admin(s): ", tostring(AdminUsers), "."
              )
          ),
          AlertSeverity = iff(HasRemote == 1, "High", "High"),
          ChangeCount = ChangeCount
      | project
          TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
          Action, MirrorName, AdminUser, ConfigCommand, ChangeCount;
  // ── Signal 2: Hardware Mirror Activation (HAL.Mirror) ───────────
  let HardwareEvents =
      Syslog
      | where TimeGenerated > ago(lookback)
      | where Facility == "local7"
      | where SyslogMessage has "HAL.Mirror"
      | extend MirrorName = extract(@"mirror\s+[\"']?(\S+?)[\"']?[\s,]", 1, SyslogMessage)
      | extend Action = case(
          SyslogMessage has_any ("activated", "enabled", "started", "created"), "ACTIVATED",
          SyslogMessage has_any ("deactivated", "disabled", "stopped", "removed"), "DEACTIVATED",
          SyslogMessage has "error", "ERROR",
          "EVENT"
      )
      | summarize
          ChangeCount = count(),
          Actions = make_set(Action, 5),
          MirrorNames = make_set(MirrorName, 10)
        by HostName, bin(TimeGenerated, 1h)
      | extend MirrorName = tostring(MirrorNames)
      | extend Action = tostring(Actions)
      | extend
          AlertTitle = strcat("Hardware Port Mirroring Active on ", HostName),
          AlertDescription = strcat(
              "Hardware-level port mirroring event on switch ", HostName,
              ". ", toint(ChangeCount), " HAL.Mirror event(s). ",
              "Action(s): ", tostring(Actions),
              ". Mirror(s): ", tostring(MirrorNames),
              ". HAL.Mirror events indicate active traffic duplication at the hardware level."
          ),
          AlertSeverity = "High",
          AdminUser = "",
          ConfigCommand = ""
      | project
          TimeGenerated, HostName, AlertTitle, AlertDescription, AlertSeverity,
          Action, MirrorName, AdminUser, ConfigCommand, ChangeCount;
  // ── Union both signals ──────────────────────────────────────────
  union ConfigChanges, HardwareEvents
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
  Action: Action
  MirrorName: MirrorName
  AdminUser: AdminUser
  ConfigCommand: ConfigCommand
  ChangeCount: ChangeCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Mirroring Configuration (ExtremeXOS v30.7)](https://documentation.extremenetworks.com/exos_30.7/GUID-FE0C3B2D-FC1E-4BDD-974A-D1FA67DDAD84.shtml)
- [Extreme Networks — Mirroring Rules and Restrictions (ExtremeXOS 31.7)](https://documentation.extremenetworks.com/exos_31.7/GUID-9B9B74C4-7164-4EE4-B2E3-C290B1C07E5F.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS v33.2.x)](https://documentation.extremenetworks.com/ExtremeXOS%20and%20Switch%20Engine%20v33.2.x%20EMS%20Message%20Catalog/downloads/ExtremeXOS_and_Switch_Engine_33_2_x_EMS_Message_Catalog.pdf)
- [Extreme Networks — configure mirror add Command Reference](https://documentation.extremenetworks.com/exos_commands_22.3/EXOS_21_1/EXOS_Commands_All/r_configure-mirror-add.shtml)
- [Extreme Networks — Mirroring Examples (ExtremeXOS v33.2.1)](https://documentation.extremenetworks.com/ExtremeXOS%20v33.2.1%20User%20Guide/content/documents/Switch_Operating_Systems/ExtremeXOS/User_Guide/mirroring_examples.shtml)
