**Author:** Goodness Caleb Ibeh

# Unauthorized Remote Access Tool Usage

Detects the use of commercial remote access tools such as TeamViewer, AnyDesk, LogMeIn, and similar software. While these tools have legitimate uses, they are also heavily abused by attackers for persistent remote access to compromised hosts. Many ransomware operators and initial access brokers use these tools to maintain access that blends in with normal IT activity. Unauthorized use should be flagged and validated against approved software lists.

**Importance:** Remote access tools are one of the most common persistence mechanisms used by ransomware operators, and unauthorized usage must be immediately validated against the approved software inventory.

**MITRE:** T1219 — Remote Access Software
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
// Reference: FortiOS Log ID 1059028704 (App Control) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/28704/28704
let lookback = 24h;
// Define known remote access tool names to detect
let RemoteAccessApps = dynamic(["TeamViewer", "AnyDesk", "LogMeIn", "RustDesk",
    "Ammyy.Admin", "VNC", "Splashtop", "ConnectWise", "RemotePC",
    "GoToMyPC", "Dameware", "Radmin", "UltraVNC"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for application control log entries
| where Activity has "app-ctrl"
// Extract the detected application name
| extend AppName = extract("FTNTFGTapp=([^;]+)", 1, AdditionalExtensions)
// Match against the list of known remote access tools
| where AppName has_any (RemoteAccessApps)
| project TimeGenerated, SourceIP, DestinationIP, AppName, DeviceAction,
          DestinationUserName, DestinationHostName
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: e1a7c4b8-0d2f-4e5c-f3a9-7b8c1d4e6f5a
name: "Unauthorized Remote Access Tool Usage"
description: |
  Detects the use of commercial remote access tools such as TeamViewer, AnyDesk, LogMeIn, and similar software. Remote access tools are one of the most common persistence mechanisms used by ransomware operators, and unauthorized usage must be immediately validated against the approved software inventory. Designed for Fortinet FortiGate firewalls.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CommandAndControl
  - Persistence
relevantTechniques:
  - T1219
query: |
  let lookback = 24h;
  // Define known remote access tool names to detect
  let RemoteAccessApps = dynamic(["TeamViewer", "AnyDesk", "LogMeIn", "RustDesk",
      "Ammyy.Admin", "VNC", "Splashtop", "ConnectWise", "RemotePC",
      "GoToMyPC", "Dameware", "Radmin", "UltraVNC"]);
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for application control log entries
  | where Activity has "app-ctrl"
  // Extract the detected application name
  | extend AppName = extract("FTNTFGTapp=([^;]+)", 1, AdditionalExtensions)
  // Match against the list of known remote access tools
  | where AppName has_any (RemoteAccessApps)
  | project TimeGenerated, SourceIP, DestinationIP, AppName, DeviceAction,
            DestinationUserName, DestinationHostName
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
customDetails:
  DeviceAction: DeviceAction
  AppName: AppName
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=app-ctrl):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 1059028704:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/28704/28704
