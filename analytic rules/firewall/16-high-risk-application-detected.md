**Author:** Goodness Caleb Ibeh

# High-Risk Application Detected (Tor, P2P, Tunneling)

Detects the use of applications classified as critical or high risk by FortiGate's application control engine. This includes Tor (anonymous routing), peer-to-peer file sharing, tunneling tools, and other applications that can be used to bypass security controls or establish covert communication channels. These applications are rarely legitimate in enterprise environments and often indicate either malicious activity or serious policy violations.

**Importance:** High-risk applications like Tor and tunneling tools provide attackers with encrypted, anonymous channels that bypass all other security controls, making them a top-priority detection for SOC teams.

**MITRE:** T1090.003 — Proxy: Multi-hop Proxy (Tor)
**Severity:** High

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
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for application control log entries
| where Activity has "app-ctrl"
// Extract application control fields from additional extensions
| extend AppName = extract("FTNTFGTapp=([^;]+)", 1, AdditionalExtensions)
| extend AppCat = extract("FTNTFGTappcat=([^;]+)", 1, AdditionalExtensions)
| extend AppRisk = extract("FTNTFGTapprisk=([^;\\s]+)", 1, AdditionalExtensions)
// Only surface critical and high risk applications
| where AppRisk in ("critical", "high")
| extend
    AlertTitle = "High-Risk Application Detected (Tor, P2P, Tunneling)",
    AlertDescription = "Critical or high-risk application detected by FortiGate application control, including Tor, P2P, or tunneling tools that can bypass security controls.",
    AlertSeverity = "High"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          AppName, AppCat, AppRisk, DeviceAction,
          DestinationUserName, DestinationHostName, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d0f6b3a7-9c1e-4d4b-e2f8-6a7b0c3d5e4f
name: "High-Risk Application Detected (Tor, P2P, Tunneling)"
description: |
  Detects the use of applications classified as critical or high risk by FortiGate's application control engine, including Tor, P2P, and tunneling tools. High-risk applications provide attackers with encrypted, anonymous channels that bypass all other security controls, making them a top-priority detection for SOC teams. Designed for Fortinet FortiGate firewalls.
severity: High
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
relevantTechniques:
  - T1090.003
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for application control log entries
  | where Activity has "app-ctrl"
  // Extract application control fields from additional extensions
  | extend AppName = extract("FTNTFGTapp=([^;]+)", 1, AdditionalExtensions)
  | extend AppCat = extract("FTNTFGTappcat=([^;]+)", 1, AdditionalExtensions)
  | extend AppRisk = extract("FTNTFGTapprisk=([^;\\s]+)", 1, AdditionalExtensions)
  // Only surface critical and high risk applications
  | where AppRisk in ("critical", "high")
  | extend
      AlertTitle = "High-Risk Application Detected (Tor, P2P, Tunneling)",
      AlertDescription = "Critical or high-risk application detected by FortiGate application control, including Tor, P2P, or tunneling tools that can bypass security controls.",
      AlertSeverity = "High"
  | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
            AppName, AppCat, AppRisk, DeviceAction,
            DestinationUserName, DestinationHostName, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
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
  AppCat: AppCat
  AppRisk: AppRisk
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=app-ctrl):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 1059028704:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/28704/28704
