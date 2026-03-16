**Author:** Goodness Caleb Ibeh

# VPN Tunnel Flapping — Repeated Up/Down

Detects VPN tunnels that are repeatedly going up and down within a short time period. Tunnel flapping can indicate a denial-of-service attack targeting the VPN infrastructure, network instability caused by an attacker, or an adversary attempting to disrupt VPN connectivity to force users onto less secure channels. It can also signal a compromised tunnel endpoint.

**Importance:** VPN tunnel flapping disrupts business connectivity and may indicate a targeted DoS attack or an attacker manipulating network infrastructure to force traffic through attacker-controlled paths.

**MITRE:** T1498 — Network Denial of Service
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Log ID 37138 (IPSec Tunnel Status) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/37138/37138
let lookback = 1h;
let flapThreshold = 5;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: look for tunnel state change events
| where DeviceAction in ("tunnel-up", "tunnel-down")
// Extract tunnel name and type for identification
| extend VPNTunnel = extract("FTNTFGTvpntunnel=([^;\\s]+)", 1, AdditionalExtensions)
| extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
// Aggregate state changes per tunnel — count ups and downs separately
| summarize
    StateChanges = count(),
    UpCount = countif(DeviceAction == "tunnel-up"),
    DownCount = countif(DeviceAction == "tunnel-down"),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
  by VPNTunnel, TunnelType, SourceIP
// Threshold filter: only flag tunnels with excessive state changes (flapping)
| where StateChanges >= flapThreshold
| extend
    AlertTitle = "VPN Tunnel Flapping — Repeated Up/Down",
    AlertDescription = "VPN tunnel detected repeatedly going up and down, which may indicate a targeted DoS attack or attacker manipulating network infrastructure.",
    AlertSeverity = "Medium"
| project VPNTunnel, TunnelType, SourceIP, StateChanges, UpCount, DownCount, FirstEvent, LastEvent, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d6f2c9d3-5a7b-4b0e-e8f4-2a3b6c9d1e0f
name: "VPN Tunnel Flapping — Repeated Up/Down"
description: |
  Detects VPN tunnels that are repeatedly going up and down within a short time period. VPN tunnel flapping disrupts business connectivity and may indicate a targeted DoS attack or an attacker manipulating network infrastructure to force traffic through attacker-controlled paths. Designed for Fortinet FortiGate firewalls.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Impact
relevantTechniques:
  - T1498
query: |
  let lookback = 1h;
  let flapThreshold = 5;
  CommonSecurityLog
  // Filter to the last 1 hour of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for VPN-related log entries
  | where Activity has "vpn"
  // Key filter: look for tunnel state change events
  | where DeviceAction in ("tunnel-up", "tunnel-down")
  // Extract tunnel name and type for identification
  | extend VPNTunnel = extract("FTNTFGTvpntunnel=([^;\\s]+)", 1, AdditionalExtensions)
  | extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
  // Aggregate state changes per tunnel — count ups and downs separately
  | summarize
      StateChanges = count(),
      UpCount = countif(DeviceAction == "tunnel-up"),
      DownCount = countif(DeviceAction == "tunnel-down"),
      FirstEvent = min(TimeGenerated),
      LastEvent = max(TimeGenerated)
    by VPNTunnel, TunnelType, SourceIP
  // Threshold filter: only flag tunnels with excessive state changes (flapping)
  | where StateChanges >= flapThreshold
  | extend
      AlertTitle = "VPN Tunnel Flapping — Repeated Up/Down",
      AlertDescription = "VPN tunnel detected repeatedly going up and down, which may indicate a targeted DoS attack or attacker manipulating network infrastructure.",
      AlertSeverity = "Medium"
  | project VPNTunnel, TunnelType, SourceIP, StateChanges, UpCount, DownCount, FirstEvent, LastEvent, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  VPNTunnel: VPNTunnel
  TunnelType: TunnelType
  StateChanges: StateChanges
  UpCount: UpCount
  DownCount: DownCount
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **IPSec Tunnel Status (Log ID 37138):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/37138/37138
- **SSL VPN Tunnel Up (Log ID 39947):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39947/39947-log-id-event-ssl-vpn-session-tunnel-up
- **VPN Logs Overview:** https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/834425/understanding-vpn-related-logs
