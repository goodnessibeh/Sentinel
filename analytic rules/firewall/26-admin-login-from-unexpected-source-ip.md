**Author:** Goodness Caleb Ibeh

# Admin Login from Unexpected Source IP

Detects successful administrative logins to FortiGate management interfaces from IP addresses outside the expected management network ranges. Admin access should be restricted to specific management subnets or jump hosts. A successful admin login from an unexpected IP could indicate a compromised credential being used from an attacker-controlled host, or a misconfigured access policy that exposes the management plane.

**Importance:** Admin logins from outside trusted management networks may indicate credential theft or unauthorized access that could lead to complete security control takeover.

**MITRE:** T1078 — Valid Accounts
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log ID 0100032001 (Admin Login Success) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/32001/32001
let lookback = 24h;
// Define trusted management network ranges — replace with your actual CIDRs
let AllowedAdminSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries (admin events)
| where Activity has "system"
// Key filter: FortiGate event ID for successful admin login
| where DeviceEventClassID in ("32001", "0100032001")
// Admin login success from outside expected management network ranges
| where not(ipv4_is_in_any_range(SourceIP, AllowedAdminSubnets))
| project TimeGenerated, SourceIP, DestinationUserName, DeviceName, Message
```

**Tuning:** Replace `AllowedAdminSubnets` with your actual management network CIDRs.

---

## Sentinel Analytics Rule — YAML

```yaml
id: b0d6a3b7-9e1f-4f4c-c2d8-6e7f0a1b4c3d
name: "Admin Login from Unexpected Source IP"
description: |
  Detects successful administrative logins to FortiGate management interfaces from IP addresses outside the expected management network ranges. Admin logins from outside trusted management networks may indicate credential theft or unauthorized access that could lead to complete security control takeover. Designed for Fortinet FortiGate firewalls.
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
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  let lookback = 24h;
  // Define trusted management network ranges — replace with your actual CIDRs
  let AllowedAdminSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries (admin events)
  | where Activity has "system"
  // Key filter: FortiGate event ID for successful admin login
  | where DeviceEventClassID in ("32001", "0100032001")
  // Admin login success from outside expected management network ranges
  | where not(ipv4_is_in_any_range(SourceIP, AllowedAdminSubnets))
  | project TimeGenerated, SourceIP, DestinationUserName, DeviceName, Message
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
version: 1.0.0
kind: Scheduled
```

## References

- **Admin Login Success (Log ID 0100032001):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/32001/32001
- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
