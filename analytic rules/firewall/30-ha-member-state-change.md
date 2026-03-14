**Author:** Goodness Caleb Ibeh

# HA Member State Change

Detects changes in the state of HA cluster members, such as a member going from active to standby, becoming out of sync, or losing heartbeat connectivity. These events can indicate hardware degradation, network issues between HA peers, or an attacker disrupting the HA cluster to create a single point of failure. Monitoring HA member state ensures that the firewall cluster remains resilient and properly synchronized.

**Importance:** HA member state changes can leave your network running on a single firewall without redundancy, creating a critical single point of failure that must be resolved before a second failure occurs.

**MITRE:** N/A — Operational Monitoring
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |

```kql
// Reference: FortiOS Log ID 0105037892 (HA Member State) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/37892/37892
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for HA-related log entries
| where Activity has "ha"
// Key filter: FortiGate event IDs for HA member state changes, plus keyword fallback
| where DeviceEventClassID in ("37892", "0105037892")
    or Message has "member state"
| project TimeGenerated, DeviceName, DeviceExternalID, Message
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f4b0e7f1-3c5d-4d8a-a6b2-0c1d4e7f9a8b
name: "HA Member State Change"
description: |
  Detects changes in the state of HA cluster members, such as a member going from active to standby, becoming out of sync, or losing heartbeat connectivity. HA member state changes can leave your network running on a single firewall without redundancy, creating a critical single point of failure that must be resolved. Designed for Fortinet FortiGate firewalls.
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
tactics: []
relevantTechniques: []
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for HA-related log entries
  | where Activity has "ha"
  // Key filter: FortiGate event IDs for HA member state changes, plus keyword fallback
  | where DeviceEventClassID in ("37892", "0105037892")
      or Message has "member state"
  | project TimeGenerated, DeviceName, DeviceExternalID, Message
  | order by TimeGenerated desc
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
version: 1.0.0
kind: Scheduled
```

## References

- **HA Member State (Log ID 0105037892):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/37892/37892
