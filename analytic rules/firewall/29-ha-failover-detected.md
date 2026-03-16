**Author:** Goodness Caleb Ibeh

# HA Failover Detected

Detects high availability failover events where the standby FortiGate unit has taken over as the active unit. HA failovers can be triggered by hardware failure, software crashes, or deliberate attacks targeting the primary unit. While failovers ensure continued operation, they should be investigated to determine the root cause — especially if they occur outside of maintenance windows or are accompanied by other suspicious events.

**Importance:** HA failovers indicate the primary firewall experienced a critical failure, which could be caused by a DoS attack, exploit, or hardware issue that requires immediate root cause analysis.

**MITRE:** T1498 — Network Denial of Service
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |

```kql
// Reference: FortiOS Log ID 35016 (HA Failover) — https://docs.fortinet.com/document/fortigate/7.0.10/fortios-log-message-reference/35016/35016-log-id-ha-failover-success
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for HA-related log entries
| where Activity has "ha"
// Key filter: FortiGate event IDs for HA failover events, plus keyword fallback
| where DeviceEventClassID in ("35013", "35016", "0108035013", "0108035016")
    or Message has "failover"
| extend
    AlertTitle = "HA Failover Detected",
    AlertDescription = "High availability failover detected where the standby FortiGate unit has taken over, indicating the primary firewall experienced a critical failure.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, DeviceExternalID, Message, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: e3a9d6e0-2b4c-4c7f-f5a1-9b0c3d6e8f7a
name: "HA Failover Detected"
description: |
  Detects high availability failover events where the standby FortiGate unit has taken over as the active unit. HA failovers indicate the primary firewall experienced a critical failure, which could be caused by a DoS attack, exploit, or hardware issue that requires immediate root cause analysis. Designed for Fortinet FortiGate firewalls.
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
  - Impact
relevantTechniques:
  - T1498
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for HA-related log entries
  | where Activity has "ha"
  // Key filter: FortiGate event IDs for HA failover events, plus keyword fallback
  | where DeviceEventClassID in ("35013", "35016", "0108035013", "0108035016")
      or Message has "failover"
  | extend
      AlertTitle = "HA Failover Detected",
      AlertDescription = "High availability failover detected where the standby FortiGate unit has taken over, indicating the primary firewall experienced a critical failure.",
      AlertSeverity = "High"
  | project TimeGenerated, DeviceName, DeviceExternalID, Message, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **HA Failover (Log ID 35016):** https://docs.fortinet.com/document/fortigate/7.0.10/fortios-log-message-reference/35016/35016-log-id-ha-failover-success
