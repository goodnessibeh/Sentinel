**Author:** Goodness Caleb Ibeh

# Port Mirroring Configuration Change

Detects changes to packet capture, traffic mirroring, or sniffer configurations on FortiGate devices. An attacker who has gained admin access may configure port mirroring to capture sensitive traffic (credentials, session tokens, confidential data) for exfiltration. Sniffer policies and diagnostic sniffer commands can also be used to passively intercept traffic without modifying firewall rules, making this a stealthy attack technique.

**Importance:** Unauthorized port mirroring or packet capture configuration enables an attacker to passively intercept all network traffic including credentials and sensitive data without triggering other security alerts.

**MITRE:** T1040 — Network Sniffing
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Event Log Trigger — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match sniffer, packet capture, mirroring, and flow export config changes
| where Message has_any (
    "sniffer", "packet-capture", "mirror",
    "port-mirror", "traffic-mirror",
    "sflow", "netflow", "nflow",
    "diag sniff", "diagnose sniffer"
  )
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

**Tuning:** Port mirroring on FortiGate is done via sniffer policies or `diagnose sniffer` CLI commands.

---

## Sentinel Analytics Rule — YAML

```yaml
id: c7e3b0c4-6a8d-4c1e-d9f5-3a4b7c0d2e1f
name: "Port Mirroring Configuration Change"
description: |
  Detects changes to packet capture, traffic mirroring, or sniffer configurations on FortiGate devices. Unauthorized port mirroring or packet capture configuration enables an attacker to passively intercept all network traffic including credentials and sensitive data without triggering other security alerts. Designed for Fortinet FortiGate firewalls.
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
  - CredentialAccess
  - Collection
relevantTechniques:
  - T1040
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries
  | where Activity has "system"
  // Key filter: match sniffer, packet capture, mirroring, and flow export config changes
  | where Message has_any (
      "sniffer", "packet-capture", "mirror",
      "port-mirror", "traffic-mirror",
      "sflow", "netflow", "nflow",
      "diag sniff", "diagnose sniffer"
    )
  | project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
  | order by TimeGenerated desc
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
version: 1.0.0
kind: Scheduled
```

## References

- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
