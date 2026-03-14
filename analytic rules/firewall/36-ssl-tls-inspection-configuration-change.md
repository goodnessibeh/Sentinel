**Author:** Goodness Caleb Ibeh

# SSL/TLS Inspection Configuration Change

Detects changes to SSL/TLS inspection profiles, certificate configurations, and SSL exemption rules. SSL inspection is critical for detecting threats hidden in encrypted traffic. An attacker who disables or weakens SSL inspection effectively creates a blind spot where malware, C2 communications, and data exfiltration can occur undetected. Adding SSL exemptions for specific sites is also a technique attackers use to whitelist their C2 domains from inspection.

**Importance:** Weakening SSL inspection creates encrypted blind spots where malware, C2, and exfiltration can operate undetected, and unauthorized exemptions may whitelist attacker infrastructure.

**MITRE:** T1562 — Impair Defenses
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS SSL/SSH Inspection — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/929817/ssl-ssh-inspection
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match SSL/TLS inspection and certificate-related configuration changes
| where Message has_any (
    "ssl-ssh-profile", "ssl inspection", "deep-inspection",
    "certificate-inspection", "ssl-exempt", "ssl exempt",
    "certificate", "ca-cert", "local-cert"
  )
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f0b6e3f7-9d1a-4f4c-a2c8-6d7e0f1a5b4c
name: "SSL/TLS Inspection Configuration Change"
description: |
  Detects changes to SSL/TLS inspection profiles, certificate configurations, and SSL exemption rules. Weakening SSL inspection creates encrypted blind spots where malware, C2, and exfiltration can operate undetected, and unauthorized exemptions may whitelist attacker infrastructure. Designed for Fortinet FortiGate firewalls.
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
  - DefenseEvasion
relevantTechniques:
  - T1562
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries
  | where Activity has "system"
  // Key filter: match SSL/TLS inspection and certificate-related configuration changes
  | where Message has_any (
      "ssl-ssh-profile", "ssl inspection", "deep-inspection",
      "certificate-inspection", "ssl-exempt", "ssl exempt",
      "certificate", "ca-cert", "local-cert"
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

- **SSL/SSH Inspection:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/929817/ssl-ssh-inspection
- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
