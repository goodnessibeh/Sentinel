**Author:** Goodness Caleb Ibeh

# IPS Signature Allowed (Detect-Only Mode)

Detects critical or high severity IPS signature matches where the traffic was allowed through rather than blocked. This occurs when the IPS profile is set to "detect" or "monitor" mode instead of "block" mode. These are effectively active attacks that the firewall identified but permitted to pass, meaning the target host may have been successfully exploited.

**Importance:** An IPS hit in detect-only mode means a known attack reached its target unblocked — this is a critical misconfiguration that must be remediated and the target host investigated for compromise.

**MITRE:** Multiple
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
// Reference: FortiOS Log ID 0419016384 (UTM IPS) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/16384/16384-log-id-utm-ips
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for IPS-related log entries
| where Activity has "ips"
// Key filter: only show hits where the action was detect/pass (NOT blocked)
| where DeviceAction in ("detected", "pass")
// Extract threat level and attack name from additional extensions
| extend ThreatLevel = extract("FTNTFGTcrlevel=([^;\\s]+)", 1, AdditionalExtensions)
| extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
// Only surface critical and high severity detections that were allowed through
| where ThreatLevel in ("critical", "high")
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          AttackName, ThreatLevel, DeviceAction, Message
```

**Tuning:** This detects IPS hits that were NOT blocked — review IPS profile to ensure blocking is enabled.

---

## Sentinel Analytics Rule — YAML

```yaml
id: b2d8f5e9-1a3c-4b6f-c4d0-8e9f2a5b7c6d
name: "IPS Signature Allowed (Detect-Only Mode)"
description: |
  Detects critical or high severity IPS signature matches where the traffic was allowed through rather than blocked. An IPS hit in detect-only mode means a known attack reached its target unblocked — this is a critical misconfiguration that must be remediated and the target host investigated for compromise. Designed for Fortinet FortiGate firewalls.
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
  - Execution
relevantTechniques:
  - T1190
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for IPS-related log entries
  | where Activity has "ips"
  // Key filter: only show hits where the action was detect/pass (NOT blocked)
  | where DeviceAction in ("detected", "pass")
  // Extract threat level and attack name from additional extensions
  | extend ThreatLevel = extract("FTNTFGTcrlevel=([^;\\s]+)", 1, AdditionalExtensions)
  | extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
  // Only surface critical and high severity detections that were allowed through
  | where ThreatLevel in ("critical", "high")
  | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
            AttackName, ThreatLevel, DeviceAction, Message
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
customDetails:
  DeviceAction: DeviceAction
  AttackName: AttackName
  ThreatLevel: ThreatLevel
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=ips):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 0419016384 (UTM IPS):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/16384/16384-log-id-utm-ips
