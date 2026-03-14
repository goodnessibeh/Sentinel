**Author:** Goodness Caleb Ibeh

# Repeated IPS Hits from Same Source — Persistent Attacker

Detects a single source IP triggering multiple IPS signatures within a short time window. An attacker running automated exploit tools or vulnerability scanners will generate many distinct IPS signatures in rapid succession as they cycle through different attack payloads. This pattern distinguishes a determined, active attacker from isolated false positives or one-off scanning noise.

**Importance:** Repeated IPS hits from a single source indicate an active, persistent attacker methodically probing your defenses, and the source IP should be immediately blocked at the perimeter.

**MITRE:** T1595 — Active Scanning
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Log ID 0419016384 (UTM IPS) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/16384/16384-log-id-utm-ips
let lookback = 1h;
let threshold = 5;
CommonSecurityLog
// Filter to the last 1 hour for near-real-time detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for IPS-related log entries
| where Activity has "ips"
// Extract the attack name from additional extensions
| extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
// Aggregate IPS hits per source IP — count total hits, distinct attacks, and targets
| summarize
    HitCount = count(),
    DistinctAttacks = dcount(AttackName),
    AttackList = make_set(AttackName, 10),
    Targets = make_set(DestinationIP, 10),
    Actions = make_set(DeviceAction)
  by SourceIP
// Threshold filter: only flag sources with repeated IPS triggers
| where HitCount >= threshold
| project SourceIP, HitCount, DistinctAttacks, AttackList, Targets, Actions
| order by HitCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: c3e9a6f0-2b4d-4c7a-d5e1-9f0a3b6c8d7e
name: "Repeated IPS Hits from Same Source — Persistent Attacker"
description: |
  Detects a single source IP triggering multiple IPS signatures within a short time window. Repeated IPS hits from a single source indicate an active, persistent attacker methodically probing your defenses, and the source IP should be immediately blocked at the perimeter. Designed for Fortinet FortiGate firewalls.
severity: High
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
  - Reconnaissance
relevantTechniques:
  - T1595
query: |
  let lookback = 1h;
  let threshold = 5;
  CommonSecurityLog
  // Filter to the last 1 hour for near-real-time detection
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for IPS-related log entries
  | where Activity has "ips"
  // Extract the attack name from additional extensions
  | extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
  // Aggregate IPS hits per source IP — count total hits, distinct attacks, and targets
  | summarize
      HitCount = count(),
      DistinctAttacks = dcount(AttackName),
      AttackList = make_set(AttackName, 10),
      Targets = make_set(DestinationIP, 10),
      Actions = make_set(DeviceAction)
    by SourceIP
  // Threshold filter: only flag sources with repeated IPS triggers
  | where HitCount >= threshold
  | project SourceIP, HitCount, DistinctAttacks, AttackList, Targets, Actions
  | order by HitCount desc
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  HitCount: HitCount
  DistinctAttacks: DistinctAttacks
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=ips):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 0419016384 (UTM IPS):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/16384/16384-log-id-utm-ips
