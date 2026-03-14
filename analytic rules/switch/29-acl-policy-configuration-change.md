**Author:** Goodness Caleb Ibeh

# ACL/Policy Configuration Change

Detects when Access Control Lists (ACLs) or policies are created, modified, bound, or unbound on the switch. ACLs are the primary mechanism for enforcing traffic filtering and segmentation at Layer 2/3. Unauthorized ACL changes can open previously blocked pathways, disable traffic filtering, or redirect traffic. An attacker may modify ACLs to permit their traffic or remove restrictions that block lateral movement.

**Importance:** SOC analysts should investigate ACL changes because unauthorized modifications can silently open network pathways that were previously secured.

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — ACL.bind / ACL.Change — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for ACL/policy configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match ACL system events or CLI commands that modify ACLs/policies
| where SyslogMessage has_any ("ACL.bind", "ACL.unBind", "ACL.Change", "ACL.DynACL", "ACL.refresh")
    or (SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd")
        and SyslogMessage has_any ("acl", "policy", "access-list", "configure access-list"))
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 88f80836-4bae-47a9-bdb3-73f5358a5ca9
name: "ACL/Policy Configuration Change"
description: |
  Detects when Access Control Lists (ACLs) or policies are created, modified, bound, or unbound on the switch. ACLs are the primary mechanism for enforcing traffic filtering and segmentation at Layer 2/3. Unauthorized ACL changes can open previously blocked pathways, disable traffic filtering, or redirect traffic. An attacker may modify ACLs to permit their traffic or remove restrictions that block lateral movement.
  SOC analysts should investigate ACL changes because unauthorized modifications can silently open network pathways that were previously secured.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1562.001
query: |
  // Lookback: 24 hours for ACL/policy configuration changes
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match ACL system events or CLI commands that modify ACLs/policies
  | where SyslogMessage has_any ("ACL.bind", "ACL.unBind", "ACL.Change", "ACL.DynACL", "ACL.refresh")
      or (SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd")
          and SyslogMessage has_any ("acl", "policy", "access-list", "configure access-list"))
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | project TimeGenerated, HostName, Severity, Component, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Component: Component
  Severity: Severity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — ACL/Policy Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
