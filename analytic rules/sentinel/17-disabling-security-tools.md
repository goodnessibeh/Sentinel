**Author:** Goodness Caleb Ibeh

# Disabling Security Tools

This detection identifies attempts to disable or weaken security tools, particularly Windows Defender and related security services. Attackers routinely disable security tools as one of their first actions after gaining access, to prevent detection of subsequent malicious activities. The query covers PowerShell-based Defender configuration changes, service stops, and registry-based tamper attempts.

**Importance:** A SOC analyst should respond urgently because disabling security tools is a precursor to further malicious activity — the attacker is blinding your defenses before executing their primary objective.

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
DeviceProcessEvents
// 24-hour lookback for defense tampering
| where TimeGenerated > ago(24h)
| where (
    // Detection pattern 1: PowerShell commands disabling Defender features
    (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Set-MpPreference", "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring", "DisableIOAVProtection",
        "DisableScriptScanning", "Add-MpPreference", "ExclusionPath"
    ))
    or
    // Detection pattern 2: Stopping security services via net/sc commands
    (FileName in~ ("net.exe", "net1.exe", "sc.exe") and ProcessCommandLine has "stop" and
     ProcessCommandLine has_any ("WinDefend", "MpsSvc", "wscsvc", "SecurityHealthService",
         "Sense", "WdNisSvc", "WdBoot", "WdFilter"))
    or
    // Detection pattern 3: Registry-based tamper protection bypass
    (FileName =~ "reg.exe" and ProcessCommandLine has "DisableAntiSpyware")
)
| extend
    AlertTitle = "Disabling Security Tools",
    AlertDescription = "This detection identifies attempts to disable or weaken security tools, particularly Windows Defender and related security services.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 17e8f9a0-b1c2-4d3e-4f5a-6b7c8d9e0f1d
name: "Disabling Security Tools"
description: |
  This detection identifies attempts to disable or weaken security tools, particularly Windows Defender and related security services. Attackers routinely disable security tools as one of their first actions after gaining access, to prevent detection of subsequent malicious activities.
  A SOC analyst should respond urgently because disabling security tools is a precursor to further malicious activity — the attacker is blinding your defenses before executing their primary objective.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1562.001
query: |
  DeviceProcessEvents
  // 24-hour lookback for defense tampering
  | where TimeGenerated > ago(24h)
  | where (
      // Detection pattern 1: PowerShell commands disabling Defender features
      (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
          "Set-MpPreference", "DisableRealtimeMonitoring",
          "DisableBehaviorMonitoring", "DisableIOAVProtection",
          "DisableScriptScanning", "Add-MpPreference", "ExclusionPath"
      ))
      or
      // Detection pattern 2: Stopping security services via net/sc commands
      (FileName in~ ("net.exe", "net1.exe", "sc.exe") and ProcessCommandLine has "stop" and
       ProcessCommandLine has_any ("WinDefend", "MpsSvc", "wscsvc", "SecurityHealthService",
           "Sense", "WdNisSvc", "WdBoot", "WdFilter"))
      or
      // Detection pattern 3: Registry-based tamper protection bypass
      (FileName =~ "reg.exe" and ProcessCommandLine has "DisableAntiSpyware")
  )
  | extend
      AlertTitle = "Disabling Security Tools",
      AlertDescription = "This detection identifies attempts to disable or weaken security tools, particularly Windows Defender and related security services.",
      AlertSeverity = "High"
  | project TimeGenerated, DeviceName, AccountName, FileName,
            ProcessCommandLine, InitiatingProcessFileName, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
