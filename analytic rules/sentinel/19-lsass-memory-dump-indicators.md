**Author:** Goodness Caleb Ibeh

# LSASS Memory Dump Indicators

This detection identifies attempts to dump the memory of the LSASS (Local Security Authority Subsystem Service) process, which stores plaintext passwords, NTLM hashes, and Kerberos tickets in memory. Credential dumping from LSASS is one of the most impactful post-exploitation techniques because it can yield credentials for lateral movement across the entire domain. The query covers known tools like procdump, mimikatz, and comsvcs.dll-based methods.

**Importance:** A SOC analyst should treat this as critical because a successful LSASS dump gives the attacker credentials to move laterally to any system where those credentials are valid.

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Detect processes attempting to access or dump LSASS memory
DeviceProcessEvents
// 24-hour lookback for credential dumping activity
| where TimeGenerated > ago(24h)
| where (
    // Pattern 1: Known dump tools targeting LSASS
    (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    or
    // Pattern 2: Mimikatz command patterns
    (ProcessCommandLine has_any ("sekurlsa", "lsadump", "kerberos::list", "crypto::certificates"))
    or
    // Pattern 3: Task manager / comsvcs.dll based memory dump
    (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
    or
    // Pattern 4: Direct LSASS access via rundll32
    (FileName =~ "rundll32.exe" and ProcessCommandLine has "lsass")
)
| extend
    AlertTitle = "LSASS Memory Dump Indicators",
    AlertDescription = "This detection identifies attempts to dump the memory of the LSASS (Local Security Authority Subsystem Service) process, which stores plaintext passwords, NTLM hashes, and Kerberos tickets in memory.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 19a0b1c2-d3e4-4f5a-6b7c-8d9e0f1a2b3f
name: "LSASS Memory Dump Indicators"
description: |
  This detection identifies attempts to dump the memory of the LSASS (Local Security Authority Subsystem Service) process, which stores plaintext passwords, NTLM hashes, and Kerberos tickets in memory. Credential dumping from LSASS is one of the most impactful post-exploitation techniques.
  A SOC analyst should treat this as critical because a successful LSASS dump gives the attacker credentials to move laterally to any system where those credentials are valid.
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
  - CredentialAccess
relevantTechniques:
  - T1003.001
query: |
  // Detect processes attempting to access or dump LSASS memory
  DeviceProcessEvents
  // 24-hour lookback for credential dumping activity
  | where TimeGenerated > ago(24h)
  | where (
      // Pattern 1: Known dump tools targeting LSASS
      (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
      or
      // Pattern 2: Mimikatz command patterns
      (ProcessCommandLine has_any ("sekurlsa", "lsadump", "kerberos::list", "crypto::certificates"))
      or
      // Pattern 3: Task manager / comsvcs.dll based memory dump
      (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
      or
      // Pattern 4: Direct LSASS access via rundll32
      (FileName =~ "rundll32.exe" and ProcessCommandLine has "lsass")
  )
  | extend
      AlertTitle = "LSASS Memory Dump Indicators",
      AlertDescription = "This detection identifies attempts to dump the memory of the LSASS (Local Security Authority Subsystem Service) process, which stores plaintext passwords, NTLM hashes, and Kerberos tickets in memory.",
      AlertSeverity = "High"
  | project TimeGenerated, DeviceName, AccountName, FileName,
            ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AlertTitle, AlertDescription, AlertSeverity
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
