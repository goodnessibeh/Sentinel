**Author:** Goodness Caleb Ibeh

# LOLBAS/LOLBin Execution with Suspicious Parameters

This detection identifies the use of Living Off the Land Binaries (LOLBins) — legitimate Windows system binaries being abused with suspicious parameters to download, execute, or proxy malicious code. Attackers prefer LOLBins because they are signed by Microsoft and trusted by most security tools. Combining binary name with suspicious parameter patterns reduces false positives significantly.

**Importance:** A SOC analyst should investigate because LOLBin abuse is a primary defense evasion technique that allows attackers to execute malicious code using trusted system binaries, often bypassing application whitelisting.

**MITRE:** T1218 — System Binary Proxy Execution

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |
| Process | CommandLine | ProcessCommandLine |

```kql
// Define known Living Off the Land Binaries
let LOLBins = dynamic([
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wmic.exe", "cmstp.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "bitsadmin.exe",
    "wscript.exe", "cscript.exe", "hh.exe", "forfiles.exe",
    "pcalua.exe", "infdefaultinstall.exe", "msconfig.exe",
    "control.exe", "csc.exe", "vbc.exe", "jsc.exe"
]);
// Define suspicious parameter patterns indicating abuse
let SuspiciousPatterns = dynamic([
    "http://", "https://", "ftp://", "\\\\",
    "-decode", "-encode", "-urlcache", "-split",
    "javascript:", "vbscript:", "/i:http", "scrobj.dll",
    "advpack.dll", "ieadvpack.dll", "syssetup.dll",
    "/s /n /u /i:", "mshta vbscript:", "CMSTPLUA",
    "DotNetToJScript", "ActiveXObject"
]);
DeviceProcessEvents
// 24-hour lookback window
| where TimeGenerated > ago(24h)
// Filter for known LOLBin filenames
| where FileName in~ (LOLBins)
// Key filter: LOLBin must be used with suspicious parameters
| where ProcessCommandLine has_any (SuspiciousPatterns)
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8091a2
name: "LOLBAS/LOLBin Execution with Suspicious Parameters"
description: |
  This detection identifies the use of Living Off the Land Binaries (LOLBins) — legitimate Windows system binaries being abused with suspicious parameters to download, execute, or proxy malicious code. Attackers prefer LOLBins because they are signed by Microsoft and trusted by most security tools.
  A SOC analyst should investigate because LOLBin abuse is a primary defense evasion technique that allows attackers to execute malicious code using trusted system binaries, often bypassing application whitelisting.
severity: Medium
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
  - Execution
relevantTechniques:
  - T1218
query: |
  // Define known Living Off the Land Binaries
  let LOLBins = dynamic([
      "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
      "wmic.exe", "cmstp.exe", "msiexec.exe", "installutil.exe",
      "regasm.exe", "regsvcs.exe", "msbuild.exe", "bitsadmin.exe",
      "wscript.exe", "cscript.exe", "hh.exe", "forfiles.exe",
      "pcalua.exe", "infdefaultinstall.exe", "msconfig.exe",
      "control.exe", "csc.exe", "vbc.exe", "jsc.exe"
  ]);
  // Define suspicious parameter patterns indicating abuse
  let SuspiciousPatterns = dynamic([
      "http://", "https://", "ftp://", "\\\\",
      "-decode", "-encode", "-urlcache", "-split",
      "javascript:", "vbscript:", "/i:http", "scrobj.dll",
      "advpack.dll", "ieadvpack.dll", "syssetup.dll",
      "/s /n /u /i:", "mshta vbscript:", "CMSTPLUA",
      "DotNetToJScript", "ActiveXObject"
  ]);
  DeviceProcessEvents
  // 24-hour lookback window
  | where TimeGenerated > ago(24h)
  // Filter for known LOLBin filenames
  | where FileName in~ (LOLBins)
  // Key filter: LOLBin must be used with suspicious parameters
  | where ProcessCommandLine has_any (SuspiciousPatterns)
  | project TimeGenerated, DeviceName, AccountName, FileName,
            ProcessCommandLine, InitiatingProcessFileName,
            InitiatingProcessCommandLine, FolderPath
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: ProcessCommandLine
version: 1.0.0
kind: Scheduled
```
