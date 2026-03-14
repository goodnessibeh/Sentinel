# KQL Sentinel — Detection Rules Library

> Full detection library organized by MITRE ATT&CK tactics. Each detection includes: KQL query, MITRE technique ID, severity, entity mapping, and tuning notes.

---

## Initial Access

### 1. Brute Force — Multiple Failed Sign-ins Followed by Success

**MITRE:** T1110 — Brute Force
**Severity:** Medium
**Entity Mapping:** Account (UserPrincipalName), IP (IPAddress)

```kql
let threshold = 10;
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| summarize
    FailureCount = countif(ResultType != 0),
    SuccessCount = countif(ResultType == 0),
    IPAddresses = make_set(IPAddress, 100),
    AppList = make_set(AppDisplayName, 10),
    FailureReasons = make_set(ResultDescription, 5),
    FirstFailure = minif(TimeGenerated, ResultType != 0),
    LastSuccess = maxif(TimeGenerated, ResultType == 0)
  by UserPrincipalName
| where FailureCount >= threshold and SuccessCount > 0
| where LastSuccess > FirstFailure
| extend TimeBetween = LastSuccess - FirstFailure
| project UserPrincipalName, FailureCount, SuccessCount, IPAddresses, AppList, FailureReasons, TimeBetween
```

**Tuning:** Adjust `threshold` based on environment. Exclude service accounts. Exclude known VPN/proxy IPs that cause legitimate failures.

---

### 2. Impossible Travel — Sign-ins from Geographically Distant Locations

**MITRE:** T1078 — Valid Accounts
**Severity:** Medium
**Entity Mapping:** Account (UserPrincipalName), IP (IPAddress1, IPAddress2)

```kql
let timeWindow = 2h;
let minDistance = 500; // km — adjust for your org
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend Lat = todouble(LocationDetails.geoCoordinates.latitude)
| extend Lon = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(City) and isnotnull(Lat)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend
    PrevUser = prev(UserPrincipalName),
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Lat), PrevLon = prev(Lon),
    PrevCity = prev(City), PrevCountry = prev(Country),
    PrevIP = prev(IPAddress)
| where UserPrincipalName == PrevUser
| extend TimeDelta = (TimeGenerated - PrevTime) / 1m
| where TimeDelta < (timeWindow / 1m)
// Haversine approximation
| extend DistanceKm = 6371 * acos(
    sin(radians(Lat)) * sin(radians(PrevLat)) +
    cos(radians(Lat)) * cos(radians(PrevLat)) * cos(radians(PrevLon - Lon))
  )
| where DistanceKm > minDistance
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country,
          PrevIP, PrevCity, PrevCountry, TimeDelta, DistanceKm
```

**Tuning:** Exclude VPN IPs. Adjust distance/time thresholds. Whitelist known travel patterns.

---

### 3. Phishing Email Delivered with Malicious Attachment

**MITRE:** T1566.001 — Phishing: Spearphishing Attachment
**Severity:** Medium
**Entity Mapping:** MailMessage (RecipientEmailAddress), File (FileName)

```kql
EmailEvents
| where TimeGenerated > ago(24h)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| join kind=leftouter (
    EmailAttachmentInfo
    | where TimeGenerated > ago(24h)
    | project NetworkMessageId, FileName, FileType, SHA256, MalwareFilterVerdict
  ) on NetworkMessageId
| project TimeGenerated, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
          Subject, FileName, FileType, SHA256, ThreatTypes, ThreatNames, DeliveryLocation
```

---

### 4. MFA Fatigue / MFA Bypass

**MITRE:** T1621 — Multi-Factor Authentication Request Generation
**Severity:** High
**Entity Mapping:** Account (UserPrincipalName), IP (IPAddress)

```kql
let mfaThreshold = 5;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 50074 or ResultType == 50076  // MFA required
| summarize
    MFARequests = count(),
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Apps = make_set(AppDisplayName, 5),
    LastAttempt = max(TimeGenerated)
  by UserPrincipalName
| where MFARequests >= mfaThreshold
// Check if eventually succeeded
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize SuccessTime = min(TimeGenerated) by UserPrincipalName
  ) on UserPrincipalName
| extend MFABypassed = isnotnull(SuccessTime) and SuccessTime > LastAttempt
| project UserPrincipalName, MFARequests, DistinctIPs, IPList, Apps, MFABypassed
```

---

## Execution

### 5. Encoded PowerShell Command Execution

**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Account (AccountName), Process (ProcessCommandLine)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-ec ")
| extend EncodedPayload = extract(@"(?i)-[eE](?:nc(?:odedCommand)?|c)?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| where isnotempty(EncodedPayload)
| extend DecodedCommand = base64_decode_tostring(EncodedPayload)
| project TimeGenerated, DeviceName, AccountName,
          ProcessCommandLine, DecodedCommand,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

### 6. LOLBAS/LOLBin Execution with Suspicious Parameters

**MITRE:** T1218 — System Binary Proxy Execution
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Account (AccountName), Process (ProcessCommandLine)

```kql
let LOLBins = dynamic([
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wmic.exe", "cmstp.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "bitsadmin.exe",
    "wscript.exe", "cscript.exe", "hh.exe", "forfiles.exe",
    "pcalua.exe", "infdefaultinstall.exe", "msconfig.exe",
    "control.exe", "csc.exe", "vbc.exe", "jsc.exe"
]);
let SuspiciousPatterns = dynamic([
    "http://", "https://", "ftp://", "\\\\",
    "-decode", "-encode", "-urlcache", "-split",
    "javascript:", "vbscript:", "/i:http", "scrobj.dll",
    "advpack.dll", "ieadvpack.dll", "syssetup.dll",
    "/s /n /u /i:", "mshta vbscript:", "CMSTPLUA",
    "DotNetToJScript", "ActiveXObject"
]);
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ (LOLBins)
| where ProcessCommandLine has_any (SuspiciousPatterns)
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath
```

---

### 7. WMI Remote Execution

**MITRE:** T1047 — Windows Management Instrumentation
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName !in~ ("wmiprvse.exe", "wmiapsrv.exe", "scrcons.exe")
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| summarize
    ProcessCount = count(),
    ProcessList = make_set(strcat(FileName, " → ", ProcessCommandLine), 10)
  by DeviceName, AccountName, bin(TimeGenerated, 1h)
```

---

### 8. Scheduled Task Creation via Command Line

**MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| parse ProcessCommandLine with * "/tn " TaskName " " *
| parse ProcessCommandLine with * "/tr " TaskCommand " " *
| project TimeGenerated, DeviceName, AccountName, TaskName, TaskCommand,
          ProcessCommandLine, InitiatingProcessFileName
```

---

## Persistence

### 9. New User Account Created

**MITRE:** T1136.001 — Create Account: Local Account
**Severity:** Low
**Entity Mapping:** Account (TargetAccount), Host (Computer)

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4720
| project TimeGenerated, Computer, TargetAccount, TargetUserName, TargetDomainName,
          SubjectAccount, SubjectUserName, SubjectDomainName
```

---

### 10. New Entra ID User Created with Immediate Role Assignment

**MITRE:** T1136.003 — Create Account: Cloud Account
**Severity:** High
**Entity Mapping:** Account (TargetUPN)

```kql
let timeWindow = 1h;
let UserCreation = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add user"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project CreationTime = TimeGenerated, TargetUPN, Initiator;
let RoleAssignment = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| project AssignmentTime = TimeGenerated, TargetUPN, RoleName;
UserCreation
| join kind=inner (RoleAssignment) on TargetUPN
| where (AssignmentTime - CreationTime) between (0s .. timeWindow)
| project CreationTime, AssignmentTime, TargetUPN, Initiator, RoleName
```

---

### 11. Registry Run Key Persistence

**MITRE:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
let RunKeyPaths = dynamic([
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    @"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
]);
DeviceRegistryEvents
| where TimeGenerated > ago(24h)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (RunKeyPaths)
| project TimeGenerated, DeviceName, AccountName,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

### 12. New Windows Service Installed

**MITRE:** T1543.003 — Create or Modify System Process: Windows Service
**Severity:** Medium
**Entity Mapping:** Host (Computer)

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 7045
| project TimeGenerated, Computer, ServiceName = tostring(EventData.ServiceName),
          ServiceFileName = tostring(EventData.ImagePath),
          ServiceType = tostring(EventData.ServiceType),
          ServiceStartType = tostring(EventData.StartType),
          ServiceAccount = tostring(EventData.AccountName)
| where ServiceFileName has_any ("cmd", "powershell", "wscript", "cscript", "mshta",
          "\\Temp\\", "\\tmp\\", "\\AppData\\", "\\Users\\Public\\")
```

---

### 13. Inbox Rule Creation (Email Persistence)

**MITRE:** T1137.005 — Office Application Startup: Outlook Rules
**Severity:** Medium
**Entity Mapping:** Account (UserId)

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| extend MoveToFolder = tostring(parse_json(Parameters)[3].Value)
| extend ForwardTo = tostring(parse_json(Parameters)[4].Value)
| extend DeleteMessage = tostring(parse_json(Parameters)[5].Value)
| where isnotempty(ForwardTo) or isnotempty(DeleteMessage) or MoveToFolder has_any ("RSS", "Deleted", "Junk")
| project TimeGenerated, UserId, ClientIP, Operation, RuleName, ForwardTo, DeleteMessage, MoveToFolder
```

---

## Privilege Escalation

### 14. User Added to Privileged Entra ID Role

**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts
**Severity:** High
**Entity Mapping:** Account (TargetUPN)

```kql
let PrivilegedRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Conditional Access Administrator", "Authentication Administrator",
    "Privileged Authentication Administrator", "Billing Administrator"
]);
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = replace_string(tostring(TargetResources[0].modifiedProperties[1].newValue), '"', '')
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| where RoleName in (PrivilegedRoles)
| project TimeGenerated, TargetUPN, RoleName, Initiator
```

---

### 15. Member Added to Sensitive Security Group

**MITRE:** T1078.002 — Valid Accounts: Domain Accounts
**Severity:** High
**Entity Mapping:** Account (MemberName), Host (Computer)

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4728, 4732, 4756)  // Global, Local, Universal group add
| where TargetUserName has_any (
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "DnsAdmins", "Exchange Organization Management"
  )
| project TimeGenerated, Computer, SubjectAccount, MemberName, MemberSid,
          TargetUserName, Activity
```

---

## Defense Evasion

### 16. Security Log Cleared

**MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs
**Severity:** High
**Entity Mapping:** Account (SubjectAccount), Host (Computer)

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 1102
| project TimeGenerated, Computer, SubjectAccount = Account, Activity
| union (
    // Also check for wevtutil clear-log
    DeviceProcessEvents
    | where TimeGenerated > ago(24h)
    | where FileName =~ "wevtutil.exe"
    | where ProcessCommandLine has_any ("cl", "clear-log")
    | project TimeGenerated, Computer = DeviceName, SubjectAccount = AccountName,
              Activity = strcat("wevtutil ", ProcessCommandLine)
)
```

---

### 17. Disabling Security Tools

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools
**Severity:** High
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where (
    // Stopping Defender
    (FileName =~ "powershell.exe" and ProcessCommandLine has_any (
        "Set-MpPreference", "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring", "DisableIOAVProtection",
        "DisableScriptScanning", "Add-MpPreference", "ExclusionPath"
    ))
    or
    // net stop / sc stop security services
    (FileName in~ ("net.exe", "net1.exe", "sc.exe") and ProcessCommandLine has "stop" and
     ProcessCommandLine has_any ("WinDefend", "MpsSvc", "wscsvc", "SecurityHealthService",
         "Sense", "WdNisSvc", "WdBoot", "WdFilter"))
    or
    // Tamper protection bypass attempts
    (FileName =~ "reg.exe" and ProcessCommandLine has "DisableAntiSpyware")
)
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
```

---

### 18. Process Masquerading — Suspicious Process Path

**MITRE:** T1036.005 — Masquerading: Match Legitimate Name or Location
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Process (ProcessCommandLine)

```kql
let SystemProcesses = datatable(ProcessName:string, LegitPaths:dynamic) [
    "svchost.exe",   dynamic([@"C:\Windows\System32\", @"C:\Windows\SysWOW64\"]),
    "lsass.exe",     dynamic([@"C:\Windows\System32\"]),
    "csrss.exe",     dynamic([@"C:\Windows\System32\"]),
    "services.exe",  dynamic([@"C:\Windows\System32\"]),
    "smss.exe",      dynamic([@"C:\Windows\System32\"]),
    "winlogon.exe",  dynamic([@"C:\Windows\System32\"]),
    "taskhost.exe",  dynamic([@"C:\Windows\System32\"]),
    "explorer.exe",  dynamic([@"C:\Windows\", @"C:\Windows\SysWOW64\"])
];
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                       "smss.exe", "winlogon.exe", "taskhost.exe", "explorer.exe")
| join kind=inner (SystemProcesses) on $left.FileName == $right.ProcessName
| where not(FolderPath has_any (LegitPaths))
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
```

---

## Credential Access

### 19. LSASS Memory Dump Indicators

**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory
**Severity:** High
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
// Process accessing LSASS
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where (
    // Known dump tools
    (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    or
    // Mimikatz patterns
    (ProcessCommandLine has_any ("sekurlsa", "lsadump", "kerberos::list", "crypto::certificates"))
    or
    // Task manager / comsvcs.dll dump
    (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump")
    or
    // Direct LSASS access
    (FileName =~ "rundll32.exe" and ProcessCommandLine has "lsass")
)
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

### 20. Kerberoasting — Abnormal Service Ticket Requests

**MITRE:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
**Severity:** Medium
**Entity Mapping:** Account (TargetAccount), Host (Computer)

```kql
let threshold = 5;
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4769
| where Status == "0x0"
| where TicketEncryptionType in ("0x17", "0x18")  // RC4 (weak) encryption
| where ServiceName !endswith "$"  // Exclude machine accounts
| where ServiceName !in ("krbtgt", "kadmin")
| summarize
    TicketCount = count(),
    ServiceNames = make_set(ServiceName, 20),
    DistinctServices = dcount(ServiceName)
  by TargetAccount = Account, Computer, IpAddress
| where DistinctServices >= threshold
| project TargetAccount, Computer, IpAddress, DistinctServices, ServiceNames
```

---

### 21. Password Spray Attack

**MITRE:** T1110.003 — Brute Force: Password Spraying
**Severity:** Medium
**Entity Mapping:** IP (IPAddress)

```kql
let timeframe = 1h;
let userThreshold = 10;
let failureCode = dynamic([50126, 50053, 50055, 50056]);
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType in (failureCode)
| summarize
    TargetedUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 50),
    AttemptCount = count(),
    Apps = make_set(AppDisplayName, 5),
    FailureCodes = make_set(ResultType)
  by IPAddress
| where TargetedUsers >= userThreshold
| extend SuccessCheck = toscalar(
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where IPAddress == IPAddress and ResultType == 0
    | summarize count()
  )
| project IPAddress, TargetedUsers, AttemptCount, UserList, Apps, FailureCodes
```

---

## Discovery

### 22. Network Scanning Activity

**MITRE:** T1046 — Network Service Discovery
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), IP (LocalIP)

```kql
let portThreshold = 50;
let hostThreshold = 20;
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType == "ConnectionAttempt" or ActionType == "ConnectionFailed"
| summarize
    DistinctPorts = dcount(RemotePort),
    DistinctHosts = dcount(RemoteIP),
    PortList = make_set(RemotePort, 50),
    TargetHosts = make_set(RemoteIP, 20)
  by DeviceName, LocalIP, InitiatingProcessFileName
| where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
| project DeviceName, LocalIP, InitiatingProcessFileName,
          DistinctPorts, DistinctHosts, PortList, TargetHosts
```

---

### 23. Account Enumeration via LDAP

**MITRE:** T1087.002 — Account Discovery: Domain Account
**Severity:** Low
**Entity Mapping:** Account (AccountUpn), Host (DeviceName)

```kql
IdentityQueryEvents
| where TimeGenerated > ago(24h)
| where QueryType == "LDAP"
| where ActionType == "LDAP query"
| summarize
    QueryCount = count(),
    DistinctQueries = dcount(QueryTarget),
    Queries = make_set(QueryTarget, 20)
  by AccountUpn, DeviceName
| where QueryCount > 50
| project AccountUpn, DeviceName, QueryCount, DistinctQueries, Queries
```

---

## Lateral Movement

### 24. RDP from Single Account to Multiple Hosts

**MITRE:** T1021.001 — Remote Services: Remote Desktop Protocol
**Severity:** Medium
**Entity Mapping:** Account (AccountName), IP (RemoteIP)

```kql
let threshold = 3;
DeviceLogonEvents
| where TimeGenerated > ago(24h)
| where LogonType == "RemoteInteractive"
| summarize
    TargetCount = dcount(DeviceName),
    Targets = make_set(DeviceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by AccountName, RemoteIP
| where TargetCount >= threshold
| project AccountName, RemoteIP, TargetCount, Targets, FirstSeen, LastSeen
```

---

### 25. PSRemoting / WinRM Lateral Movement

**MITRE:** T1021.006 — Remote Services: Windows Remote Management
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName =~ "wsmprovhost.exe"  // WinRM host process
| where FileName !in~ ("wsmprovhost.exe", "conhost.exe")
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| summarize
    CommandCount = count(),
    Processes = make_set(FileName, 10),
    Commands = make_set(ProcessCommandLine, 10)
  by DeviceName, AccountName, bin(TimeGenerated, 1h)
```

---

### 26. SMB/Named Pipe Lateral Movement

**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares
**Severity:** Medium
**Entity Mapping:** Account (SubjectAccount), Host (Computer)

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 5145
| where ShareName in (@"\*\ADMIN$", @"\*\C$", @"\*\IPC$")
| where SubjectUserName !endswith "$"  // Exclude machine accounts
| summarize
    AccessCount = count(),
    Shares = make_set(ShareName),
    Targets = make_set(RelativeTargetName, 20)
  by SubjectAccount, Computer, IpAddress
| where AccessCount > 10
```

---

### 27. Pass-the-Hash Detection

**MITRE:** T1550.002 — Use Alternate Authentication Material: Pass the Hash
**Severity:** High
**Entity Mapping:** Account (TargetUserName), Host (Computer)

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"  // Exclude machine accounts
| where IpAddress != "-" and IpAddress != "127.0.0.1"
| summarize
    LogonCount = count(),
    DistinctHosts = dcount(Computer),
    HostList = make_set(Computer, 20)
  by TargetUserName, TargetDomainName, IpAddress
| where DistinctHosts >= 3  // NTLM to 3+ hosts = suspicious
| project TargetUserName, TargetDomainName, IpAddress, DistinctHosts, HostList, LogonCount
```

---

## Collection

### 28. Mass File Download from SharePoint/OneDrive

**MITRE:** T1213.002 — Data from Information Repositories: SharePoint
**Severity:** Medium
**Entity Mapping:** Account (UserId)

```kql
let threshold = 50;
OfficeActivity
| where TimeGenerated > ago(1h)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize
    DownloadCount = count(),
    DistinctFiles = dcount(OfficeObjectId),
    Sites = make_set(Site_Url, 5),
    SampleFiles = make_set(SourceFileName, 10)
  by UserId, ClientIP
| where DownloadCount >= threshold
| project UserId, ClientIP, DownloadCount, DistinctFiles, Sites, SampleFiles
```

---

## Command and Control

### 29. DNS Tunneling Detection

**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Severity:** High
**Entity Mapping:** Host (Computer), IP (ClientIP)

```kql
DnsEvents
| where TimeGenerated > ago(24h)
| extend DomainParts = split(Name, ".")
| extend SubdomainLength = strlen(tostring(DomainParts[0]))
| extend TLD = strcat(tostring(DomainParts[-2]), ".", tostring(DomainParts[-1]))
| where SubdomainLength > 30  // Long subdomain = potential encoded data
| summarize
    QueryCount = count(),
    AvgSubdomainLen = avg(SubdomainLength),
    MaxSubdomainLen = max(SubdomainLength),
    UniqueSubs = dcount(tostring(DomainParts[0]))
  by TLD, ClientIP, Computer
| where QueryCount > 100 and AvgSubdomainLen > 20
| project Computer, ClientIP, TLD, QueryCount, AvgSubdomainLen, MaxSubdomainLen, UniqueSubs
```

---

### 30. Beaconing Detection — Regular Interval Callbacks

**MITRE:** T1071 — Application Layer Protocol
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), IP (RemoteIP)

```kql
let minConnections = 20;
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize
    ConnectionTimes = make_list(TimeGenerated, 1000),
    ConnectionCount = count()
  by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnectionCount >= minConnections
// Calculate time deltas between connections
| mv-apply ct = ConnectionTimes to typeof(datetime) on (
    serialize
    | extend NextTime = next(ct)
    | where isnotnull(NextTime)
    | extend Delta = datetime_diff("second", NextTime, ct)
    | summarize AvgDelta = avg(Delta), StdevDelta = stdev(Delta), Deltas = count()
)
// Low standard deviation = regular interval = beaconing
| where StdevDelta < AvgDelta * 0.2  // <20% variation
| where AvgDelta between (10 .. 3600)  // 10s to 1h intervals
| project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName,
          ConnectionCount, AvgDelta, StdevDelta
| order by StdevDelta asc
```

---

### 31. Connection to Known Malicious IP (TI Match)

**MITRE:** T1071 — Application Layer Protocol
**Severity:** High
**Entity Mapping:** Host (DeviceName), IP (RemoteIP)

```kql
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where Active == true and ExpirationDateTime > now()
| where isnotempty(NetworkIP)
| distinct NetworkIP;
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIP in (TI_IPs)
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | project NetworkIP, ThreatType, Description, Confidence, Tags
  ) on $left.RemoteIP == $right.NetworkIP
```

---

## Exfiltration

### 32. Large Outbound Data Transfer

**MITRE:** T1048 — Exfiltration Over Alternative Protocol
**Severity:** Medium
**Entity Mapping:** Host (DeviceName), IP (RemoteIP)

```kql
let bytesThreshold = 100000000; // 100MB
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize
    TotalBytesSent = sum(SentBytes),
    ConnectionCount = count(),
    Ports = make_set(RemotePort, 10),
    Processes = make_set(InitiatingProcessFileName, 10)
  by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
| where TotalBytesSent > bytesThreshold
| extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
| project TimeGenerated, DeviceName, RemoteIP, TotalMB, ConnectionCount, Ports, Processes
| order by TotalMB desc
```

---

### 33. Anomalous Email Forwarding Rule

**MITRE:** T1114.003 — Email Collection: Email Forwarding Rule
**Severity:** High
**Entity Mapping:** Account (UserId)

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule", "New-TransportRule", "Set-TransportRule")
| extend Parameters = parse_json(Parameters)
| mv-expand Parameters
| extend ParamName = tostring(Parameters.Name), ParamValue = tostring(Parameters.Value)
| where ParamName in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| where isnotempty(ParamValue)
| extend ExternalDomain = extract(@"@(.+)$", 1, ParamValue)
// Flag if forwarding to external domain
| project TimeGenerated, UserId, ClientIP, Operation, ParamName,
          ForwardTarget = ParamValue, ExternalDomain
```

---

## Impact

### 34. Ransomware Indicators — Mass File Encryption

**MITRE:** T1486 — Data Encrypted for Impact
**Severity:** High
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
let encryptionExtensions = dynamic([
    ".encrypted", ".locked", ".crypto", ".crypt",
    ".enc", ".rzk", ".WNCRY", ".wnry", ".locky",
    ".cerber", ".zepto", ".thor", ".aaa", ".abc",
    ".xyz", ".zzzzz", ".micro", ".vvv"
]);
let renameThreshold = 50;
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileRenamed"
| extend NewExtension = extract(@"(\.\w+)$", 1, FileName)
| where NewExtension in (encryptionExtensions) or
        // Detect ransom note creation
        FileName in~ ("README.txt", "DECRYPT_INSTRUCTIONS.txt",
                      "HOW_TO_DECRYPT.txt", "RECOVERY_INSTRUCTIONS.html",
                      "!README!.txt", "_readme.txt")
| summarize
    RenameCount = count(),
    Extensions = make_set(NewExtension, 10),
    FolderPaths = make_set(FolderPath, 10),
    SampleFiles = make_set(FileName, 20)
  by DeviceName, AccountName, InitiatingProcessFileName,
     InitiatingProcessCommandLine, bin(TimeGenerated, 5m)
| where RenameCount >= renameThreshold
| project TimeGenerated, DeviceName, AccountName, RenameCount,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          Extensions, SampleFiles
```

---

### 35. Critical Service Stopped

**MITRE:** T1489 — Service Stop
**Severity:** High
**Entity Mapping:** Host (DeviceName), Account (AccountName)

```kql
let CriticalServices = dynamic([
    "WinDefend", "MpsSvc", "wscsvc", "Sense",      // Security
    "MSSQLSERVER", "SQLSERVERAGENT",                  // Database
    "VSS", "wbengine", "SamSs",                       // Backup/Recovery
    "EventLog", "Winmgmt",                             // Management
    "W3SVC", "WAS"                                     // Web
]);
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("net.exe", "net1.exe", "sc.exe", "taskkill.exe")
| where ProcessCommandLine has "stop" or ProcessCommandLine has "/f"
| extend StoppedService = extract(@"(?:stop|/f)\s+[\"']?(\S+)", 1, ProcessCommandLine)
| where StoppedService in~ (CriticalServices)
| project TimeGenerated, DeviceName, AccountName, FileName,
          StoppedService, ProcessCommandLine, InitiatingProcessFileName
```

---

### 36. Azure Resource Deletion Spree

**MITRE:** T1485 — Data Destruction
**Severity:** High
**Entity Mapping:** Account (Caller)

```kql
let threshold = 10;
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "delete"
| where ActivityStatusValue == "Succeeded"
| summarize
    DeleteCount = count(),
    Resources = make_set(Resource, 20),
    ResourceTypes = make_set(ResourceProviderValue, 10),
    ResourceGroups = make_set(ResourceGroup, 10)
  by Caller, CallerIpAddress
| where DeleteCount >= threshold
| project Caller, CallerIpAddress, DeleteCount, ResourceTypes, Resources, ResourceGroups
```

---

## Cross-Tactic Detections

### 37. Full Attack Chain — Compromised Account to Data Exfiltration

**MITRE:** Multiple
**Severity:** High

```kql
// Correlate suspicious sign-in → mailbox rule → data download
let SuspiciousSignins = SigninLogs
| where TimeGenerated > ago(24h)
| where RiskLevelDuringSignIn in ("high", "medium")
| where ResultType == 0
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevel = RiskLevelDuringSignIn;
let MailRules = OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project RuleTime = TimeGenerated, UserId, Operation;
let Downloads = OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation == "FileDownloaded"
| summarize DownloadCount = count(), Files = make_set(SourceFileName, 10)
  by UserId, bin(TimeGenerated, 1h);
SuspiciousSignins
| join kind=inner (MailRules) on $left.UserPrincipalName == $right.UserId
| where RuleTime between (SigninTime .. (SigninTime + 4h))
| join kind=leftouter (Downloads) on $left.UserPrincipalName == $right.UserId
| project SigninTime, RuleTime, UserPrincipalName, IPAddress, RiskLevel,
          Operation, DownloadCount, Files
```

---

### 38. Consent Phishing — Malicious OAuth App Grant

**MITRE:** T1550.001 — Application Access Token
**Severity:** High
**Entity Mapping:** Account (UserPrincipalName)

```kql
let SuspiciousPermissions = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.Read.All", "Files.ReadWrite.All",
    "User.Read.All", "Directory.Read.All",
    "offline_access"
]);
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Consent to application"
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| mv-expand ModifiedProp = TargetResources[0].modifiedProperties
| where tostring(ModifiedProp.displayName) == "ConsentAction.Permissions"
| extend Permissions = tostring(ModifiedProp.newValue)
| where Permissions has_any (SuspiciousPermissions)
| project TimeGenerated, UserPrincipalName, AppName, AppId, Permissions
```

---

### 39. Conditional Access Policy Modification

**MITRE:** T1562 — Impair Defenses
**Severity:** High
**Entity Mapping:** Account (Initiator)

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "conditional access policy"
| where OperationName has_any ("Update", "Delete", "Disable")
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend PolicyName = tostring(TargetResources[0].displayName)
| mv-expand ModifiedProp = TargetResources[0].modifiedProperties
| extend PropertyName = tostring(ModifiedProp.displayName)
| extend OldValue = tostring(ModifiedProp.oldValue)
| extend NewValue = tostring(ModifiedProp.newValue)
| project TimeGenerated, Initiator, OperationName, PolicyName,
          PropertyName, OldValue, NewValue
```

---

### 40. Suspicious Azure AD Application Registration

**MITRE:** T1098.001 — Account Manipulation: Additional Cloud Credentials
**Severity:** Medium
**Entity Mapping:** Account (Initiator)

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("Add application", "Add service principal credentials",
                           "Update application – Certificates and secrets management")
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend TargetAppId = tostring(TargetResources[0].id)
| project TimeGenerated, Initiator, OperationName, TargetApp, TargetAppId
```

---

### 41. Token Replay / Stolen Session Token

**MITRE:** T1528 — Steal Application Access Token
**Severity:** High
**Entity Mapping:** Account (UserPrincipalName)

```kql
// Same token used from multiple IPs in short timeframe
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where isnotempty(OriginalRequestId)
| summarize
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Locations = make_set(tostring(LocationDetails.city), 10),
    AppList = make_set(AppDisplayName, 5)
  by UserPrincipalName, OriginalRequestId, bin(TimeGenerated, 1h)
| where DistinctIPs > 1
| project TimeGenerated, UserPrincipalName, DistinctIPs, IPList, Locations, AppList
```

---

### 42. Azure Key Vault Secret Access Anomaly

**MITRE:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
**Severity:** Medium
**Entity Mapping:** Account (CallerIPAddress)

```kql
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| summarize
    AccessCount = count(),
    DistinctSecrets = dcount(id_s),
    SecretNames = make_set(id_s, 20),
    ResultTypes = make_set(ResultType)
  by CallerIPAddress, Identity = identity_claim_upn_s, bin(TimeGenerated, 1h)
| where AccessCount > 20 or DistinctSecrets > 5
| project TimeGenerated, CallerIPAddress, Identity, AccessCount, DistinctSecrets, SecretNames
```
