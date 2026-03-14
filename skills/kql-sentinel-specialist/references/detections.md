# KQL Sentinel — Detection Rules Library

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

> Full detection library organized by MITRE ATT&CK tactics. Each detection includes: KQL query, MITRE technique ID, severity, entity mapping, and tuning notes.

---

## Initial Access

### 1. Brute Force — Multiple Failed Sign-ins Followed by Success

This detection identifies accounts that experience a high volume of failed sign-in attempts followed by a successful login within the same time window. Brute force attacks are one of the most common initial access techniques, where adversaries systematically try passwords until they find the correct one. A successful login after many failures strongly suggests credential compromise.

**Importance:** A SOC analyst should prioritize this alert because it indicates an attacker likely guessed or cracked a user's password and now has authenticated access to the environment.

**MITRE:** T1110 — Brute Force

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |
| IP | Address | IPAddress |

```kql
let threshold = 10;
let timeframe = 1h;
SigninLogs
// Filter to the detection window
| where TimeGenerated > ago(timeframe)
// Aggregate both failed and successful sign-ins per user
| summarize
    FailureCount = countif(ResultType != 0),
    SuccessCount = countif(ResultType == 0),
    IPAddresses = make_set(IPAddress, 100),
    AppList = make_set(AppDisplayName, 10),
    FailureReasons = make_set(ResultDescription, 5),
    FirstFailure = minif(TimeGenerated, ResultType != 0),
    LastSuccess = maxif(TimeGenerated, ResultType == 0)
  by UserPrincipalName
// Threshold: require at least N failures AND at least one success
| where FailureCount >= threshold and SuccessCount > 0
// Ensure the success came AFTER the failures (not before)
| where LastSuccess > FirstFailure
| extend TimeBetween = LastSuccess - FirstFailure
| project UserPrincipalName, FailureCount, SuccessCount, IPAddresses, AppList, FailureReasons, TimeBetween
```

**Tuning:** Adjust `threshold` based on environment. Exclude service accounts. Exclude known VPN/proxy IPs that cause legitimate failures.

---

### 2. Impossible Travel — Sign-ins from Geographically Distant Locations

This detection finds instances where the same user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible. This is a strong indicator that account credentials have been compromised and are being used by an attacker from a different location. The query uses the Haversine formula to calculate the distance between consecutive sign-in locations.

**Importance:** A SOC analyst should investigate this alert because it reveals likely credential theft — a legitimate user cannot physically be in two distant places within minutes.

**MITRE:** T1078 — Valid Accounts

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |
| IP | Address | IPAddress |
| IP | Address | PrevIP |

```kql
let timeWindow = 2h;
let minDistance = 500; // km — adjust for your org
SigninLogs
// Look back 24 hours for sign-in pairs
| where TimeGenerated > ago(24h)
// Only consider successful sign-ins
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend Lat = todouble(LocationDetails.geoCoordinates.latitude)
| extend Lon = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(City) and isnotnull(Lat)
// Order by user and time to compare consecutive logins
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend
    PrevUser = prev(UserPrincipalName),
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Lat), PrevLon = prev(Lon),
    PrevCity = prev(City), PrevCountry = prev(Country),
    PrevIP = prev(IPAddress)
// Only compare consecutive rows for the same user
| where UserPrincipalName == PrevUser
| extend TimeDelta = (TimeGenerated - PrevTime) / 1m
// Filter: the two sign-ins must be within the time window
| where TimeDelta < (timeWindow / 1m)
// Haversine approximation to calculate distance in km
| extend DistanceKm = 6371 * acos(
    sin(radians(Lat)) * sin(radians(PrevLat)) +
    cos(radians(Lat)) * cos(radians(PrevLat)) * cos(radians(PrevLon - Lon))
  )
// Threshold: flag only if distance exceeds minimum
| where DistanceKm > minDistance
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country,
          PrevIP, PrevCity, PrevCountry, TimeDelta, DistanceKm
```

**Tuning:** Exclude VPN IPs. Adjust distance/time thresholds. Whitelist known travel patterns.

---

### 3. Phishing Email Delivered with Malicious Attachment

This detection identifies inbound emails that were successfully delivered to a user's mailbox despite being flagged as phishing or containing malware. Email remains the primary initial access vector for most threat actors, and a delivered malicious attachment means the user could execute it at any time. Correlating with attachment metadata helps analysts quickly identify the specific payload.

**Importance:** A SOC analyst should act on this immediately because a malicious email has already landed in a user's inbox and the user may open the attachment at any moment.

**MITRE:** T1566.001 — Phishing: Spearphishing Attachment

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| MailMessage | Recipient | RecipientEmailAddress |
| File | Name | FileName |

```kql
EmailEvents
// Look back 24 hours for delivered phishing emails
| where TimeGenerated > ago(24h)
// Only inbound emails that were actually delivered
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
// Key filter: must be flagged as phishing or malware by the mail filter
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
// Join with attachment info to get file details
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

This detection identifies accounts receiving an unusually high number of MFA push requests in a short period, which is characteristic of MFA fatigue attacks. Adversaries who have obtained valid credentials will repeatedly trigger MFA prompts, hoping the user eventually approves one out of frustration or confusion. The query also checks whether the attacker ultimately succeeded in bypassing MFA.

**Importance:** A SOC analyst should treat this as urgent because if MFA was bypassed after the fatigue attack, the attacker has full authenticated access despite the second factor.

**MITRE:** T1621 — Multi-Factor Authentication Request Generation

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |
| IP | Address | IPAddress |

```kql
let mfaThreshold = 5;
SigninLogs
// Short detection window — MFA fatigue happens in bursts
| where TimeGenerated > ago(1h)
// Filter for MFA-required result codes
| where ResultType == 50074 or ResultType == 50076  // MFA required
// Aggregate MFA requests per user to find abnormal volumes
| summarize
    MFARequests = count(),
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Apps = make_set(AppDisplayName, 5),
    LastAttempt = max(TimeGenerated)
  by UserPrincipalName
// Threshold: flag users with excessive MFA prompts
| where MFARequests >= mfaThreshold
// Check if eventually succeeded — indicates MFA was bypassed
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

This detection identifies PowerShell processes launched with Base64-encoded command-line arguments, a technique heavily used by attackers to obfuscate malicious payloads. Legitimate administrators rarely use encoded commands, making this a reliable indicator of malicious activity. The query automatically decodes the payload so analysts can immediately see what was executed.

**Importance:** A SOC analyst should investigate because encoded PowerShell is the most common obfuscation technique used in malware droppers, post-exploitation frameworks, and fileless attacks.

**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |
| Process | CommandLine | ProcessCommandLine |

```kql
DeviceProcessEvents
// 24-hour lookback for encoded PowerShell execution
| where TimeGenerated > ago(24h)
// Filter for PowerShell executables
| where FileName in~ ("powershell.exe", "pwsh.exe")
// Key filter: detect encoded command flags
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-ec ")
// Extract the Base64 payload from the command line
| extend EncodedPayload = extract(@"(?i)-[eE](?:nc(?:odedCommand)?|c)?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| where isnotempty(EncodedPayload)
// Decode the Base64 payload so analysts can read the actual command
| extend DecodedCommand = base64_decode_tostring(EncodedPayload)
| project TimeGenerated, DeviceName, AccountName,
          ProcessCommandLine, DecodedCommand,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

### 6. LOLBAS/LOLBin Execution with Suspicious Parameters

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

### 7. WMI Remote Execution

This detection identifies processes spawned by the WMI Provider Host (wmiprvse.exe), which indicates remote code execution via Windows Management Instrumentation. WMI is a powerful administration framework that attackers frequently abuse for lateral movement and remote execution because it leaves minimal forensic artifacts. The query filters out normal WMI child processes to surface suspicious activity.

**Importance:** A SOC analyst should investigate because WMI-based remote execution is a hallmark of advanced adversaries and is commonly used in hands-on-keyboard lateral movement.

**MITRE:** T1047 — Windows Management Instrumentation

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
DeviceProcessEvents
// 24-hour lookback for WMI-spawned processes
| where TimeGenerated > ago(24h)
// Key filter: process was spawned by the WMI provider host
| where InitiatingProcessFileName =~ "wmiprvse.exe"
// Exclude normal WMI child processes to reduce noise
| where FileName !in~ ("wmiprvse.exe", "wmiapsrv.exe", "scrcons.exe")
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
// Aggregate to show the volume and variety of WMI-spawned processes
| summarize
    ProcessCount = count(),
    ProcessList = make_set(strcat(FileName, " → ", ProcessCommandLine), 10)
  by DeviceName, AccountName, bin(TimeGenerated, 1h)
```

---

### 8. Scheduled Task Creation via Command Line

This detection identifies the creation of scheduled tasks via the command line using schtasks.exe. Adversaries commonly create scheduled tasks for persistence, privilege escalation, or delayed execution of malicious payloads. While scheduled tasks have legitimate uses, creation via command line (especially from unusual parent processes) warrants investigation.

**Importance:** A SOC analyst should investigate because command-line scheduled task creation is a primary persistence mechanism that attackers use to survive reboots and maintain access.

**MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
DeviceProcessEvents
// 24-hour lookback for scheduled task creation
| where TimeGenerated > ago(24h)
// Filter for schtasks.exe execution
| where FileName =~ "schtasks.exe"
// Key filter: only task creation, not queries or deletions
| where ProcessCommandLine has "/create"
// Parse out the task name and command for analyst review
| parse ProcessCommandLine with * "/tn " TaskName " " *
| parse ProcessCommandLine with * "/tr " TaskCommand " " *
| project TimeGenerated, DeviceName, AccountName, TaskName, TaskCommand,
          ProcessCommandLine, InitiatingProcessFileName
```

---

## Persistence

### 9. New User Account Created

This detection monitors for the creation of new local user accounts on Windows systems via Security Event 4720. While account creation is a normal administrative activity, attackers frequently create new accounts to establish persistent backdoor access. Unexpected account creation, especially outside of change windows or by non-admin users, is a strong indicator of compromise.

**Importance:** A SOC analyst should review this alert because unauthorized account creation is one of the simplest and most effective persistence techniques attackers use to maintain access.

**MITRE:** T1136.001 — Create Account: Local Account

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetAccount |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for account creation events
| where TimeGenerated > ago(24h)
// Event ID 4720 = A user account was created
| where EventID == 4720
| project TimeGenerated, Computer, TargetAccount, TargetUserName, TargetDomainName,
          SubjectAccount, SubjectUserName, SubjectDomainName
```

---

### 10. New Entra ID User Created with Immediate Role Assignment

This detection correlates two events: the creation of a new Entra ID (Azure AD) user account followed by an immediate privileged role assignment within a short time window. This pattern is characteristic of an attacker who has gained administrative access and is creating a backdoor account with elevated privileges. Legitimate onboarding typically has a longer delay between account creation and role assignment.

**Importance:** A SOC analyst should treat this as high priority because rapid account creation followed by role assignment suggests an attacker is establishing a persistent privileged foothold in the cloud environment.

**MITRE:** T1136.003 — Create Account: Cloud Account

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetUPN |

```kql
let timeWindow = 1h;
// Step 1: Identify user creation events
let UserCreation = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add user"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project CreationTime = TimeGenerated, TargetUPN, Initiator;
// Step 2: Identify role assignment events
let RoleAssignment = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "Add member to role"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| project AssignmentTime = TimeGenerated, TargetUPN, RoleName;
// Correlate: join creation with role assignment for the same user
UserCreation
| join kind=inner (RoleAssignment) on TargetUPN
// Threshold: role must be assigned within the time window after creation
| where (AssignmentTime - CreationTime) between (0s .. timeWindow)
| project CreationTime, AssignmentTime, TargetUPN, Initiator, RoleName
```

---

### 11. Registry Run Key Persistence

This detection monitors for modifications to Windows Registry Run keys, which are one of the oldest and most commonly used persistence mechanisms. When a value is added to a Run key, the associated program executes automatically every time the user logs in. Attackers use this to ensure their malware or backdoor survives system reboots.

**Importance:** A SOC analyst should investigate because Registry Run key modifications are a classic persistence technique that allows malware to automatically execute on every user logon.

**MITRE:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Define the registry paths commonly abused for persistence
let RunKeyPaths = dynamic([
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    @"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
]);
DeviceRegistryEvents
// 24-hour lookback for registry modifications
| where TimeGenerated > ago(24h)
// Filter for registry value set operations only
| where ActionType == "RegistryValueSet"
// Key filter: only Run key paths that enable auto-start persistence
| where RegistryKey has_any (RunKeyPaths)
| project TimeGenerated, DeviceName, AccountName,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

### 12. New Windows Service Installed

This detection identifies the installation of new Windows services (Event ID 7045) where the service binary path references suspicious locations or known LOLBins. Attackers commonly install malicious services for persistence and privilege escalation because services run with SYSTEM-level privileges. Filtering on suspicious binary paths significantly reduces false positives from legitimate software installations.

**Importance:** A SOC analyst should investigate because a malicious Windows service provides SYSTEM-level persistent access — one of the most powerful persistence mechanisms available on Windows.

**MITRE:** T1543.003 — Create or Modify System Process: Windows Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for new service installations
| where TimeGenerated > ago(24h)
// Event ID 7045 = A new service was installed
| where EventID == 7045
| project TimeGenerated, Computer, ServiceName = tostring(EventData.ServiceName),
          ServiceFileName = tostring(EventData.ImagePath),
          ServiceType = tostring(EventData.ServiceType),
          ServiceStartType = tostring(EventData.StartType),
          ServiceAccount = tostring(EventData.AccountName)
// Key filter: only flag services with suspicious binary paths or LOLBin references
| where ServiceFileName has_any ("cmd", "powershell", "wscript", "cscript", "mshta",
          "\\Temp\\", "\\tmp\\", "\\AppData\\", "\\Users\\Public\\")
```

---

### 13. Inbox Rule Creation (Email Persistence)

This detection identifies the creation or modification of Outlook inbox rules that forward, redirect, or delete emails. Attackers who compromise email accounts frequently create inbox rules to maintain persistent access to communications, exfiltrate sensitive data, or hide evidence of their activity by deleting security notifications. Rules that forward to external addresses or move messages to obscure folders are especially suspicious.

**Importance:** A SOC analyst should investigate because malicious inbox rules allow attackers to silently intercept emails, hide breach notifications, and exfiltrate data long after the initial compromise.

**MITRE:** T1137.005 — Office Application Startup: Outlook Rules

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserId |

```kql
OfficeActivity
// 24-hour lookback for inbox rule changes
| where TimeGenerated > ago(24h)
// Filter for inbox rule creation or modification
| where Operation in ("New-InboxRule", "Set-InboxRule")
// Parse the rule parameters to extract key fields
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| extend MoveToFolder = tostring(parse_json(Parameters)[3].Value)
| extend ForwardTo = tostring(parse_json(Parameters)[4].Value)
| extend DeleteMessage = tostring(parse_json(Parameters)[5].Value)
// Key filter: only flag rules that forward, delete, or move to suspicious folders
| where isnotempty(ForwardTo) or isnotempty(DeleteMessage) or MoveToFolder has_any ("RSS", "Deleted", "Junk")
| project TimeGenerated, UserId, ClientIP, Operation, RuleName, ForwardTo, DeleteMessage, MoveToFolder
```

---

## Privilege Escalation

### 14. User Added to Privileged Entra ID Role

This detection monitors for users being assigned to high-privilege Entra ID (Azure AD) roles such as Global Administrator, Security Administrator, or Exchange Administrator. Privilege escalation via role assignment is a critical step in cloud-based attacks, as these roles grant broad access to tenant resources. Unauthorized role assignments often indicate an attacker has compromised an admin account and is elevating privileges.

**Importance:** A SOC analyst should treat this as high priority because assignment to a privileged Entra ID role grants sweeping control over the cloud tenant, and unauthorized assignments indicate active privilege escalation.

**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetUPN |

```kql
// Define the list of privileged roles to monitor
let PrivilegedRoles = dynamic([
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Conditional Access Administrator", "Authentication Administrator",
    "Privileged Authentication Administrator", "Billing Administrator"
]);
AuditLogs
// 24-hour lookback for role assignment events
| where TimeGenerated > ago(24h)
// Filter for role member additions
| where OperationName has "Add member to role"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = replace_string(tostring(TargetResources[0].modifiedProperties[1].newValue), '"', '')
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
// Key filter: only alert on privileged roles, not low-impact ones
| where RoleName in (PrivilegedRoles)
| project TimeGenerated, TargetUPN, RoleName, Initiator
```

---

### 15. Member Added to Sensitive Security Group

This detection monitors for users being added to sensitive on-premises Active Directory security groups such as Domain Admins, Enterprise Admins, and Schema Admins. These groups provide the highest levels of privilege in an AD environment. Unauthorized additions typically indicate an attacker has compromised a privileged account and is escalating their access to gain full domain control.

**Importance:** A SOC analyst should investigate immediately because membership in groups like Domain Admins or Enterprise Admins grants near-total control over the Active Directory environment.

**MITRE:** T1078.002 — Valid Accounts: Domain Accounts

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | MemberName |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for group membership changes
| where TimeGenerated > ago(24h)
// Event IDs: 4728 (Global), 4732 (Local), 4756 (Universal) group member add
| where EventID in (4728, 4732, 4756)
// Key filter: only flag additions to known sensitive/privileged groups
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

This detection identifies when Windows Security event logs are cleared, either through the Event Log service (Event ID 1102) or via the wevtutil command-line tool. Clearing security logs is a hallmark of attackers attempting to cover their tracks after performing malicious actions. This is almost never done legitimately in production environments and should be treated as a strong indicator of compromise.

**Importance:** A SOC analyst should treat this as high priority because log clearing is a deliberate anti-forensic technique — an attacker is actively trying to destroy evidence of their activity.

**MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | SubjectAccount |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for log clearing events
| where TimeGenerated > ago(24h)
// Event ID 1102 = The audit log was cleared
| where EventID == 1102
| project TimeGenerated, Computer, SubjectAccount = Account, Activity
| union (
    // Also detect command-line log clearing via wevtutil
    DeviceProcessEvents
    | where TimeGenerated > ago(24h)
    // Filter for wevtutil.exe usage
    | where FileName =~ "wevtutil.exe"
    // Key filter: detect clear-log commands
    | where ProcessCommandLine has_any ("cl", "clear-log")
    | project TimeGenerated, Computer = DeviceName, SubjectAccount = AccountName,
              Activity = strcat("wevtutil ", ProcessCommandLine)
)
```

---

### 17. Disabling Security Tools

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
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
```

---

### 18. Process Masquerading — Suspicious Process Path

This detection identifies critical Windows system processes (such as svchost.exe, lsass.exe, and csrss.exe) running from unexpected file paths. These processes should only ever run from specific system directories. When an attacker names their malware after a legitimate system process but places it in a different directory, it is a clear masquerading attempt designed to hide in plain sight.

**Importance:** A SOC analyst should investigate because a system process name running from a non-standard path is a near-certain indicator of malware masquerading as a trusted process.

**MITRE:** T1036.005 — Masquerading: Match Legitimate Name or Location

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Process | CommandLine | ProcessCommandLine |

```kql
// Define the legitimate paths for critical system processes
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
// 24-hour lookback for process execution
| where TimeGenerated > ago(24h)
// Filter for processes using critical system process names
| where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                       "smss.exe", "winlogon.exe", "taskhost.exe", "explorer.exe")
// Join with legitimate paths to compare
| join kind=inner (SystemProcesses) on $left.FileName == $right.ProcessName
// Key filter: flag processes NOT running from their legitimate paths
| where not(FolderPath has_any (LegitPaths))
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
```

---

## Credential Access

### 19. LSASS Memory Dump Indicators

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
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

### 20. Kerberoasting — Abnormal Service Ticket Requests

This detection identifies Kerberoasting attacks by finding accounts that request an unusually high number of Kerberos service tickets (TGS) with weak RC4 encryption. In a Kerberoasting attack, the adversary requests service tickets for service accounts, then cracks the tickets offline to obtain plaintext passwords. The use of RC4 encryption and high volume of distinct service ticket requests are the key indicators.

**Importance:** A SOC analyst should investigate because Kerberoasting can lead to the compromise of service account passwords, which often have elevated privileges and rarely get rotated.

**MITRE:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetAccount |
| Host | FullName | Computer |

```kql
let threshold = 5;
SecurityEvent
// Short 1-hour window — Kerberoasting happens in bursts
| where TimeGenerated > ago(1h)
// Event ID 4769 = A Kerberos service ticket was requested
| where EventID == 4769
| where Status == "0x0"
// Key filter: RC4 (weak) encryption indicates Kerberoasting
| where TicketEncryptionType in ("0x17", "0x18")
// Exclude machine accounts (end with $) and built-in accounts
| where ServiceName !endswith "$"
| where ServiceName !in ("krbtgt", "kadmin")
// Aggregate: count distinct services per requesting account
| summarize
    TicketCount = count(),
    ServiceNames = make_set(ServiceName, 20),
    DistinctServices = dcount(ServiceName)
  by TargetAccount = Account, Computer, IpAddress
// Threshold: requesting tickets for many distinct services is anomalous
| where DistinctServices >= threshold
| project TargetAccount, Computer, IpAddress, DistinctServices, ServiceNames
```

---

### 21. Password Spray Attack

This detection identifies password spray attacks by finding single IP addresses that attempt to authenticate against many different user accounts. Unlike brute force, password spraying tries a small number of common passwords across a large number of accounts to avoid lockout thresholds. The query aggregates failed authentication attempts by source IP and flags those targeting an unusually high number of distinct users.

**Importance:** A SOC analyst should investigate because password spraying is a stealthy technique designed to fly under lockout thresholds — even a single successful login out of many attempts gives the attacker a foothold.

**MITRE:** T1110.003 — Brute Force: Password Spraying

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | IPAddress |

```kql
let timeframe = 1h;
let userThreshold = 10;
// Common failure codes for invalid credentials
let failureCode = dynamic([50126, 50053, 50055, 50056]);
SigninLogs
// Short detection window for spray activity
| where TimeGenerated > ago(timeframe)
// Filter for authentication failure result codes
| where ResultType in (failureCode)
// Aggregate by source IP to detect one IP targeting many users
| summarize
    TargetedUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 50),
    AttemptCount = count(),
    Apps = make_set(AppDisplayName, 5),
    FailureCodes = make_set(ResultType)
  by IPAddress
// Threshold: flag IPs targeting more users than normal
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

This detection identifies hosts that are connecting to an unusually high number of distinct ports or remote hosts in a short time window, which is characteristic of network scanning and reconnaissance. Attackers perform network scanning after gaining initial access to map out the internal network, identify live hosts, and discover exploitable services. High port or host counts from a single source are strong indicators of automated scanning tools.

**Importance:** A SOC analyst should investigate because network scanning indicates an attacker is actively performing internal reconnaissance, which typically precedes lateral movement.

**MITRE:** T1046 — Network Service Discovery

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | LocalIP |

```kql
let portThreshold = 50;
let hostThreshold = 20;
DeviceNetworkEvents
// Short 1-hour window to detect scanning bursts
| where TimeGenerated > ago(1h)
// Filter for connection attempts (both successful and failed)
| where ActionType == "ConnectionAttempt" or ActionType == "ConnectionFailed"
// Aggregate: count distinct ports and hosts per source device
| summarize
    DistinctPorts = dcount(RemotePort),
    DistinctHosts = dcount(RemoteIP),
    PortList = make_set(RemotePort, 50),
    TargetHosts = make_set(RemoteIP, 20)
  by DeviceName, LocalIP, InitiatingProcessFileName
// Threshold: flag if port or host count exceeds normal levels
| where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
| project DeviceName, LocalIP, InitiatingProcessFileName,
          DistinctPorts, DistinctHosts, PortList, TargetHosts
```

---

### 23. Account Enumeration via LDAP

This detection identifies accounts performing an unusually high volume of LDAP queries against the directory, which indicates account enumeration and Active Directory reconnaissance. Attackers use LDAP queries to map out user accounts, group memberships, and organizational structure to identify high-value targets for lateral movement. While LDAP queries are normal in AD environments, the volume and pattern of queries differentiate legitimate tools from attacker reconnaissance.

**Importance:** A SOC analyst should investigate because high-volume LDAP enumeration indicates an attacker is mapping the Active Directory environment to identify targets for privilege escalation and lateral movement.

**MITRE:** T1087.002 — Account Discovery: Domain Account

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | AccountUpn |
| Host | FullName | DeviceName |

```kql
IdentityQueryEvents
// 24-hour lookback for LDAP query activity
| where TimeGenerated > ago(24h)
// Filter for LDAP query type
| where QueryType == "LDAP"
| where ActionType == "LDAP query"
// Aggregate: count total and distinct queries per user and device
| summarize
    QueryCount = count(),
    DistinctQueries = dcount(QueryTarget),
    Queries = make_set(QueryTarget, 20)
  by AccountUpn, DeviceName
// Threshold: flag accounts with abnormally high query volumes
| where QueryCount > 50
| project AccountUpn, DeviceName, QueryCount, DistinctQueries, Queries
```

---

## Lateral Movement

### 24. RDP from Single Account to Multiple Hosts

This detection identifies a single user account establishing Remote Desktop Protocol sessions to multiple distinct hosts within a short timeframe. While administrators may legitimately RDP to several servers, an attacker with compromised credentials will rapidly pivot across many systems via RDP to expand their access. The number of distinct target hosts is the key detection signal.

**Importance:** A SOC analyst should investigate because a single account RDP-ing to many hosts in rapid succession is a strong indicator of credential-based lateral movement across the network.

**MITRE:** T1021.001 — Remote Services: Remote Desktop Protocol

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | AccountName |
| IP | Address | RemoteIP |

```kql
let threshold = 3;
DeviceLogonEvents
// 24-hour lookback for RDP sessions
| where TimeGenerated > ago(24h)
// Filter for Remote Desktop (RemoteInteractive) logon type
| where LogonType == "RemoteInteractive"
// Aggregate: count distinct target hosts per account and source IP
| summarize
    TargetCount = dcount(DeviceName),
    Targets = make_set(DeviceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by AccountName, RemoteIP
// Threshold: flag accounts connecting to 3+ distinct hosts
| where TargetCount >= threshold
| project AccountName, RemoteIP, TargetCount, Targets, FirstSeen, LastSeen
```

---

### 25. PSRemoting / WinRM Lateral Movement

This detection identifies processes spawned by the Windows Remote Management (WinRM) host process (wsmprovhost.exe), which indicates remote command execution via PowerShell Remoting. PSRemoting is a powerful legitimate administration tool, but it is also heavily abused by attackers for fileless lateral movement because commands execute entirely in memory on the target host. The query filters out normal WinRM child processes to surface suspicious activity.

**Importance:** A SOC analyst should investigate because PSRemoting-based lateral movement is fileless and leaves minimal disk artifacts, making it a preferred technique for sophisticated attackers.

**MITRE:** T1021.006 — Remote Services: Windows Remote Management

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
DeviceProcessEvents
// 24-hour lookback for WinRM-spawned processes
| where TimeGenerated > ago(24h)
// Key filter: process was spawned by the WinRM host process
| where InitiatingProcessFileName =~ "wsmprovhost.exe"  // WinRM host process
// Exclude expected WinRM child processes
| where FileName !in~ ("wsmprovhost.exe", "conhost.exe")
| project TimeGenerated, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
// Aggregate to summarize remote execution activity per host
| summarize
    CommandCount = count(),
    Processes = make_set(FileName, 10),
    Commands = make_set(ProcessCommandLine, 10)
  by DeviceName, AccountName, bin(TimeGenerated, 1h)
```

---

### 26. SMB/Named Pipe Lateral Movement

This detection identifies access to administrative SMB shares (ADMIN$, C$, IPC$) from non-machine accounts, which is a common lateral movement technique. Attackers use these administrative shares to copy tools and malware to remote systems, execute commands, and access sensitive files. While administrative shares are used legitimately, access from standard user accounts or unusual source IPs warrants investigation.

**Importance:** A SOC analyst should investigate because administrative share access is the backbone of many lateral movement techniques including PsExec, remote service installation, and manual file staging.

**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | SubjectAccount |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for SMB share access events
| where TimeGenerated > ago(24h)
// Event ID 5145 = A network share object was checked for access
| where EventID == 5145
// Key filter: only administrative shares used for lateral movement
| where ShareName in (@"\*\ADMIN$", @"\*\C$", @"\*\IPC$")
// Exclude machine accounts (end with $) which access these legitimately
| where SubjectUserName !endswith "$"
// Aggregate access count to identify high-volume/automated activity
| summarize
    AccessCount = count(),
    Shares = make_set(ShareName),
    Targets = make_set(RelativeTargetName, 20)
  by SubjectAccount, Computer, IpAddress
// Threshold: flag high-volume share access
| where AccessCount > 10
```

---

### 27. Pass-the-Hash Detection

This detection identifies potential Pass-the-Hash attacks by finding NTLM network logons from a single account and IP address to multiple distinct hosts. In a Pass-the-Hash attack, the adversary uses a stolen NTLM hash (rather than a plaintext password) to authenticate to remote systems. The use of NTLM authentication combined with network logon type across multiple hosts is a strong indicator of this technique.

**Importance:** A SOC analyst should treat this as high priority because Pass-the-Hash enables an attacker to move laterally across the domain using stolen credential hashes without knowing the actual password.

**MITRE:** T1550.002 — Use Alternate Authentication Material: Pass the Hash

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetUserName |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for NTLM logon events
| where TimeGenerated > ago(24h)
// Event ID 4624 = An account was successfully logged on
| where EventID == 4624
// Key filter: Network logon (Type 3) + NTLM = PtH pattern
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
// Exclude machine accounts and local/loopback addresses
| where TargetUserName !endswith "$"
| where IpAddress != "-" and IpAddress != "127.0.0.1"
// Aggregate: count distinct target hosts per account and source IP
| summarize
    LogonCount = count(),
    DistinctHosts = dcount(Computer),
    HostList = make_set(Computer, 20)
  by TargetUserName, TargetDomainName, IpAddress
// Threshold: NTLM logons to 3+ distinct hosts from same source is suspicious
| where DistinctHosts >= 3
| project TargetUserName, TargetDomainName, IpAddress, DistinctHosts, HostList, LogonCount
```

---

## Collection

### 28. Mass File Download from SharePoint/OneDrive

This detection identifies users downloading an unusually high number of files from SharePoint or OneDrive in a short time window. Mass file downloads can indicate data collection by a compromised account, an insider threat staging data for exfiltration, or an attacker harvesting sensitive documents. The query aggregates download activity per user and flags those exceeding a configurable threshold.

**Importance:** A SOC analyst should investigate because mass file downloads from cloud storage typically precede data exfiltration and may indicate a compromised account or malicious insider.

**MITRE:** T1213.002 — Data from Information Repositories: SharePoint

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserId |

```kql
let threshold = 50;
OfficeActivity
// Short 1-hour window to detect burst download activity
| where TimeGenerated > ago(1h)
// Filter for SharePoint and OneDrive workloads
| where OfficeWorkload in ("SharePoint", "OneDrive")
// Key filter: only file download operations
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
// Aggregate download activity per user and source IP
| summarize
    DownloadCount = count(),
    DistinctFiles = dcount(OfficeObjectId),
    Sites = make_set(Site_Url, 5),
    SampleFiles = make_set(SourceFileName, 10)
  by UserId, ClientIP
// Threshold: flag users exceeding the download limit
| where DownloadCount >= threshold
| project UserId, ClientIP, DownloadCount, DistinctFiles, Sites, SampleFiles
```

---

## Command and Control

### 29. DNS Tunneling Detection

This detection identifies potential DNS tunneling by finding DNS queries with abnormally long subdomain names, which is characteristic of data being encoded into DNS requests. DNS tunneling is a covert communication technique where attackers encode commands and exfiltrated data within DNS queries and responses to bypass network security controls. Long, high-entropy subdomains with high query volumes to the same top-level domain are the key indicators.

**Importance:** A SOC analyst should investigate because DNS tunneling allows attackers to maintain command and control communication and exfiltrate data through a protocol that is rarely inspected or blocked.

**MITRE:** T1071.004 — Application Layer Protocol: DNS

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | Computer |
| IP | Address | ClientIP |

```kql
DnsEvents
// 24-hour lookback for DNS query analysis
| where TimeGenerated > ago(24h)
// Parse the domain into components for analysis
| extend DomainParts = split(Name, ".")
| extend SubdomainLength = strlen(tostring(DomainParts[0]))
| extend TLD = strcat(tostring(DomainParts[-2]), ".", tostring(DomainParts[-1]))
// Key filter: long subdomains indicate encoded data in DNS queries
| where SubdomainLength > 30
// Aggregate: measure query volume and subdomain characteristics per destination domain
| summarize
    QueryCount = count(),
    AvgSubdomainLen = avg(SubdomainLength),
    MaxSubdomainLen = max(SubdomainLength),
    UniqueSubs = dcount(tostring(DomainParts[0]))
  by TLD, ClientIP, Computer
// Threshold: high query count + long average subdomain = tunneling
| where QueryCount > 100 and AvgSubdomainLen > 20
| project Computer, ClientIP, TLD, QueryCount, AvgSubdomainLen, MaxSubdomainLen, UniqueSubs
```

---

### 30. Beaconing Detection — Regular Interval Callbacks

This detection identifies network beaconing behavior by analyzing the regularity of outbound connections from a host to a specific remote IP. Command and control implants typically call back to their C2 server at regular intervals (beaconing), and this periodic pattern can be detected by measuring the standard deviation of time intervals between connections. A low standard deviation relative to the average interval indicates a high degree of regularity consistent with automated beaconing.

**Importance:** A SOC analyst should investigate because regular-interval network callbacks are the signature behavior of C2 implants, and identifying beaconing early can stop an attack before data exfiltration or lateral movement.

**MITRE:** T1071 — Application Layer Protocol

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | RemoteIP |

```kql
let minConnections = 20;
DeviceNetworkEvents
// 24-hour lookback for connection pattern analysis
| where TimeGenerated > ago(24h)
// Filter for successful outbound connections
| where ActionType == "ConnectionSuccess"
// Only analyze connections to public IPs (not internal)
| where RemoteIPType == "Public"
// Aggregate connection timestamps per unique communication pair
| summarize
    ConnectionTimes = make_list(TimeGenerated, 1000),
    ConnectionCount = count()
  by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
// Threshold: need enough connections for statistical analysis
| where ConnectionCount >= minConnections
// Calculate time deltas between consecutive connections
| mv-apply ct = ConnectionTimes to typeof(datetime) on (
    serialize
    | extend NextTime = next(ct)
    | where isnotnull(NextTime)
    | extend Delta = datetime_diff("second", NextTime, ct)
    | summarize AvgDelta = avg(Delta), StdevDelta = stdev(Delta), Deltas = count()
)
// Detection logic: low standard deviation = regular interval = beaconing
| where StdevDelta < AvgDelta * 0.2  // <20% variation
| where AvgDelta between (10 .. 3600)  // 10s to 1h intervals
| project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName,
          ConnectionCount, AvgDelta, StdevDelta
| order by StdevDelta asc
```

---

### 31. Connection to Known Malicious IP (TI Match)

This detection correlates outbound network connections against known malicious IP addresses from threat intelligence feeds. When a device connects to an IP that has been flagged as malicious by threat intelligence providers, it strongly suggests compromise — either by malware communicating with its C2 infrastructure or by a user inadvertently visiting a malicious host. The query enriches matches with TI metadata to provide context for the analyst.

**Importance:** A SOC analyst should prioritize this alert because a confirmed connection to a threat-intelligence-flagged IP address is direct evidence of communication with known attacker infrastructure.

**MITRE:** T1071 — Application Layer Protocol

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | RemoteIP |

```kql
// Step 1: Build a list of active malicious IPs from threat intelligence
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where Active == true and ExpirationDateTime > now()
| where isnotempty(NetworkIP)
| distinct NetworkIP;
// Step 2: Find device connections to any of those malicious IPs
DeviceNetworkEvents
// 24-hour lookback for outbound connections
| where TimeGenerated > ago(24h)
// Key filter: match against threat intelligence IP list
| where RemoteIP in (TI_IPs)
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
// Enrich with threat intelligence metadata for analyst context
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | project NetworkIP, ThreatType, Description, Confidence, Tags
  ) on $left.RemoteIP == $right.NetworkIP
```

---

## Exfiltration

### 32. Large Outbound Data Transfer

This detection identifies hosts sending unusually large volumes of data to public IP addresses, which may indicate data exfiltration. Attackers who have collected sensitive data will transfer it out of the network, often using legitimate protocols to blend in. A threshold-based approach on total bytes sent to external IPs per time window helps surface these bulk transfers.

**Importance:** A SOC analyst should investigate because large outbound data transfers to public IPs are a primary indicator of active data exfiltration, which represents the final stage of many attack chains.

**MITRE:** T1048 — Exfiltration Over Alternative Protocol

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | RemoteIP |

```kql
let bytesThreshold = 100000000; // 100MB
DeviceNetworkEvents
// 24-hour lookback for outbound transfer analysis
| where TimeGenerated > ago(24h)
// Filter for successful outbound connections
| where ActionType == "ConnectionSuccess"
// Only analyze transfers to public (external) IPs
| where RemoteIPType == "Public"
// Aggregate: total bytes sent per device, destination, and time window
| summarize
    TotalBytesSent = sum(SentBytes),
    ConnectionCount = count(),
    Ports = make_set(RemotePort, 10),
    Processes = make_set(InitiatingProcessFileName, 10)
  by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
// Threshold: flag transfers exceeding 100MB
| where TotalBytesSent > bytesThreshold
| extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
| project TimeGenerated, DeviceName, RemoteIP, TotalMB, ConnectionCount, Ports, Processes
| order by TotalMB desc
```

---

### 33. Anomalous Email Forwarding Rule

This detection identifies the creation of email forwarding or redirect rules that send copies of emails to external addresses. This is a critical exfiltration technique where attackers set up auto-forwarding rules on compromised mailboxes to continuously receive copies of all incoming emails without needing to remain logged in. The query extracts the external domain being forwarded to, enabling analysts to quickly assess the severity.

**Importance:** A SOC analyst should treat this as high priority because email forwarding rules provide attackers with continuous, passive access to all emails in a compromised mailbox — often persisting long after the initial access is remediated.

**MITRE:** T1114.003 — Email Collection: Email Forwarding Rule

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserId |

```kql
OfficeActivity
// 24-hour lookback for email rule changes
| where TimeGenerated > ago(24h)
// Filter for inbox and transport rule creation/modification
| where Operation in ("New-InboxRule", "Set-InboxRule", "New-TransportRule", "Set-TransportRule")
| extend Parameters = parse_json(Parameters)
// Expand parameters to inspect each rule setting
| mv-expand Parameters
| extend ParamName = tostring(Parameters.Name), ParamValue = tostring(Parameters.Value)
// Key filter: only rules that forward, redirect, or forward-as-attachment
| where ParamName in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| where isnotempty(ParamValue)
// Extract the external domain for analyst review
| extend ExternalDomain = extract(@"@(.+)$", 1, ParamValue)
| project TimeGenerated, UserId, ClientIP, Operation, ParamName,
          ForwardTarget = ParamValue, ExternalDomain
```

---

## Impact

### 34. Ransomware Indicators — Mass File Encryption

This detection identifies potential ransomware activity by monitoring for mass file rename operations using known ransomware file extensions, as well as the creation of ransom note files. Ransomware encrypts files and renames them with specific extensions, then drops instructional files telling victims how to pay. Detecting this pattern early — even within a 5-minute window — can enable containment before the entire environment is encrypted.

**Importance:** A SOC analyst should treat this as the highest priority because active ransomware encryption causes immediate, widespread data loss and every second of delay increases the blast radius.

**MITRE:** T1486 — Data Encrypted for Impact

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Define known ransomware file extensions
let encryptionExtensions = dynamic([
    ".encrypted", ".locked", ".crypto", ".crypt",
    ".enc", ".rzk", ".WNCRY", ".wnry", ".locky",
    ".cerber", ".zepto", ".thor", ".aaa", ".abc",
    ".xyz", ".zzzzz", ".micro", ".vvv"
]);
let renameThreshold = 50;
DeviceFileEvents
// Short 1-hour window for rapid ransomware detection
| where TimeGenerated > ago(1h)
// Filter for file rename operations (encryption renames files)
| where ActionType == "FileRenamed"
| extend NewExtension = extract(@"(\.\w+)$", 1, FileName)
// Key filter: match ransomware extensions or ransom note filenames
| where NewExtension in (encryptionExtensions) or
        // Detect ransom note creation
        FileName in~ ("README.txt", "DECRYPT_INSTRUCTIONS.txt",
                      "HOW_TO_DECRYPT.txt", "RECOVERY_INSTRUCTIONS.html",
                      "!README!.txt", "_readme.txt")
// Aggregate into 5-minute windows to detect rapid encryption bursts
| summarize
    RenameCount = count(),
    Extensions = make_set(NewExtension, 10),
    FolderPaths = make_set(FolderPath, 10),
    SampleFiles = make_set(FileName, 20)
  by DeviceName, AccountName, InitiatingProcessFileName,
     InitiatingProcessCommandLine, bin(TimeGenerated, 5m)
// Threshold: 50+ renames in 5 minutes indicates active ransomware
| where RenameCount >= renameThreshold
| project TimeGenerated, DeviceName, AccountName, RenameCount,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          Extensions, SampleFiles
```

---

### 35. Critical Service Stopped

This detection identifies attempts to stop critical Windows services such as security tools, databases, backup systems, and management infrastructure. Stopping critical services is a common precursor to ransomware deployment (to prevent backup recovery) and a defense evasion technique (to disable security monitoring). The query monitors for service stop commands targeting a curated list of high-value services.

**Importance:** A SOC analyst should respond urgently because stopping critical services — especially security and backup services — is a hallmark of ransomware operators preparing to encrypt the environment.

**MITRE:** T1489 — Service Stop

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Define the list of critical services to monitor
let CriticalServices = dynamic([
    "WinDefend", "MpsSvc", "wscsvc", "Sense",      // Security
    "MSSQLSERVER", "SQLSERVERAGENT",                  // Database
    "VSS", "wbengine", "SamSs",                       // Backup/Recovery
    "EventLog", "Winmgmt",                             // Management
    "W3SVC", "WAS"                                     // Web
]);
DeviceProcessEvents
// 24-hour lookback for service stop commands
| where TimeGenerated > ago(24h)
// Filter for tools commonly used to stop services
| where FileName in~ ("net.exe", "net1.exe", "sc.exe", "taskkill.exe")
// Key filter: detect stop or force-kill commands
| where ProcessCommandLine has "stop" or ProcessCommandLine has "/f"
// Extract the service name from the command line
| extend StoppedService = extract(@"(?:stop|/f)\s+[\"']?(\S+)", 1, ProcessCommandLine)
// Only alert on critical services, not routine service management
| where StoppedService in~ (CriticalServices)
| project TimeGenerated, DeviceName, AccountName, FileName,
          StoppedService, ProcessCommandLine, InitiatingProcessFileName
```

---

### 36. Azure Resource Deletion Spree

This detection identifies accounts deleting a high number of Azure resources in a short time window, which indicates either a destructive attack or a compromised account performing sabotage. Mass deletion of cloud resources can cause severe service disruption and data loss. The query aggregates successful delete operations by caller identity and flags those exceeding a configurable threshold.

**Importance:** A SOC analyst should treat this as critical because mass Azure resource deletion can cause immediate and widespread service outages and permanent data loss.

**MITRE:** T1485 — Data Destruction

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Caller |

```kql
let threshold = 10;
AzureActivity
// Short 1-hour window to detect deletion sprees
| where TimeGenerated > ago(1h)
// Filter for delete operations only
| where OperationNameValue has "delete"
// Only count successful deletions
| where ActivityStatusValue == "Succeeded"
// Aggregate: count deletions per caller to detect spree behavior
| summarize
    DeleteCount = count(),
    Resources = make_set(Resource, 20),
    ResourceTypes = make_set(ResourceProviderValue, 10),
    ResourceGroups = make_set(ResourceGroup, 10)
  by Caller, CallerIpAddress
// Threshold: flag accounts exceeding the deletion limit
| where DeleteCount >= threshold
| project Caller, CallerIpAddress, DeleteCount, ResourceTypes, Resources, ResourceGroups
```

---

## Cross-Tactic Detections

### 37. Full Attack Chain — Compromised Account to Data Exfiltration

This detection correlates three stages of a typical business email compromise (BEC) attack chain: a suspicious sign-in (initial access), inbox rule creation (persistence), and mass file downloads (collection/exfiltration). By joining these events for the same user account within a time window, the query surfaces complete attack chains that individual detections might miss. This multi-signal correlation produces very high-fidelity alerts.

**Importance:** A SOC analyst should treat this as the highest priority because a correlated three-stage attack chain — risky login, mail rule, and data download — is strong evidence of an active, ongoing compromise with data exfiltration.

**MITRE:** Multiple

**Severity:** High

```kql
// Stage 1: Identify suspicious sign-ins (risky logins that succeeded)
let SuspiciousSignins = SigninLogs
| where TimeGenerated > ago(24h)
// Filter for medium or high risk successful sign-ins
| where RiskLevelDuringSignIn in ("high", "medium")
| where ResultType == 0
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevel = RiskLevelDuringSignIn;
// Stage 2: Identify inbox rule creation (persistence)
let MailRules = OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project RuleTime = TimeGenerated, UserId, Operation;
// Stage 3: Identify mass file downloads (collection/exfiltration)
let Downloads = OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation == "FileDownloaded"
| summarize DownloadCount = count(), Files = make_set(SourceFileName, 10)
  by UserId, bin(TimeGenerated, 1h);
// Correlate: join all three stages for the same user account
SuspiciousSignins
| join kind=inner (MailRules) on $left.UserPrincipalName == $right.UserId
// Rule must be created within 4 hours of suspicious sign-in
| where RuleTime between (SigninTime .. (SigninTime + 4h))
| join kind=leftouter (Downloads) on $left.UserPrincipalName == $right.UserId
| project SigninTime, RuleTime, UserPrincipalName, IPAddress, RiskLevel,
          Operation, DownloadCount, Files
```

---

### 38. Consent Phishing — Malicious OAuth App Grant

This detection identifies users granting consent to OAuth applications that request sensitive permissions such as mail access, file access, or directory enumeration. Consent phishing is an increasingly common attack where users are tricked into authorizing a malicious application that then uses delegated permissions to access their data. The query flags consent events where the requested permissions match a list of commonly abused permission scopes.

**Importance:** A SOC analyst should investigate because a malicious OAuth app with consent-granted permissions can silently access the user's email, files, and directory data without needing the user's password.

**MITRE:** T1550.001 — Application Access Token

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |

```kql
// Define permission scopes commonly requested by malicious OAuth apps
let SuspiciousPermissions = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.Read.All", "Files.ReadWrite.All",
    "User.Read.All", "Directory.Read.All",
    "offline_access"
]);
AuditLogs
// 24-hour lookback for OAuth consent events
| where TimeGenerated > ago(24h)
// Filter for application consent operations
| where OperationName == "Consent to application"
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
// Expand modified properties to inspect granted permissions
| mv-expand ModifiedProp = TargetResources[0].modifiedProperties
| where tostring(ModifiedProp.displayName) == "ConsentAction.Permissions"
| extend Permissions = tostring(ModifiedProp.newValue)
// Key filter: only flag apps requesting sensitive/suspicious permissions
| where Permissions has_any (SuspiciousPermissions)
| project TimeGenerated, UserPrincipalName, AppName, AppId, Permissions
```

---

### 39. Conditional Access Policy Modification

This detection monitors for modifications, deletions, or disabling of Conditional Access policies in Entra ID. Conditional Access policies are a critical security control that enforces MFA requirements, device compliance, and access restrictions. An attacker who compromises an administrator account will often weaken or remove these policies to make subsequent access easier and avoid MFA challenges.

**Importance:** A SOC analyst should investigate immediately because weakening Conditional Access policies removes security guardrails and opens the door for unrestricted access to the entire cloud environment.

**MITRE:** T1562 — Impair Defenses

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Initiator |

```kql
AuditLogs
// 24-hour lookback for policy changes
| where TimeGenerated > ago(24h)
// Filter for Conditional Access policy operations
| where OperationName has "conditional access policy"
// Key filter: only flag modifications, deletions, and disabling — not creation
| where OperationName has_any ("Update", "Delete", "Disable")
| extend Initiator = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend PolicyName = tostring(TargetResources[0].displayName)
// Expand modified properties to show what changed
| mv-expand ModifiedProp = TargetResources[0].modifiedProperties
| extend PropertyName = tostring(ModifiedProp.displayName)
| extend OldValue = tostring(ModifiedProp.oldValue)
| extend NewValue = tostring(ModifiedProp.newValue)
| project TimeGenerated, Initiator, OperationName, PolicyName,
          PropertyName, OldValue, NewValue
```

---

### 40. Suspicious Azure AD Application Registration

This detection monitors for the creation of new Azure AD applications and the addition of credentials (secrets or certificates) to existing applications. Attackers who gain administrative access frequently register new applications or add credentials to existing ones to create persistent backdoor access. Application credentials allow API-based access that bypasses MFA and user-based conditional access policies.

**Importance:** A SOC analyst should investigate because malicious application registrations and credential additions provide persistent, MFA-bypassing access to tenant resources that survives password resets.

**MITRE:** T1098.001 — Account Manipulation: Additional Cloud Credentials

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Initiator |

```kql
AuditLogs
// 24-hour lookback for application changes
| where TimeGenerated > ago(24h)
// Key filter: operations related to app creation or credential management
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

This detection identifies potential token replay attacks by finding the same authentication token (identified by OriginalRequestId) being used from multiple distinct IP addresses within a short time window. When a session token is stolen (via malware, network interception, or browser exploitation), the attacker replays it from their own infrastructure. Seeing the same token appear from different IPs is a strong indicator that the token has been compromised.

**Importance:** A SOC analyst should treat this as high priority because token replay bypasses all authentication controls including MFA — the attacker has a fully authenticated session without needing credentials.

**MITRE:** T1528 — Steal Application Access Token

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |

```kql
// Detect the same authentication token used from multiple IP addresses
SigninLogs
// 24-hour lookback for token reuse analysis
| where TimeGenerated > ago(24h)
// Only analyze successful authentications
| where ResultType == 0
// Filter for entries with a request ID to track token reuse
| where isnotempty(OriginalRequestId)
// Aggregate: count distinct IPs per token per user
| summarize
    DistinctIPs = dcount(IPAddress),
    IPList = make_set(IPAddress, 10),
    Locations = make_set(tostring(LocationDetails.city), 10),
    AppList = make_set(AppDisplayName, 5)
  by UserPrincipalName, OriginalRequestId, bin(TimeGenerated, 1h)
// Detection logic: same token from more than one IP = stolen token
| where DistinctIPs > 1
| project TimeGenerated, UserPrincipalName, DistinctIPs, IPList, Locations, AppList
```

---

### 42. Azure Key Vault Secret Access Anomaly

This detection identifies anomalous access patterns to Azure Key Vault secrets, such as a single identity accessing an unusually high number of distinct secrets or making an excessive volume of secret retrieval calls. Key Vaults store sensitive credentials, API keys, and certificates, making them a high-value target for attackers. Abnormal access patterns may indicate an attacker enumerating and harvesting secrets after compromising a service principal or user identity.

**Importance:** A SOC analyst should investigate because Key Vault secrets contain the most sensitive credentials in the environment — mass retrieval likely indicates an attacker harvesting credentials for broader access.

**MITRE:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | Identity |
| IP | Address | CallerIPAddress |

```kql
AzureDiagnostics
// 24-hour lookback for Key Vault access analysis
| where TimeGenerated > ago(24h)
// Filter for Key Vault resources
| where ResourceType == "VAULTS"
// Filter for secret retrieval operations
| where OperationName == "SecretGet"
// Aggregate: count access volume and distinct secrets per caller
| summarize
    AccessCount = count(),
    DistinctSecrets = dcount(id_s),
    SecretNames = make_set(id_s, 20),
    ResultTypes = make_set(ResultType)
  by CallerIPAddress, Identity = identity_claim_upn_s, bin(TimeGenerated, 1h)
// Threshold: flag high volume or high breadth of secret access
| where AccessCount > 20 or DistinctSecrets > 5
| project TimeGenerated, CallerIPAddress, Identity, AccessCount, DistinctSecrets, SecretNames
```
