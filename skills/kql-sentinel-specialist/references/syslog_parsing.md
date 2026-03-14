# KQL Sentinel — Syslog, CEF & Custom Log Parsing

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

> Complete parsing patterns for Linux Syslog, CEF (Common Event Format), custom logs, and ASIM normalization.

---

## Linux Syslog Format

### Standard Syslog Structure

```
<priority>timestamp hostname process[pid]: message
```

Example:
```
<34>Jan 15 12:30:45 webserver01 sshd[12345]: Failed password for admin from 10.0.0.1 port 22 ssh2
```

In Sentinel, Syslog is pre-parsed into the `Syslog` table with these key columns:
- `Facility` — Syslog facility (auth, authpriv, kern, daemon, cron, local0-7, etc.)
- `SeverityLevel` — Syslog severity (emerg, alert, crit, err, warning, notice, info, debug)
- `HostName` — Source hostname
- `ProcessName` — Process name (e.g., sshd, sudo, cron)
- `SyslogMessage` — Raw message content (needs further parsing)

### Facility Codes

| Code | Facility | Description |
|---|---|---|
| 0 | kern | Kernel messages |
| 1 | user | User-level messages |
| 2 | mail | Mail system |
| 3 | daemon | System daemons |
| 4 | auth | Security/authorization |
| 5 | syslog | Syslog internal |
| 6 | lpr | Printer subsystem |
| 7 | news | Network news |
| 8 | uucp | UUCP subsystem |
| 9 | cron | Clock daemon (cron/at) |
| 10 | authpriv | Security/authorization (private) |
| 11 | ftp | FTP daemon |
| 16-23 | local0-local7 | Local use (custom) |

### Severity Levels

| Code | Severity | Description |
|---|---|---|
| 0 | emerg | System is unusable |
| 1 | alert | Action must be taken immediately |
| 2 | crit | Critical conditions |
| 3 | err | Error conditions |
| 4 | warning | Warning conditions |
| 5 | notice | Normal but significant |
| 6 | info | Informational |
| 7 | debug | Debug-level messages |

---

## Syslog Parsing Patterns

### SSH Authentication

```kql
// Failed SSH logins
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| parse SyslogMessage with * "Failed password for " FailedUser " from " SourceIP " port " SourcePort:int " " Protocol
| project TimeGenerated, HostName, FailedUser, SourceIP, SourcePort, Protocol

// Successful SSH logins
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where ProcessName == "sshd"
| where SyslogMessage has "Accepted"
| parse SyslogMessage with * "Accepted " AuthMethod " for " User " from " SourceIP " port " SourcePort:int " " Protocol
| project TimeGenerated, HostName, User, AuthMethod, SourceIP, SourcePort

// Invalid user attempts (username enumeration)
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "sshd"
| where SyslogMessage has "Invalid user"
| parse SyslogMessage with * "Invalid user " AttemptedUser " from " SourceIP " port " *
| project TimeGenerated, HostName, AttemptedUser, SourceIP

// SSH key-based auth
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "sshd"
| where SyslogMessage has "Accepted publickey"
| parse SyslogMessage with * "Accepted publickey for " User " from " SourceIP " port " SourcePort:int " " * "SHA256:" KeyFingerprint
| project TimeGenerated, HostName, User, SourceIP, KeyFingerprint

// SSH disconnections
Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Disconnected from"
| parse SyslogMessage with * "Disconnected from " DisconnectType " user " User " " SourceIP " port " SourcePort:int *
```

### Sudo Usage

```kql
// All sudo commands
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "sudo"
| where SyslogMessage !has "pam_unix"
| parse SyslogMessage with ActingUser " : TTY=" TTY " ; PWD=" WorkingDir " ; USER=" TargetUser " ; COMMAND=" Command
| project TimeGenerated, HostName, ActingUser, TargetUser, Command, WorkingDir, TTY

// Failed sudo attempts
Syslog
| where ProcessName == "sudo"
| where SyslogMessage has "NOT in sudoers" or SyslogMessage has "incorrect password"
| parse SyslogMessage with User " : " * "COMMAND=" AttemptedCommand
| project TimeGenerated, HostName, User, SyslogMessage, AttemptedCommand
```

### User/Group Management

```kql
// User creation
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "useradd" or SyslogMessage has "useradd"
| parse SyslogMessage with * "new user: name=" NewUser ", UID=" UID:int ", GID=" GID:int ", home=" HomeDir ", shell=" Shell
| project TimeGenerated, HostName, NewUser, UID, GID, HomeDir, Shell

// User deletion
Syslog
| where ProcessName == "userdel" or SyslogMessage has "userdel"
| parse SyslogMessage with * "delete user '" DeletedUser "'"

// Password changes
Syslog
| where ProcessName == "passwd"
| where SyslogMessage has "password changed"
| parse SyslogMessage with * "password changed for " User
| project TimeGenerated, HostName, User

// Group changes
Syslog
| where ProcessName in ("groupadd", "groupmod", "gpasswd")
| project TimeGenerated, HostName, ProcessName, SyslogMessage
```

### Firewall Logs (iptables/nftables)

```kql
// iptables/nftables blocked connections
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("BLOCKED", "DROP", "REJECT", "DPT=")
| parse SyslogMessage with * "SRC=" SrcIP " DST=" DstIP " " * "PROTO=" Protocol " " * "DPT=" DstPort:int " " *
| extend SrcPort = extract(@"SPT=(\d+)", 1, SyslogMessage)
| extend InInterface = extract(@"IN=(\S+)", 1, SyslogMessage)
| extend OutInterface = extract(@"OUT=(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, SrcIP, DstIP, Protocol, DstPort, SrcPort, InInterface, OutInterface
```

### Cron Job Execution

```kql
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "CRON" or ProcessName == "cron"
| where SyslogMessage has "CMD"
| parse SyslogMessage with "(" User ") CMD (" Command ")"
| project TimeGenerated, HostName, User, Command
```

### System Boot/Shutdown

```kql
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has_any ("System startup", "Booting", "shutdown", "Stopping", "Reached target Shutdown")
| project TimeGenerated, HostName, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

### Package Management

```kql
// APT package installations (Debian/Ubuntu)
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName has_any ("apt", "dpkg")
| where SyslogMessage has_any ("install", "upgrade", "remove")
| project TimeGenerated, HostName, ProcessName, SyslogMessage

// YUM/DNF installations (RHEL/CentOS)
Syslog
| where ProcessName has_any ("yum", "dnf", "rpm")
| where SyslogMessage has_any ("Installed", "Updated", "Erased")
```

### Systemd Service Changes

```kql
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "systemd"
| where SyslogMessage has_any ("Started", "Stopped", "Failed", "Reached target")
| parse SyslogMessage with Action " " ServiceDescription "."
| project TimeGenerated, HostName, Action, ServiceDescription
```

---

## CEF (Common Event Format)

### CEF Format Structure

```
CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
```

Example:
```
CEF:0|Palo Alto Networks|PAN-OS|10.0|TRAFFIC|traffic|3|src=10.0.0.1 dst=8.8.8.8 dpt=443 act=allow
```

### CEF to CommonSecurityLog Mapping

CEF fields are automatically mapped to `CommonSecurityLog` columns:

| CEF Key | CommonSecurityLog Column | Description |
|---|---|---|
| src | SourceIP | Source IP address |
| dst | DestinationIP | Destination IP address |
| spt | SourcePort | Source port |
| dpt | DestinationPort | Destination port |
| act | DeviceAction | Action taken (allow, deny, drop) |
| proto | Protocol | Network protocol |
| request | RequestURL | Request URL |
| msg | Message | Event message |
| cat | DeviceEventCategory | Event category |
| suser | SourceUserName | Source username |
| duser | DestinationUserName | Destination username |
| shost | SourceHostName | Source hostname |
| dhost | DestinationHostName | Destination hostname |
| smac | SourceMACAddress | Source MAC |
| dmac | DestinationMACAddress | Destination MAC |
| in | ReceivedBytes | Bytes received |
| out | SentBytes | Bytes sent |
| outcome | EventOutcome | Event outcome |
| reason | Reason | Event reason |
| fname | FileName | File name |
| fsize | FileSize | File size |
| fileHash | FileHash | File hash |
| cn1-cn3 | DeviceCustomNumber1-3 | Custom numeric fields |
| cn1Label-cn3Label | DeviceCustomNumber1-3Label | Custom numeric field labels |
| cs1-cs6 | DeviceCustomString1-6 | Custom string fields |
| cs1Label-cs6Label | DeviceCustomString1-6Label | Custom string field labels |
| flexString1-2 | FlexString1-2 | Flexible string fields |
| flexNumber1-2 | FlexNumber1-2 | Flexible numeric fields |
| deviceExternalId | DeviceExternalID | External device ID |
| rt | ReceiptTime | Event receipt time |

### CEF Parsing by Vendor

#### Palo Alto Networks PAN-OS

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Palo Alto Networks"
| where DeviceProduct == "PAN-OS"
// Traffic logs
| where Activity has "TRAFFIC"
| project TimeGenerated, SourceIP, SourcePort, DestinationIP, DestinationPort,
          DeviceAction, ApplicationProtocol, Protocol,
          SentBytes, ReceivedBytes,
          SourceUserName, DestinationUserName,
          DeviceCustomString1, DeviceCustomString1Label,  // Rule name
          DeviceCustomString2, DeviceCustomString2Label   // Zone info
```

#### Fortinet FortiGate

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Fortinet"
| where DeviceProduct == "Fortigate"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          DeviceAction, ApplicationProtocol, Protocol,
          SentBytes, ReceivedBytes,
          DeviceCustomString1, DeviceCustomString1Label,  // Policy name
          DeviceCustomString3, DeviceCustomString3Label   // Serial number
```

#### Check Point

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Check Point"
| where DeviceProduct == "VPN-1 & FireWall-1"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          DeviceAction, ApplicationProtocol, Protocol,
          DeviceCustomString2, DeviceCustomString2Label,  // Rule name
          LogSeverity, Activity
```

#### Cisco ASA

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Cisco"
| where DeviceProduct == "ASA"
| project TimeGenerated, SourceIP, SourcePort, DestinationIP, DestinationPort,
          DeviceAction, Protocol,
          DeviceEventClassID, Activity, Message
```

#### Trend Micro Deep Security

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Trend Micro"
| where DeviceProduct == "Deep Security Agent"
| project TimeGenerated, SourceIP, DestinationIP,
          DeviceAction, Activity, LogSeverity,
          DeviceCustomString1, DeviceCustomString1Label,
          Message
```

#### Generic CEF — Unknown/Custom Vendor

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize count() by DeviceVendor, DeviceProduct
| order by count_ desc

// Explore unknown vendor fields
CommonSecurityLog
| where DeviceVendor == "<YourVendor>"
| take 10
| project-away TenantId, SourceSystem, MG, ManagementGroupName, Type
```

### CEF Severity Mapping

```kql
CommonSecurityLog
| extend SeverityName = case(
    toint(LogSeverity) == 10 or LogSeverity == "10", "Critical",
    toint(LogSeverity) >= 7, "High",
    toint(LogSeverity) >= 4, "Medium",
    toint(LogSeverity) >= 1, "Low",
    "Informational"
  )
```

---

## Custom Log Parsing

### parse Operator Patterns

```kql
// Simple positional parsing
| parse SyslogMessage with * "user=" User " action=" Action " result=" Result

// With type hints
| parse SyslogMessage with * "duration=" Duration:long "ms status=" StatusCode:int

// Regex parsing (for complex patterns)
| parse kind=regex SyslogMessage with @"(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(?P<Level>\w+)\s+(?P<Message>.*)"

// Relaxed parsing (partial matches OK)
| parse kind=relaxed SyslogMessage with * "src=" SrcIP " dst=" DstIP " " *

// parse-where (only matching rows survive)
| parse-where SyslogMessage with "ERROR: " ErrorMessage " at " Location
```

### Key-Value Extraction

```kql
// Generic key=value parsing
| extend KVPairs = parse_json(
    strcat('{',
        replace_regex(
            replace_regex(SyslogMessage, @'(\w+)=([^\s]+)', @'"\1":"\2"'),
            @'" "', '","'
        ),
    '}')
  )

// Alternative: extract specific keys
| extend SrcIP = extract(@"src=(\S+)", 1, SyslogMessage)
| extend DstIP = extract(@"dst=(\S+)", 1, SyslogMessage)
| extend DstPort = toint(extract(@"dpt=(\d+)", 1, SyslogMessage))
| extend Action = extract(@"act=(\S+)", 1, SyslogMessage)
```

### Regex Extract Patterns

```kql
// IP address extraction
| extend IPs = extract_all(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", SyslogMessage)

// Email extraction
| extend Emails = extract_all(@"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b", SyslogMessage)

// URL extraction
| extend URLs = extract_all(@"(https?://[^\s\"'<>]+)", SyslogMessage)

// Domain extraction
| extend Domain = extract(@"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", 1, SyslogMessage)

// File path extraction (Windows)
| extend FilePath = extract(@"([A-Za-z]:\\[^\s:*?""<>|]+)", 1, SyslogMessage)

// File path extraction (Linux)
| extend FilePath = extract(@"(/[^\s:]+)", 1, SyslogMessage)

// Hash extraction
| extend MD5 = extract(@"\b([a-fA-F0-9]{32})\b", 1, SyslogMessage)
| extend SHA256 = extract(@"\b([a-fA-F0-9]{64})\b", 1, SyslogMessage)
```

### Multi-Line Log Handling

```kql
// Some logs span multiple lines — use Syslog with aggregation
Syslog
| where TimeGenerated > ago(1h)
| where ProcessName == "myapp"
| order by TimeGenerated asc, Computer
| serialize
| extend NextTime = next(TimeGenerated), NextMsg = next(SyslogMessage)
| extend TimeDelta = datetime_diff("second", NextTime, TimeGenerated)
| extend IsMultiLine = (TimeDelta < 1)  // Messages within 1 second
// Aggregate multi-line messages
| summarize FullMessage = strcat_array(make_list(SyslogMessage), "\n")
  by Computer, bin(TimeGenerated, 1s), ProcessName
```

### JSON Log Parsing

```kql
// Application logs that output JSON
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "myapp"
| where SyslogMessage startswith "{"
| extend Parsed = parse_json(SyslogMessage)
| extend
    Level = tostring(Parsed.level),
    Logger = tostring(Parsed.logger),
    Message = tostring(Parsed.message),
    TraceId = tostring(Parsed.trace_id),
    UserId = tostring(Parsed.user_id),
    Duration = todouble(Parsed.duration_ms)
```

### CSV/Delimiter Parsing

```kql
// Comma-separated log fields
| extend Fields = split(SyslogMessage, ",")
| extend
    Timestamp = tostring(Fields[0]),
    Action = tostring(Fields[1]),
    SourceIP = tostring(Fields[2]),
    DestIP = tostring(Fields[3]),
    Port = toint(Fields[4])

// Tab-separated
| extend Fields = split(SyslogMessage, "\t")

// Pipe-separated
| extend Fields = split(SyslogMessage, "|")
```

---

## ASIM (Advanced Security Information Model) Parsers

### What is ASIM?

ASIM provides **vendor-agnostic** normalized schemas. Instead of querying `SigninLogs` for Entra ID and `SecurityEvent` for Windows and `Syslog` for Linux, you query `_Im_Authentication()` and it normalizes all sources into one schema.

### Parser Naming Convention

| Prefix | Meaning |
|---|---|
| `_Im_` | Filtering parser (recommended — supports parameters) |
| `_ASim_` | Unifying parser (no parameters) |
| `vim` | Source-specific parser (e.g., `vimAuthenticationSigninLogs`) |

### Available ASIM Parsers

#### _Im_Authentication — Authentication Events

```kql
// Query all authentication sources (Entra ID, Windows, Linux, etc.)
_Im_Authentication(starttime=ago(1h), eventresult="Failure")
| summarize FailureCount = count() by TargetUsername, SrcIpAddr, EventProduct
| where FailureCount > 10
| order by FailureCount desc

// Parameters:
// starttime, endtime — time range
// targetusername_has — filter by username
// srcipaddr_has_any_prefix — filter by source IP
// eventresult — "Success" or "Failure"
// eventtype — "Logon", "Logoff", "Elevate"
// disabled — disable specific source parsers
```

#### _Im_NetworkSession — Network Sessions

```kql
// Query all firewall/NSG/network sources
_Im_NetworkSession(starttime=ago(1h), dstportnumber=22)
| summarize ConnectionCount = count() by SrcIpAddr, DstIpAddr, DvcAction
| where ConnectionCount > 100

// Parameters:
// starttime, endtime
// srcipaddr_has_any_prefix, dstipaddr_has_any_prefix
// dstportnumber — filter by destination port
// url_has_any — filter by URL
// httpuseragent_has_any
// eventresult — "Success" or "Failure"
```

#### _Im_Dns — DNS Events

```kql
// Query all DNS sources
_Im_Dns(starttime=ago(24h), domain_has_any=dynamic(["malicious.com", "evil.net"]))
| project TimeGenerated, SrcIpAddr, DnsQuery, DnsResponseName, EventProduct

// Parameters:
// starttime, endtime
// srcipaddr — source IP
// domain_has_any — domain filter
// responsecodename — DNS response code
// response_has_any_prefix — response content filter
// response_has_ipv4 — response contains specific IP
// eventtype — "Query", "Response"
```

#### _Im_ProcessCreate — Process Creation

```kql
// Query all process creation sources (Sysmon, MDE, Security Events)
_Im_ProcessCreate(
    starttime=ago(1h),
    commandline_has_any=dynamic(["mimikatz", "sekurlsa", "kerberos::list"])
)
| project TimeGenerated, DvcHostname, TargetProcessName,
          TargetProcessCommandLine, ActorUsername, EventProduct

// Parameters:
// starttime, endtime
// commandline_has_any, commandline_has_all
// commandline_has_any_ip_prefix
// actingprocess_has_any — parent process filter
// targetprocess_has_any — child process filter
// actorusername_has — username filter
// dvchostname_has_any — hostname filter
// hashes_has_any — file hash filter
```

#### _Im_FileEvent — File Events

```kql
_Im_FileEvent(starttime=ago(24h))
| where EventType == "FileCreated"
| where TargetFilePath has @"\Temp\"
| where TargetFileName has_any (".exe", ".dll", ".ps1", ".bat")
| project TimeGenerated, DvcHostname, ActorUsername,
          TargetFileName, TargetFilePath, EventProduct
```

#### _Im_WebSession — Web/Proxy Sessions

```kql
_Im_WebSession(starttime=ago(1h))
| where HttpStatusCode >= 400
| summarize ErrorCount = count() by Url, SrcIpAddr, HttpStatusCode
| where ErrorCount > 50
```

#### _Im_RegistryEvent — Registry Events

```kql
_Im_RegistryEvent(starttime=ago(24h))
| where EventType == "RegistryValueSet"
| where RegistryKey has @"CurrentVersion\Run"
| project TimeGenerated, DvcHostname, ActorUsername,
          RegistryKey, RegistryValue, RegistryValueData
```

#### _Im_AuditEvent — Audit Events

```kql
_Im_AuditEvent(starttime=ago(24h))
| where EventType in ("Create", "Delete")
| where Operation has "user"
| project TimeGenerated, ActorUsername, Operation, Object, EventProduct
```

### Custom ASIM Parser

```kql
// Create a custom source-specific parser for your vendor
let vimAuthenticationMyVendor = (
    starttime:datetime=datetime(null),
    endtime:datetime=datetime(null),
    targetusername_has:string="*"
) {
    Syslog
    | where (isnull(starttime) or TimeGenerated >= starttime)
    | where (isnull(endtime) or TimeGenerated <= endtime)
    | where ProcessName == "myvendor-auth"
    | parse SyslogMessage with * "user=" TargetUsername " result=" EventResult " ip=" SrcIpAddr
    | where (targetusername_has == "*" or TargetUsername has targetusername_has)
    | extend
        EventProduct = "MyVendor Auth",
        EventVendor = "MyVendor",
        EventSchema = "Authentication",
        EventSchemaVersion = "0.1.3",
        EventType = "Logon"
};
```

---

## Common Syslog Data Sources

### Linux Audit Daemon (auditd)

```kql
Syslog
| where TimeGenerated > ago(24h)
| where ProcessName == "audit" or Facility == "authpriv"
| where SyslogMessage has "type="
| extend AuditType = extract(@"type=(\w+)", 1, SyslogMessage)
| extend AuditResult = extract(@"res=(\w+)", 1, SyslogMessage)
| extend UID = extract(@"uid=(\d+)", 1, SyslogMessage)
| extend Command = extract(@"exe=""([^""]+)""", 1, SyslogMessage)
// Key audit types: EXECVE (command execution), USER_AUTH, USER_LOGIN, SYSCALL
```

### Apache/Nginx Access Logs

```kql
Syslog
| where ProcessName in ("apache2", "httpd", "nginx")
| parse SyslogMessage with ClientIP " - " User " [" * "] \"" Method " " URL " " * "\" " StatusCode:int " " ResponseSize:long
| project TimeGenerated, HostName, ClientIP, User, Method, URL, StatusCode, ResponseSize
```

### Docker Container Logs

```kql
Syslog
| where ProcessName == "dockerd" or SyslogMessage has "container"
| extend ContainerId = extract(@"container[= ]([a-f0-9]{12})", 1, SyslogMessage)
| extend ContainerAction = extract(@"container (\w+)", 1, SyslogMessage)
```
