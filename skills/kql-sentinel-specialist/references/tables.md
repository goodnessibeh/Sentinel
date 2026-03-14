# KQL Sentinel — Complete Table Reference

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

> All Microsoft Sentinel, Defender XDR, and Azure Monitor security tables with full schemas.

---

## Windows Security Tables

### SecurityEvent — Windows Security Event Log

**Key EventIDs:**

| EventID | Description | Category |
|---|---|---|
| 1100 | Event logging service shutdown | Audit |
| 1102 | Audit log cleared | Defense Evasion |
| 4624 | Successful logon | Logon |
| 4625 | Failed logon | Logon |
| 4627 | Group membership at logon | Logon |
| 4634 | Logoff | Logon |
| 4648 | Explicit credentials logon (runas) | Credential Access |
| 4656 | Object handle requested | Object Access |
| 4657 | Registry value modified | Persistence |
| 4663 | Object access attempt | Object Access |
| 4672 | Special privileges assigned | Privilege Escalation |
| 4688 | New process created | Execution |
| 4689 | Process terminated | Execution |
| 4697 | Service installed | Persistence |
| 4698 | Scheduled task created | Persistence |
| 4699 | Scheduled task deleted | Defense Evasion |
| 4700 | Scheduled task enabled | Persistence |
| 4702 | Scheduled task updated | Persistence |
| 4706 | Trust created to domain | Persistence |
| 4720 | User account created | Persistence |
| 4722 | User account enabled | Persistence |
| 4723 | Password change attempt | Credential Access |
| 4724 | Password reset attempt | Credential Access |
| 4725 | User account disabled | Account Management |
| 4726 | User account deleted | Account Management |
| 4728 | Member added to security-enabled global group | Privilege Escalation |
| 4732 | Member added to local group | Privilege Escalation |
| 4735 | Local group changed | Account Management |
| 4738 | User account changed | Account Management |
| 4740 | Account locked out | Credential Access |
| 4741 | Computer account created | Persistence |
| 4742 | Computer account changed | Account Management |
| 4756 | Member added to universal group | Privilege Escalation |
| 4767 | Account unlocked | Account Management |
| 4768 | Kerberos TGT requested | Credential Access |
| 4769 | Kerberos service ticket requested | Credential Access |
| 4770 | Kerberos service ticket renewed | Credential Access |
| 4771 | Kerberos pre-auth failed | Credential Access |
| 4776 | NTLM authentication (DC) | Credential Access |
| 4946 | Firewall rule added | Defense Evasion |
| 4947 | Firewall rule modified | Defense Evasion |
| 4950 | Firewall setting changed | Defense Evasion |
| 5136 | Directory service object modified | Persistence |
| 5145 | Network share access | Lateral Movement |
| 5156 | Windows Filtering Platform connection | Network |
| 5157 | Windows Filtering Platform blocked | Network |
| 7034 | Service crashed | Impact |
| 7036 | Service state change | Service Control |
| 7040 | Service start type changed | Persistence |
| 7045 | New service installed | Persistence |

**LogonType values (EventID 4624/4625):**

| LogonType | Name | Description |
|---|---|---|
| 2 | Interactive | Console logon (keyboard) |
| 3 | Network | Network logon (SMB, mapped drives) |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Service started by SCM |
| 7 | Unlock | Workstation unlocked |
| 8 | NetworkCleartext | Network logon with cleartext creds (IIS basic auth) |
| 9 | NewCredentials | Explicit creds logon (runas /netonly) |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Cached domain credentials |
| 12 | CachedRemoteInteractive | Cached RDP credentials |
| 13 | CachedUnlock | Cached unlock |

**Full Schema:**

```
TimeGenerated, Computer, EventID, Activity, Account, AccountType,
TargetAccount, TargetUserName, TargetDomainName, TargetUserSid,
SubjectAccount, SubjectUserName, SubjectDomainName, SubjectUserSid,
LogonType, LogonTypeName, LogonProcessName, AuthenticationPackageName,
IpAddress, IpPort, WorkstationName, Status, SubStatus,
Process, ProcessName, ProcessId, NewProcessId, NewProcessName,
ParentProcessName, CommandLine, TokenElevationType,
PrivilegeList, MemberName, MemberSid,
ShareName, ShareLocalPath, RelativeTargetName,
ObjectName, ObjectType, ObjectServer,
ServiceName, ServiceFileName, ServiceType, ServiceStartType, ServiceAccount,
RegistryKey, RegistryValueName, RegistryValueData,
SourceComputerId, ManagementGroupName, Channel, Task, Level
```

### WindowsEvent — New Windows Event Format

```
TimeGenerated, Computer, Channel, Provider, EventID,
EventData (dynamic), EventOriginId, ManagementGroupName,
RawEventData, TimeCreated
```

**NOTE:** EventData is dynamic JSON. Access fields via `EventData.TargetUserName`, etc.

```kql
WindowsEvent
| where EventID == 4625
| extend TargetUserName = tostring(EventData.TargetUserName)
| extend LogonType = toint(EventData.LogonType)
| extend IpAddress = tostring(EventData.IpAddress)
```

---

## Identity & Access (Microsoft Entra ID)

### SigninLogs — Interactive User Sign-ins

```
TimeGenerated, UserPrincipalName, UserDisplayName, UserId,
AppDisplayName, AppId, ResourceDisplayName, ResourceId,
IPAddress, IPAddressFromResourceProvider,
Location (dynamic: city, state, countryOrRegion, geoCoordinates),
LocationDetails (dynamic: city, state, countryOrRegion, geoCoordinates.latitude/longitude),
ResultType (0=success, non-zero=failure), ResultDescription,
Status (dynamic: errorCode, failureReason, additionalDetails),
ClientAppUsed, UserAgent, Browser, OperatingSystem,
DeviceDetail (dynamic: deviceId, displayName, operatingSystem, browser, isCompliant, isManaged),
ConditionalAccessStatus (success, failure, notApplied),
ConditionalAccessPolicies (dynamic array),
MfaDetail (dynamic: authMethod, authDetail),
AuthenticationDetails (dynamic array: authenticationMethod, succeeded, authenticationStepDateTime),
AuthenticationRequirement (singleFactorAuthentication, multiFactorAuthentication),
IsInteractive, TokenIssuerType, TokenIssuerName,
RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2,
NetworkLocationDetails, OriginalRequestId, CorrelationId,
HomeTenantId, ResourceTenantId, CrossTenantAccessType,
AuthenticationProcessingDetails, AuthenticationProtocol
```

**Common ResultType codes:**

| Code | Meaning |
|---|---|
| 0 | Success |
| 50053 | Account locked |
| 50055 | Password expired |
| 50056 | Invalid password |
| 50057 | Account disabled |
| 50058 | User didn't complete sign-in |
| 50074 | MFA required (strong auth) |
| 50076 | MFA required (conditional access) |
| 50079 | User must register for MFA |
| 50126 | Invalid username or password |
| 50140 | "Keep me signed in" interrupt |
| 53003 | Blocked by conditional access |
| 530032 | Blocked by security defaults |
| 700016 | Application not found |

### AADNonInteractiveUserSignInLogs

Same schema as SigninLogs but for non-interactive flows (token refresh, SSO, agent-based).

### AADServicePrincipalSignInLogs

```
TimeGenerated, ServicePrincipalName, ServicePrincipalId,
AppId, ResourceDisplayName, ResourceId,
IPAddress, Location, ResultType, ResultDescription,
ConditionalAccessStatus, CorrelationId
```

### AADManagedIdentitySignInLogs

```
TimeGenerated, ServicePrincipalName, ServicePrincipalId,
AppId, ResourceDisplayName, ResourceId,
IPAddress, Location, ResultType, ResultDescription,
FederatedCredentialId
```

### AuditLogs — Entra ID Directory Changes

```
TimeGenerated, OperationName, Category, Result, ResultDescription,
LoggedByService, CorrelationId, Identity,
InitiatedBy (dynamic: user.userPrincipalName, user.ipAddress, app.displayName, app.servicePrincipalId),
TargetResources (dynamic array: id, displayName, type, modifiedProperties),
AdditionalDetails (dynamic array: key, value),
AADTenantId, AADOperationType
```

**Common operations:**
- Add user, Update user, Delete user
- Add member to group, Remove member from group
- Add application, Update application, Delete application
- Add service principal, Update service principal
- Consent to application
- Add conditional access policy, Update conditional access policy
- Reset password, Change password
- Add role assignment, Remove role assignment

---

## Microsoft 365

### OfficeActivity — M365 Audit Logs

```
TimeGenerated, UserId, ClientIP, UserAgent,
OfficeWorkload (Exchange, SharePoint, OneDrive, AzureActiveDirectory, MicrosoftTeams),
Operation, RecordType, ResultStatus,
OfficeObjectId, Item, SourceFileName, SourceFileExtension,
Site_Url, DestinationFileName, DestinationRelativeUrl,
ExternalAccess, OrganizationName, OriginatingServer,
Members (dynamic), TeamName, ChannelName, MessageId,
AffectedItems (dynamic), ModifiedProperties (dynamic)
```

**Key Operations by Workload:**

| Workload | Key Operations |
|---|---|
| SharePoint | FileAccessed, FileDownloaded, FileUploaded, FileModified, FileDeleted, SharingSet, SharingInvitationCreated, AnonymousLinkCreated |
| Exchange | MailboxLogin, SendAs, SendOnBehalf, Create, MoveToDeletedItems, SoftDelete, HardDelete, Set-Mailbox, New-InboxRule, Set-InboxRule |
| OneDrive | FileDownloaded, FileUploaded, FileSyncUploadedFull, FileModifiedExtended |
| Teams | MemberAdded, MemberRemoved, TeamCreated, ChannelAdded, MessageCreatedHasLink |
| AzureAD | UserLoggedIn, Add user, Change user password |

### EmailEvents — Defender for Office 365

```
TimeGenerated, NetworkMessageId, InternetMessageId,
SenderFromAddress, SenderFromDomain, SenderDisplayName,
SenderMailFromAddress, SenderMailFromDomain, SenderIPv4,
RecipientEmailAddress, RecipientObjectId,
Subject, DeliveryAction (Delivered, Blocked, Replaced, Junked),
DeliveryLocation (Inbox, JunkFolder, Quarantine, External, Blocked),
EmailDirection (Inbound, Outbound, Intra-org),
ThreatTypes, ThreatNames, DetectionMethods,
PhishConfidenceLevel, BulkComplaintLevel, SpamConfidenceLevel,
AuthenticationDetails, Connectors,
OrgLevelAction, OrgLevelPolicy, UserLevelAction, UserLevelPolicy,
AttachmentCount, UrlCount, EmailLanguage, LatestDeliveryAction
```

### EmailAttachmentInfo

```
TimeGenerated, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
FileName, FileType, FileSize, SHA256,
MalwareFilterVerdict, ThreatTypes, ThreatNames,
DetectionMethods
```

### EmailUrlInfo

```
TimeGenerated, NetworkMessageId, Url, UrlDomain, UrlLocation,
ThreatTypes, ThreatNames, DetectionMethods
```

### EmailPostDeliveryEvents

```
TimeGenerated, NetworkMessageId, InternetMessageId,
RecipientEmailAddress, Action (ZAP, Manual removal, Dynamic Delivery),
ActionType, ActionTrigger, ActionResult,
DeliveryLocation, ThreatTypes
```

---

## Defender for Endpoint

### DeviceProcessEvents — Process Creation

```
TimeGenerated, DeviceId, DeviceName, ActionType,
FileName, FolderPath, SHA1, SHA256, MD5, FileSize,
ProcessId, ProcessCommandLine, ProcessCreationTime,
ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
ProcessVersionInfoFileDescription, ProcessVersionInfoOriginalFileName,
ProcessIntegrityLevel, ProcessTokenElevation,
AccountDomain, AccountName, AccountSid, AccountUpn, AccountObjectId,
LogonId, LogonType,
InitiatingProcessFileName, InitiatingProcessFolderPath,
InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,
InitiatingProcessId, InitiatingProcessCommandLine,
InitiatingProcessCreationTime, InitiatingProcessParentFileName,
InitiatingProcessParentId, InitiatingProcessParentCreationTime,
InitiatingProcessAccountDomain, InitiatingProcessAccountName,
InitiatingProcessAccountSid, InitiatingProcessAccountUpn,
InitiatingProcessIntegrityLevel, InitiatingProcessTokenElevation,
ReportId, AdditionalFields (dynamic)
```

### DeviceNetworkEvents — Network Connections

```
TimeGenerated, DeviceId, DeviceName, ActionType,
RemoteIP, RemotePort, RemoteUrl, RemoteIPType,
LocalIP, LocalPort, LocalIPType, Protocol,
InitiatingProcessFileName, InitiatingProcessFolderPath,
InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,
InitiatingProcessId, InitiatingProcessCommandLine,
InitiatingProcessCreationTime, InitiatingProcessParentFileName,
InitiatingProcessAccountDomain, InitiatingProcessAccountName,
InitiatingProcessAccountSid, InitiatingProcessIntegrityLevel,
AdditionalFields (dynamic), ReportId
```

### DeviceFileEvents — File Operations

```
TimeGenerated, DeviceId, DeviceName,
ActionType (FileCreated, FileModified, FileDeleted, FileRenamed),
FileName, FolderPath, SHA1, SHA256, MD5, FileSize, FileOriginUrl, FileOriginIP,
PreviousFileName, PreviousFolderPath,
InitiatingProcessFileName, InitiatingProcessFolderPath,
InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,
InitiatingProcessId, InitiatingProcessCommandLine,
InitiatingProcessCreationTime, InitiatingProcessParentFileName,
InitiatingProcessAccountDomain, InitiatingProcessAccountName,
IsAzureInfoProtectionApplied, SensitivityLabel, SensitivitySubLabel,
AdditionalFields (dynamic), ReportId
```

### DeviceRegistryEvents — Registry Changes

```
TimeGenerated, DeviceId, DeviceName,
ActionType (RegistryValueSet, RegistryKeyCreated, RegistryValueDeleted, RegistryKeyDeleted),
RegistryKey, RegistryValueName, RegistryValueData, RegistryValueType,
PreviousRegistryKey, PreviousRegistryValueName, PreviousRegistryValueData,
InitiatingProcessFileName, InitiatingProcessFolderPath,
InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,
InitiatingProcessId, InitiatingProcessCommandLine,
InitiatingProcessCreationTime, InitiatingProcessParentFileName,
InitiatingProcessAccountDomain, InitiatingProcessAccountName,
AdditionalFields (dynamic), ReportId
```

### DeviceLogonEvents — Device Logon Events

```
TimeGenerated, DeviceId, DeviceName,
ActionType, LogonType (Interactive, Network, RemoteInteractive, Batch, Service, Unlock, etc.),
AccountDomain, AccountName, AccountSid,
Protocol (NTLM, Kerberos, Negotiate),
RemoteIP, RemotePort, RemoteDeviceName,
IsLocalAdmin, FailureReason, LogonId,
InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine,
AdditionalFields (dynamic), ReportId
```

### DeviceImageLoadEvents — DLL/Module Loads

```
TimeGenerated, DeviceId, DeviceName, ActionType,
FileName, FolderPath, SHA1, SHA256, MD5, FileSize,
InitiatingProcessFileName, InitiatingProcessFolderPath,
InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,
InitiatingProcessId, InitiatingProcessCommandLine,
InitiatingProcessCreationTime, InitiatingProcessParentFileName,
InitiatingProcessAccountDomain, InitiatingProcessAccountName,
AdditionalFields (dynamic), ReportId
```

### DeviceEvents — Miscellaneous Device Events

```
TimeGenerated, DeviceId, DeviceName,
ActionType, AdditionalFields (dynamic),
FileName, FolderPath, SHA1, SHA256, MD5,
ProcessId, ProcessCommandLine,
AccountDomain, AccountName, AccountSid,
RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort,
RegistryKey, RegistryValueName, RegistryValueData,
InitiatingProcessFileName, InitiatingProcessFolderPath,
InitiatingProcessSHA1, InitiatingProcessSHA256,
InitiatingProcessId, InitiatingProcessCommandLine,
InitiatingProcessParentFileName, InitiatingProcessAccountName,
ReportId
```

**Key ActionTypes:**
- AntivirusDetection, AntivirusDetectionActionType
- ExploitGuardNetworkProtectionBlocked
- SmartScreenUrlWarning, SmartScreenAppWarning
- FirewallInboundConnectionBlocked, FirewallOutboundConnectionBlocked
- UsbDriveMounted, UsbDriveUnmounted
- TamperingAttempt
- PowerShellCommand, NamedPipeEvent
- ServiceInstalled, DriverLoad
- BrowserLaunchedToOpenUrl
- RemoteDesktopConnection, OpenedSshConnection

### DeviceInfo — Device Inventory

```
TimeGenerated, DeviceId, DeviceName, DeviceType,
OSPlatform, OSVersion, OSBuild, OSArchitecture, OSDistribution,
ClientVersion, PublicIP, MachineGroup,
IsAzureADJoined, IsAzureADRegistered,
OnboardingStatus, SensorHealthState,
ExposureLevel, DeviceCategory,
LoggedOnUsers (dynamic array), JoinType,
MergedDeviceIds, MergedToDeviceId,
AdditionalFields (dynamic)
```

### DeviceNetworkInfo — Network Configuration

```
TimeGenerated, DeviceId, DeviceName,
NetworkAdapterName, NetworkAdapterType (Ethernet, Wi-Fi, etc.),
MacAddress, IPAddresses (dynamic array),
DnsSuffix, DefaultGateway, ConnectedNetworks (dynamic),
TunnelType, NetworkAdapterStatus, NetworkAdapterVendor,
AdditionalFields (dynamic)
```

### DeviceTvmSoftwareInventory / DeviceTvmSoftwareVulnerabilities

```
// Software Inventory
TimeGenerated, DeviceId, DeviceName,
SoftwareName, SoftwareVersion, SoftwareVendor,
OSPlatform, OSVersion, EndOfSupportStatus

// Vulnerabilities
TimeGenerated, DeviceId, DeviceName,
CveId, VulnerabilitySeverityLevel (Critical, High, Medium, Low),
SoftwareName, SoftwareVersion, SoftwareVendor,
RecommendedSecurityUpdate, RecommendedSecurityUpdateId,
IsExploitAvailable, CvssScore
```

---

## Defender for Identity

### IdentityLogonEvents

```
TimeGenerated, AccountUpn, AccountDisplayName, AccountDomain, AccountName, AccountSid, AccountObjectId,
Application, Protocol (NTLM, Kerberos, LDAP, etc.),
LogonType, ActionType,
DestinationDeviceName, DestinationIPAddress, DestinationPort,
IPAddress, Location, ISP,
FailureReason, AdditionalFields (dynamic), ReportId
```

### IdentityQueryEvents — AD/LDAP Queries

```
TimeGenerated, AccountUpn, AccountDisplayName, AccountDomain, AccountName, AccountSid,
ActionType, Application, QueryType (LDAP, DNS, SAMAccountName, etc.),
QueryTarget, Query,
DestinationDeviceName, DestinationIPAddress, DestinationPort,
IPAddress, DeviceName, Protocol,
AdditionalFields (dynamic), ReportId
```

### IdentityDirectoryEvents — AD Changes

```
TimeGenerated, AccountUpn, AccountDisplayName, AccountDomain, AccountName, AccountSid,
ActionType, Application, Protocol,
TargetAccountUpn, TargetAccountDisplayName, TargetDeviceName,
DestinationDeviceName, DestinationIPAddress, DestinationPort,
IPAddress, DeviceName,
AdditionalFields (dynamic), ReportId
```

---

## Syslog & CEF

### Syslog — Linux Syslog

```
TimeGenerated, Computer, HostName, HostIP,
Facility (auth, authpriv, cron, daemon, kern, local0-local7, mail, syslog, user, etc.),
SeverityLevel (emerg, alert, crit, err, warning, notice, info, debug),
ProcessName, ProcessID,
SyslogMessage,
SourceSystem, CollectorHostName, EventTime, Type
```

### CommonSecurityLog — CEF Format

```
TimeGenerated, DeviceVendor, DeviceProduct, DeviceVersion,
DeviceEventClassID, Activity, LogSeverity,
SourceIP, SourcePort, SourceHostName, SourceUserName, SourceMACAddress, SourceTranslatedAddress, SourceTranslatedPort,
DestinationIP, DestinationPort, DestinationHostName, DestinationUserName, DestinationMACAddress, DestinationTranslatedAddress, DestinationTranslatedPort,
DeviceAction, ApplicationProtocol, Protocol, RequestURL, RequestMethod, RequestContext,
SentBytes, ReceivedBytes, BytesTotal,
DeviceName, DeviceAddress, DeviceExternalID, DeviceFacility,
Message, SimplifiedDeviceAction,
AdditionalExtensions, FlexString1, FlexString1Label, FlexString2, FlexString2Label,
FlexNumber1, FlexNumber1Label, FlexNumber2, FlexNumber2Label,
DeviceCustomString1-6, DeviceCustomString1-6Label,
DeviceCustomNumber1-3, DeviceCustomNumber1-3Label,
DeviceCustomDate1-2, DeviceCustomDate1-2Label,
DeviceCustomIPv6Address1-4, DeviceCustomIPv6Address1-4Label,
DeviceCustomFloatingPoint1-4, DeviceCustomFloatingPoint1-4Label,
ExternalID, Reason, Type, Computer, CollectorHostName
```

---

## Azure Platform

### AzureActivity — Azure Control Plane

```
TimeGenerated, Caller, CallerIpAddress,
OperationNameValue, OperationName, CategoryValue, Category,
ActivityStatusValue (Started, Succeeded, Failed), ActivitySubstatusValue,
ResourceGroup, ResourceProviderValue, Resource, ResourceId,
SubscriptionId, TenantId,
Level (Informational, Warning, Error, Critical),
Properties (dynamic), Authorization (dynamic), Claims (dynamic),
HTTPRequest (dynamic: clientRequestId, clientIpAddress, method),
CorrelationId, EventSubmissionTimestamp
```

### AzureDiagnostics — Azure Data Plane

```
TimeGenerated, ResourceType, ResourceId, Resource, ResourceGroup,
Category, OperationName, ResultType, ResultDescription, ResultSignature,
CallerIPAddress, Identity (dynamic),
DurationMs, Level, Location,
Properties (dynamic — varies by resource type),
SubscriptionId, TenantId, SourceSystem, Type
```

### AzureMetrics

```
TimeGenerated, ResourceId, MetricName, Namespace,
Total, Count, Maximum, Minimum, Average, TimeGrain,
UnitName, DimensionList
```

---

## Threat Intelligence

### ThreatIntelligenceIndicator

```
TimeGenerated, ThreatType, ThreatSeverity,
DomainName, Url, NetworkIP, NetworkSourceIP, NetworkDestinationIP, NetworkCidrBlock,
EmailSenderAddress, EmailSubject, EmailRecipient,
FileHashValue, FileHashType (MD5, SHA1, SHA256),
Description, Tags, Confidence, KillChainActions, KillChainPhases,
Action (alert, block, allow), Active, ExpirationDateTime,
SourceSystem, IndicatorId, TLPLevel, TrafficLightProtocolLevel,
AdditionalInformation, ExternalIndicatorId
```

---

## UEBA & Behavior

### BehaviorAnalytics

```
TimeGenerated, UserPrincipalName, UserName,
ActivityType, ActionType, SourceDevice, DestinationDevice,
SourceIPAddress, SourceIPLocation, DestinationIPAddress,
ActivityInsights (dynamic), UsersInsights (dynamic), DevicesInsights (dynamic),
InvestigationPriority (0-10), EventSource, SourceRecordId
```

### IdentityInfo

```
TimeGenerated, AccountUPN, AccountDisplayName, AccountName, AccountDomain,
AccountSID, AccountObjectId, AccountTenantId,
GivenName, Surname, Department, JobTitle, Manager, ManagerUPN,
City, State, Country, CompanyName, OfficeLocation,
Phone, EmailAddress,
IsAccountEnabled, DeletedDateTime,
RiskLevel (low, medium, high, none), RiskState, RiskDetail,
Tags (dynamic), AssignedRoles (dynamic), GroupMembership (dynamic),
SourceProvider, ChangeSource
```

---

## Sentinel Internal Tables

### SecurityAlert — All Alerts

```
TimeGenerated, AlertName, AlertType, AlertSeverity (High, Medium, Low, Informational),
Description, RemediationSteps, ExtendedLinks, ExtendedProperties (dynamic),
Entities (dynamic array), Tactics (dynamic), Techniques (dynamic),
ProviderName, ProductName, ProductComponentName, VendorName,
Status (New, InProgress, Resolved, Dismissed), CompromisedEntity,
StartTime, EndTime, ProcessingEndTime,
ConfidenceLevel, ConfidenceScore, IsIncident,
SystemAlertId, AlertLink, ResourceId, SourceComputerId,
WorkspaceSubscriptionId, WorkspaceResourceGroup, TenantId
```

### SecurityIncident

```
TimeGenerated, Title, Description, Severity (High, Medium, Low, Informational),
Status (New, Active, Closed), Classification (Undetermined, TruePositive, FalsePositive, BenignPositive),
ClassificationReason, ClassificationComment,
Owner (dynamic: email, assignedTo, userPrincipalName, objectId),
Labels (dynamic array), ProviderName, ProviderIncidentId,
AlertIds (dynamic array), BookmarkIds (dynamic array),
Comments (dynamic array), RelatedAnalyticRuleIds (dynamic array),
Tactics (dynamic array), Techniques (dynamic array),
FirstActivityTime, LastActivityTime, FirstModifiedTime, LastModifiedTime, CreatedTime, ClosedTime,
IncidentName, IncidentNumber, IncidentUrl, AdditionalData (dynamic),
ModifiedBy, TenantId
```

### Watchlist / _GetWatchlist

```kql
// Query a watchlist
_GetWatchlist('HighRiskUsers')
| project SearchKey, UserPrincipalName, RiskReason, LastUpdated

// Join with watchlist
SigninLogs
| where TimeGenerated > ago(24h)
| join kind=inner (_GetWatchlist('VIPUsers')) on $left.UserPrincipalName == $right.SearchKey
```

---

## ASIM Normalized Tables — Parser Functions

### _Im_Authentication

```
// Parameters: starttime, endtime, targetusername_has, srcipaddr_has_any_prefix, eventresult, eventtype, disabled
_Im_Authentication(starttime=ago(1h), eventresult="Failure")

// Schema:
TimeGenerated, EventProduct, EventVendor, EventSchema, EventSchemaVersion,
EventType (Logon, Logoff, Elevate), EventResult (Success, Failure),
EventResultDetails, EventSeverity, EventOriginalType,
TargetUsername, TargetUsernameType, TargetUserId, TargetUserIdType, TargetUserType,
ActorUsername, ActorUserId,
SrcIpAddr, SrcPortNumber, SrcHostname, SrcDvcId,
TargetIpAddr, TargetPortNumber, TargetHostname, TargetDvcId,
LogonMethod, LogonProtocol, HttpUserAgent,
ActingAppId, ActingAppName, ActingAppType,
DvcIpAddr, DvcHostname, DvcDomain
```

### _Im_NetworkSession

```
// Parameters: starttime, endtime, srcipaddr_has_any_prefix, dstipaddr_has_any_prefix, dstportnumber, url_has_any, httpuseragent_has_any, eventresult, disabled
_Im_NetworkSession(starttime=ago(1h))

// Schema:
TimeGenerated, EventProduct, EventVendor, EventSchema,
EventType (NetworkSession, EndpointNetworkSession), EventResult,
SrcIpAddr, SrcPortNumber, SrcHostname, SrcUsername,
DstIpAddr, DstPortNumber, DstHostname, DstUsername, DstNatIpAddr, DstNatPortNumber,
NetworkProtocol, NetworkDirection (Inbound, Outbound, Local),
NetworkApplicationProtocol, Url, UrlCategory,
SrcBytes, DstBytes, NetworkBytes, SrcPackets, DstPackets, NetworkPackets,
NetworkDuration, DvcAction (Allow, Deny, Drop, Reset),
ThreatName, ThreatCategory, ThreatRiskLevel, ThreatOriginalRiskLevel
```

### _Im_Dns

```
// Parameters: starttime, endtime, srcipaddr, domain_has_any, responsecodename, response_has_any_prefix, response_has_ipv4, eventtype, disabled
_Im_Dns(starttime=ago(1h))

// Schema:
TimeGenerated, EventProduct, EventVendor, EventSchema,
EventType (Query, Response), EventResult, EventResultDetails, EventSubType,
DnsQuery, DnsQueryType, DnsQueryTypeName, DnsQueryClass, DnsQueryClassName,
DnsResponseName, DnsResponseCode, DnsResponseCodeName,
DnsFlags, TransactionIdHex, NetworkProtocol,
SrcIpAddr, SrcPortNumber, SrcHostname, SrcUsername,
DstIpAddr, DstPortNumber, DstHostname,
Url, UrlCategory, Domain, DomainCategory,
ThreatName, ThreatCategory, ThreatRiskLevel
```

### _Im_ProcessCreate

```
// Parameters: starttime, endtime, commandline_has_any, commandline_has_all, commandline_has_any_ip_prefix, actingprocess_has_any, targetprocess_has_any, parentprocess_has_any, actorusername_has, targetusername_has, dvcipaddr_has_any_prefix, dvchostname_has_any, hashes_has_any, disabled
_Im_ProcessCreate(starttime=ago(1h))

// Schema:
TimeGenerated, EventProduct, EventVendor, EventSchema,
TargetProcessName, TargetProcessFileDescription, TargetProcessFileProduct,
TargetProcessFileVersion, TargetProcessFileCompany, TargetProcessFilePath,
TargetProcessId, TargetProcessGuid, TargetProcessCommandLine,
TargetProcessTokenElevation, TargetProcessIntegrityLevel,
TargetProcessMD5, TargetProcessSHA1, TargetProcessSHA256, TargetProcessIMPHASH,
TargetProcessCreationTime, TargetProcessCurrentDirectory,
ActingProcessName, ActingProcessFilePath, ActingProcessId,
ActingProcessGuid, ActingProcessCommandLine, ActingProcessCreationTime,
ActingProcessMD5, ActingProcessSHA1, ActingProcessSHA256,
ParentProcessName, ParentProcessId, ParentProcessGuid, ParentProcessCreationTime,
ActorUsername, ActorUsernameType, ActorUserId, ActorUserIdType, ActorUserType,
ActorSessionId, ActorScope, TargetUsername, TargetUserId,
DvcIpAddr, DvcHostname, DvcDomain, DvcOs, DvcOsVersion
```

### _Im_FileEvent

```
// Schema:
TimeGenerated, EventType (FileCreated, FileModified, FileDeleted, FileRenamed, FileAccessed),
TargetFileName, TargetFilePath, TargetFileDirectory,
TargetFileMD5, TargetFileSHA1, TargetFileSHA256, TargetFileSize, TargetFileMimeType,
SrcFileName, SrcFilePath, SrcFileMD5, SrcFileSHA1, SrcFileSHA256,
ActorUsername, ActorUserId, ActingProcessName, ActingProcessId, ActingProcessCommandLine,
DvcIpAddr, DvcHostname
```

### _Im_WebSession

```
// Schema:
TimeGenerated, EventType, EventResult,
Url, UrlCategory, UrlOriginal, HttpVersion, HttpRequestMethod,
HttpStatusCode, HttpContentType, HttpContentFormat, HttpUserAgent, HttpRequestXff,
SrcIpAddr, SrcPortNumber, SrcHostname, SrcUsername,
DstIpAddr, DstPortNumber, DstHostname, DstNatIpAddr,
NetworkBytes, SrcBytes, DstBytes, NetworkDuration,
DvcAction, ThreatName, ThreatCategory, ThreatRiskLevel,
RuleName, Rule, RuleNumber
```

### _Im_RegistryEvent

```
// Schema:
TimeGenerated, EventType (RegistryValueSet, RegistryKeyCreated, RegistryValueDeleted, RegistryKeyDeleted),
RegistryKey, RegistryValue, RegistryValueData, RegistryValueType, RegistryPreviousKey, RegistryPreviousValue,
ActorUsername, ActorUserId, ActingProcessName, ActingProcessId, ActingProcessCommandLine,
DvcIpAddr, DvcHostname
```

### _Im_AuditEvent

```
// Schema:
TimeGenerated, EventType (Set, Create, Delete, Enable, Disable, Execute, Install, Other),
Operation, Object, ObjectType, OldValue, NewValue,
ActorUsername, ActorUserId, ActorUserType,
SrcIpAddr, SrcHostname, TargetAppName, TargetAppId, TargetAppType,
DvcIpAddr, DvcHostname
```
