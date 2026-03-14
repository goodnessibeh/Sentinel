# KQL Sentinel — Fortinet FortiGate Firewall Detections

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

> Comprehensive detection library for Fortinet FortiGate firewalls in Microsoft Sentinel. All logs ingested via CEF into `CommonSecurityLog`. All detections use `lookback` as the time variable.

---

## Table of Contents

### Traffic & Network Security
1. [Denied Traffic Spike — Possible Reconnaissance](#1-denied-traffic-spike--possible-reconnaissance)
2. [Outbound Traffic to Known Malicious Countries](#2-outbound-traffic-to-known-malicious-countries)
3. [Large Outbound Data Transfer — Exfiltration Indicator](#3-large-outbound-data-transfer--exfiltration-indicator)
4. [Traffic on Non-Standard Ports](#4-traffic-on-non-standard-ports)
5. [Internal Port Scan Detection](#5-internal-port-scan-detection)
6. [DMZ Lateral Movement — Unexpected Inter-Zone Traffic](#6-dmz-lateral-movement--unexpected-inter-zone-traffic)

### Intrusion Prevention (IPS)
7. [Critical/High IPS Signature Matches](#7-criticalhigh-ips-signature-matches)
8. [IPS Signature Allowed (Detect-Only Mode)](#8-ips-signature-allowed-detect-only-mode)
9. [Repeated IPS Hits from Same Source — Persistent Attacker](#9-repeated-ips-hits-from-same-source--persistent-attacker)

### Malware & Antivirus
10. [Antivirus Detection — Malware Blocked](#10-antivirus-detection--malware-blocked)
11. [Antivirus Detection — Malware Passed Through](#11-antivirus-detection--malware-passed-through)
12. [Outbreak Prevention Trigger](#12-outbreak-prevention-trigger)

### Web Filtering
13. [Access to Malicious/Phishing Websites](#13-access-to-maliciousphishing-websites)
14. [Proxy Avoidance or Anonymizer Usage](#14-proxy-avoidance-or-anonymizer-usage)
15. [Newly Registered/Observed Domain Access](#15-newly-registeredobserved-domain-access)

### Application Control
16. [High-Risk Application Detected (Tor, P2P, Tunneling)](#16-high-risk-application-detected-tor-p2p-tunneling)
17. [Unauthorized Remote Access Tool Usage](#17-unauthorized-remote-access-tool-usage)

### DNS Security
18. [DNS Botnet C&C Domain Blocked](#18-dns-botnet-cc-domain-blocked)
19. [DNS Query to Suspicious Category](#19-dns-query-to-suspicious-category)

### Data Loss Prevention
20. [DLP Policy Violation — Sensitive Data Exfiltration](#20-dlp-policy-violation--sensitive-data-exfiltration)

### VPN Security
21. [SSL VPN Brute Force — Multiple Failed Logins](#21-ssl-vpn-brute-force--multiple-failed-logins)
22. [VPN Tunnel Flapping — Repeated Up/Down](#22-vpn-tunnel-flapping--repeated-updown)
23. [SSL VPN Login from Unusual Country](#23-ssl-vpn-login-from-unusual-country)
24. [Concurrent VPN Sessions from Same User](#24-concurrent-vpn-sessions-from-same-user)

### Administrative Security
25. [Admin Login Failure — Brute Force](#25-admin-login-failure--brute-force)
26. [Admin Login from Unexpected Source IP](#26-admin-login-from-unexpected-source-ip)
27. [Configuration Change Detected](#27-configuration-change-detected)
28. [Firmware Upgrade Event](#28-firmware-upgrade-event)

### High Availability
29. [HA Failover Detected](#29-ha-failover-detected)
30. [HA Member State Change](#30-ha-member-state-change)

### Network Configuration Changes
31. [Firewall Policy Change Detected](#31-firewall-policy-change-detected)
32. [DHCP Snooping / IP Source Guard Configuration Change](#32-dhcp-snooping--ip-source-guard-configuration-change)
33. [Port Mirroring Configuration Change](#33-port-mirroring-configuration-change)
34. [NAT Policy Change Detected](#34-nat-policy-change-detected)
35. [Routing Configuration Change Detected](#35-routing-configuration-change-detected)
36. [SSL/TLS Inspection Configuration Change](#36-ssltls-inspection-configuration-change)

### DoS / Anomaly
37. [DoS Anomaly Detection Triggered](#37-dos-anomaly-detection-triggered)
38. [Session Table Saturation — Excessive Concurrent Sessions](#38-session-table-saturation--excessive-concurrent-sessions)

### Email Security
39. [Spam/Phishing Email Detected](#39-spamphishing-email-detected)

### SSL Inspection
40. [SSL Certificate Error — Potential MitM or Misconfiguration](#40-ssl-certificate-error--potential-mitm-or-misconfiguration)

---

## Helper: Parsing FortiGate AdditionalExtensions

Many FortiGate-specific fields are stored in `AdditionalExtensions`. Use this parsing pattern:

```kql
// Parse commonly needed FTNTFGT fields
let FortiGateLogs = CommonSecurityLog
| where DeviceVendor == "Fortinet"
| where DeviceProduct == "Fortigate"
| parse-kv AdditionalExtensions as (
    FTNTFGTsubtype: string,
    FTNTFGTlevel: string,
    FTNTFGTvd: string,
    FTNTFGTpolicyid: int,
    FTNTFGTpolicyname: string,
    FTNTFGTsrcintfrole: string,
    FTNTFGTdstintfrole: string,
    FTNTFGTapp: string,
    FTNTFGTappcat: string,
    FTNTFGTapprisk: string,
    FTNTFGTattack: string,
    FTNTFGTattackid: string,
    FTNTFGTprofile: string,
    FTNTFGTcrlevel: string,
    FTNTFGTcrscore: int,
    FTNTFGTsrccountry: string,
    FTNTFGTdstcountry: string,
    FTNTFGTduration: int,
    FTNTFGTseverity: string
) with (pair_delimiter=" ", kv_delimiter="=");
```

---

## Traffic & Network Security

### 1. Denied Traffic Spike — Possible Reconnaissance

Detects a sudden spike in denied (blocked) traffic from a single source IP within a short time window. A large volume of denied connections — especially to many distinct ports or hosts — is a strong indicator that an attacker or compromised host is performing network reconnaissance or port scanning. This is often the first phase of an attack chain before exploitation.

**Importance:** SOC analysts should investigate immediately because reconnaissance activity frequently precedes exploitation attempts, and early detection can stop an attack before it progresses.

**MITRE:** T1046 — Network Service Discovery
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
let lookback = 1h;
let threshold = 100;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Focus on denied/blocked connections — the reconnaissance signal
| where DeviceAction == "deny"
// Aggregate deny counts, distinct ports and targets per source IP in 5-minute bins
| summarize
    DenyCount = count(),
    DistinctPorts = dcount(DestinationPort),
    DistinctTargets = dcount(DestinationIP),
    TargetPorts = make_set(DestinationPort, 20),
    TargetIPs = make_set(DestinationIP, 10)
  by SourceIP, bin(TimeGenerated, 5m)
// Threshold filter: only alert when deny count exceeds the baseline
| where DenyCount > threshold
| project TimeGenerated, SourceIP, DenyCount, DistinctPorts, DistinctTargets, TargetPorts, TargetIPs
| order by DenyCount desc
```

**Tuning:** Adjust threshold for environment. Exclude known scanners (vulnerability assessment tools).

---

### 2. Outbound Traffic to Known Malicious Countries

Detects outbound connections from internal hosts to countries that are commonly associated with state-sponsored threat actors or sanctioned regimes. Legitimate business traffic to these regions is rare in most organizations, so any allowed connection warrants investigation. This can indicate compromised hosts communicating with command-and-control infrastructure or data being exfiltrated to adversary-controlled servers.

**Importance:** Connections to sanctioned or high-risk countries may indicate active C2 communication or sanctions violations that require immediate triage and potential blocking.

**MITRE:** T1071 — Application Layer Protocol
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
let lookback = 24h;
// Define countries with known state-sponsored threat actor activity
let SuspiciousCountries = dynamic(["North Korea", "Iran", "Syria", "Cuba"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections — these actually reached the destination
| where DeviceAction in ("accept", "close")
// Extract the destination country from FortiGate additional extensions
| extend DstCountry = extract("FTNTFGTdstcountry=([^;\\s]+)", 1, AdditionalExtensions)
// Filter to only traffic destined for suspicious countries
| where DstCountry in (SuspiciousCountries)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          ApplicationProtocol, DstCountry, SentBytes, ReceivedBytes,
          DestinationUserName
| order by TimeGenerated desc
```

---

### 3. Large Outbound Data Transfer — Exfiltration Indicator

Detects unusually large volumes of data being sent from internal hosts to external destinations. Attackers who have gained access to sensitive data will often stage and exfiltrate it in bulk transfers, sometimes over legitimate protocols to blend in. A single host sending hundreds of megabytes or more in a short window is a strong exfiltration signal, especially when the destination is unusual.

**Importance:** Large outbound transfers from LAN/DMZ hosts can indicate active data exfiltration, and rapid response can prevent the loss of sensitive intellectual property or customer data.

**MITRE:** T1048 — Exfiltration Over Alternative Protocol
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
let lookback = 1h;
// 500MB threshold — adjust based on normal business traffic patterns
let bytesThreshold = 500000000; // 500MB
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections
| where DeviceAction in ("accept", "close")
// Extract the source interface role to identify internal-origin traffic
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// Only consider traffic originating from internal (LAN) or DMZ networks
| where SrcIntfRole == "lan" or SrcIntfRole == "dmz"
// Aggregate total bytes sent per source IP in 1-hour windows
| summarize
    TotalBytesSent = sum(SentBytes),
    SessionCount = count(),
    DistinctDestinations = dcount(DestinationIP),
    Destinations = make_set(DestinationIP, 10),
    Ports = make_set(DestinationPort, 10)
  by SourceIP, bin(TimeGenerated, 1h)
// Only alert when the total bytes sent exceeds the exfiltration threshold
| where TotalBytesSent > bytesThreshold
| extend TotalMB = round(todouble(TotalBytesSent) / 1048576.0, 2)
| project TimeGenerated, SourceIP, TotalMB, SessionCount, DistinctDestinations, Destinations, Ports
| order by TotalMB desc
```

---

### 4. Traffic on Non-Standard Ports

Detects allowed outbound connections on non-standard ports (above 1024 and not in the common services list). Attackers frequently use non-standard ports to evade basic firewall rules and detection, tunneling C2 traffic or exfiltration channels over unusual port numbers. While some legitimate applications use high ports, repeated connections from LAN hosts to uncommon ports deserve scrutiny.

**Importance:** Non-standard port usage can indicate C2 channels, tunneling, or protocol abuse that bypasses traditional port-based security controls.

**MITRE:** T1571 — Non-Standard Port
**Severity:** Low

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
let lookback = 24h;
// Define well-known legitimate service ports to exclude
let StandardPorts = dynamic([20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 3389, 8080, 8443]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections
| where DeviceAction in ("accept", "close")
// Exclude all well-known standard ports
| where DestinationPort !in (StandardPorts)
// Focus on ephemeral/high ports that are more suspicious
| where DestinationPort > 1024
// Extract source interface role to focus on LAN-originated traffic
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// Only consider traffic originating from internal LAN hosts
| where SrcIntfRole == "lan"
// Aggregate connection counts per destination IP/port combination in 1-hour bins
| summarize
    ConnectionCount = count(),
    DistinctSources = dcount(SourceIP),
    Sources = make_set(SourceIP, 10)
  by DestinationIP, DestinationPort, ApplicationProtocol, bin(TimeGenerated, 1h)
// Threshold filter: only flag ports with significant activity
| where ConnectionCount > 20
| order by ConnectionCount desc
```

---

### 5. Internal Port Scan Detection

Detects internal hosts that are scanning many ports or many hosts within a short time window. Internal port scanning is a hallmark of lateral movement — an attacker who has compromised one host will scan the internal network to discover additional services, open shares, or vulnerable systems. This detection focuses on denied connections from LAN hosts, which indicates probing of services that are not permitted by policy.

**Importance:** Internal port scanning from a LAN host is a strong indicator of a compromised machine performing lateral movement reconnaissance, requiring immediate host isolation and investigation.

**MITRE:** T1046 — Network Service Discovery
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
let lookback = 15m;
// Thresholds for distinct ports or hosts contacted — either triggers the detection
let portThreshold = 25;
let hostThreshold = 10;
CommonSecurityLog
// Filter to a short 15-minute window for real-time scan detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Focus on denied connections — the scan "noise" hitting policy blocks
| where DeviceAction == "deny"
// Extract source interface role to identify internal hosts
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// Only consider traffic originating from internal LAN hosts
| where SrcIntfRole == "lan"
// Count distinct ports and hosts contacted per source IP
| summarize
    DistinctPorts = dcount(DestinationPort),
    DistinctHosts = dcount(DestinationIP),
    PortList = make_set(DestinationPort, 50),
    HostList = make_set(DestinationIP, 20)
  by SourceIP
// Alert if the source touched too many ports OR too many hosts
| where DistinctPorts > portThreshold or DistinctHosts > hostThreshold
| project SourceIP, DistinctPorts, DistinctHosts, PortList, HostList
```

---

### 6. DMZ Lateral Movement — Unexpected Inter-Zone Traffic

Detects allowed connections from DMZ hosts into the LAN or between DMZ hosts. In a properly segmented network, DMZ servers should only accept inbound connections from the internet and respond — they should never initiate connections into the LAN. DMZ-to-LAN or DMZ-to-DMZ lateral traffic is a critical indicator that a DMZ-hosted server has been compromised and the attacker is pivoting deeper into the network.

**Importance:** DMZ-to-LAN traffic violates fundamental network segmentation principles and strongly suggests an attacker has compromised a public-facing server and is pivoting internally.

**MITRE:** T1021 — Remote Services
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections — these are the dangerous ones
| where DeviceAction in ("accept", "close")
// Extract source and destination interface roles to determine traffic zones
| extend SrcIntfRole = extract("FTNTFGTsrcintfrole=([^;\\s]+)", 1, AdditionalExtensions)
| extend DstIntfRole = extract("FTNTFGTdstintfrole=([^;\\s]+)", 1, AdditionalExtensions)
// DMZ to LAN is unexpected — also flag DMZ-to-DMZ lateral movement between different hosts
| where (SrcIntfRole == "dmz" and DstIntfRole == "lan")
   or (SrcIntfRole == "dmz" and DstIntfRole == "dmz" and SourceIP != DestinationIP)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          ApplicationProtocol, DeviceInboundInterface, DeviceOutboundInterface,
          SrcIntfRole, DstIntfRole, SentBytes, ReceivedBytes
| order by TimeGenerated desc
```

---

## Intrusion Prevention (IPS)

### 7. Critical/High IPS Signature Matches

Detects IPS signature matches rated as critical or high severity by the FortiGate IPS engine. These signatures correspond to known exploitation techniques, vulnerability exploits, and attack payloads actively used in the wild. A critical or high IPS hit means the firewall identified traffic that matches a known attack pattern, regardless of whether it was blocked or allowed.

**Importance:** Critical and high IPS signatures represent active exploitation attempts against your network and must be triaged to confirm the attack was blocked and the target host is not compromised.

**MITRE:** Multiple (depends on signature)
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for IPS-related log entries
| where Activity has "utm:ips" or Activity has "ips"
// Extract IPS-specific fields from the additional extensions
| extend ThreatLevel = extract("FTNTFGTcrlevel=([^;\\s]+)", 1, AdditionalExtensions)
| extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
| extend AttackId = extract("FTNTFGTattackid=([^;\\s]+)", 1, AdditionalExtensions)
| extend ThreatScore = toint(extract("FTNTFGTcrscore=([^;\\s]+)", 1, AdditionalExtensions))
// Only surface critical and high severity detections
| where ThreatLevel in ("critical", "high")
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          AttackName, AttackId, ThreatLevel, ThreatScore,
          DeviceAction, ApplicationProtocol, Message
| order by ThreatScore desc
```

---

### 8. IPS Signature Allowed (Detect-Only Mode)

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

### 9. Repeated IPS Hits from Same Source — Persistent Attacker

Detects a single source IP triggering multiple IPS signatures within a short time window. An attacker running automated exploit tools or vulnerability scanners will generate many distinct IPS signatures in rapid succession as they cycle through different attack payloads. This pattern distinguishes a determined, active attacker from isolated false positives or one-off scanning noise.

**Importance:** Repeated IPS hits from a single source indicate an active, persistent attacker methodically probing your defenses, and the source IP should be immediately blocked at the perimeter.

**MITRE:** T1595 — Active Scanning
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
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

## Malware & Antivirus

### 10. Antivirus Detection — Malware Blocked

Detects files that the FortiGate antivirus engine identified as malware and successfully blocked from reaching the destination host. While the malware was stopped, the detection itself is valuable — it reveals which internal hosts are being targeted, what malware families are in play, and which delivery vectors (email, web, file transfer) attackers are using against your environment.

**Importance:** Even though the malware was blocked, the detection reveals active targeting of your environment and helps identify users or hosts that may need additional security awareness or endpoint hardening.

**MITRE:** T1204 — User Execution
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| File | Name | FileName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for antivirus-related log entries
| where Activity has "virus"
// Key filter: only show malware that was successfully blocked
| where DeviceAction == "blocked"
// Extract AV-specific fields from additional extensions
| extend VirusName = extract("FTNTFGTvirus=([^;]+)", 1, AdditionalExtensions)
| extend FileName = extract("FTNTFGTfilename=([^;]+)", 1, AdditionalExtensions)
| extend FileType = extract("FTNTFGTfiletype=([^;\\s]+)", 1, AdditionalExtensions)
| extend Profile = extract("FTNTFGTprofile=([^;\\s]+)", 1, AdditionalExtensions)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          VirusName, FileName, FileType, Profile,
          ApplicationProtocol, DestinationUserName, DeviceAction
| order by TimeGenerated desc
```

---

### 11. Antivirus Detection — Malware Passed Through

Detects files identified as malware by the FortiGate AV engine that were NOT blocked — the firewall detected the malware but allowed it to pass through to the destination host. This is an extremely dangerous condition, typically caused by an AV profile configured in "monitor" mode rather than "block" mode. The malware has reached the endpoint and may have executed.

**Importance:** This is a critical detection because malware reached its target unblocked — the destination host must be immediately isolated and investigated for active compromise.

**MITRE:** T1204 — User Execution
**Severity:** Critical

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| File | Name | FileName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for antivirus-related log entries
| where Activity has "virus"
// Key filter: only show malware that was NOT blocked — passthrough or detect-only
| where DeviceAction in ("passthrough", "detected")
// Extract the virus name and file name for investigation context
| extend VirusName = extract("FTNTFGTvirus=([^;]+)", 1, AdditionalExtensions)
| extend FileName = extract("FTNTFGTfilename=([^;]+)", 1, AdditionalExtensions)
| project TimeGenerated, SourceIP, DestinationIP, VirusName, FileName,
          DeviceAction, ApplicationProtocol, DestinationUserName, Message
```

**Tuning:** This detects malware that was NOT blocked. Investigate AV profile — action should be "block" not "monitor".

---

### 12. Outbreak Prevention Trigger

Detects FortiGate outbreak prevention events, which fire when FortiGuard identifies a zero-day or rapidly spreading malware sample that has not yet received a full AV signature. Outbreak prevention uses heuristic and behavioral signatures pushed by FortiGuard in real-time to block emerging threats before traditional AV signatures are available. These events indicate your environment is being targeted by very recent or zero-day malware.

**Importance:** Outbreak prevention triggers indicate zero-day or emerging malware targeting your environment before traditional signatures exist, requiring immediate threat intelligence correlation and host investigation.

**MITRE:** T1204 — User Execution
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for virus activity specifically related to outbreak prevention
| where Activity has "virus" and Activity has "outbreak"
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction,
          ApplicationProtocol, Message, DestinationUserName
```

---

## Web Filtering

### 13. Access to Malicious/Phishing Websites

Detects web requests to URLs categorized by FortiGuard as malicious, phishing, spyware, spam, or command-and-control. These category IDs correspond to known threat infrastructure that hosts malware downloads, credential harvesting pages, or C2 panels. Whether the request was blocked or allowed, the fact that an internal host attempted to reach such a site indicates either a compromised host following C2 instructions or a user falling for a phishing lure.

**Importance:** Access attempts to known malicious or phishing sites indicate either user compromise via social engineering or an already-infected host reaching out to threat infrastructure.

**MITRE:** T1566 — Phishing
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| URL | Url | RequestURL |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
// FortiGuard web filter category IDs for malicious content
let MaliciousCategories = dynamic([7, 8, 9, 26, 76, 90]); // Malware, Spyware, Phishing, Malicious, Spam URLs, C&C
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for web filter log entries
| where Activity has "webfilter"
// Extract the FortiGuard category ID and description
| extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
| extend CatDesc = coalesce(RequestContext, extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions))
// Only surface requests to categories associated with threats
| where Category in (MaliciousCategories)
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
          Category, CatDesc, DeviceAction, DestinationUserName,
          DestinationIP, Message
| order by TimeGenerated desc
```

---

### 14. Proxy Avoidance or Anonymizer Usage

Detects internal users accessing proxy avoidance services, anonymizers, dynamic DNS services, or cryptocurrency-related sites. These categories are commonly used by insiders attempting to bypass corporate security controls, hide their browsing activity, or access restricted content. Attackers also use these services to obscure C2 communications or exfiltrate data through anonymous channels.

**Importance:** Proxy avoidance and anonymizer usage signals deliberate attempts to bypass security controls, which may indicate insider threat activity or an attacker using evasion techniques.

**MITRE:** T1090 — Proxy
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
// FortiGuard category IDs for evasion-related sites
let EvasionCategories = dynamic([59, 71, 89]); // Proxy Avoidance, Dynamic DNS, Cryptocurrency
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for web filter log entries
| where Activity has "webfilter"
// Extract the FortiGuard category ID and description
| extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
| extend CatDesc = coalesce(RequestContext, extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions))
// Only surface requests to evasion-related categories
| where Category in (EvasionCategories)
// Aggregate access counts per source IP and category for pattern analysis
| summarize
    AccessCount = count(),
    Domains = make_set(DestinationHostName, 20),
    Users = make_set(DestinationUserName, 10)
  by SourceIP, CatDesc
| order by AccessCount desc
```

---

### 15. Newly Registered/Observed Domain Access

Detects internal hosts accessing domains that FortiGuard has classified as newly registered or newly observed. Attackers frequently register fresh domains for phishing campaigns, malware distribution, and C2 infrastructure because new domains have no reputation history and often bypass traditional blocklists. While some newly registered domains are legitimate, the overlap with attacker infrastructure is high enough to warrant monitoring.

**Importance:** Newly registered domains are disproportionately used for phishing and malware campaigns, and access to them should be correlated with other indicators to identify early-stage attacks.

**MITRE:** T1583.001 — Acquire Infrastructure: Domains
**Severity:** Low

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DestinationHostName |
| Account | Name | DestinationUserName |

```kql
let lookback = 24h;
// FortiGuard category IDs for newly observed/registered domains
let NewDomainCategories = dynamic([61, 62]); // Newly Observed Domain, Newly Registered Domain
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for web filter log entries
| where Activity has "webfilter"
// Extract and filter by new domain category IDs
| extend Category = toint(extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions))
| where Category in (NewDomainCategories)
| project TimeGenerated, SourceIP, DestinationHostName, RequestURL,
          DeviceAction, DestinationUserName, Category
// Aggregate by domain to identify the most frequently accessed new domains
| summarize
    AccessCount = count(),
    Users = make_set(DestinationUserName, 10)
  by DestinationHostName
| order by AccessCount desc
```

---

## Application Control

### 16. High-Risk Application Detected (Tor, P2P, Tunneling)

Detects the use of applications classified as critical or high risk by FortiGate's application control engine. This includes Tor (anonymous routing), peer-to-peer file sharing, tunneling tools, and other applications that can be used to bypass security controls or establish covert communication channels. These applications are rarely legitimate in enterprise environments and often indicate either malicious activity or serious policy violations.

**Importance:** High-risk applications like Tor and tunneling tools provide attackers with encrypted, anonymous channels that bypass all other security controls, making them a top-priority detection for SOC teams.

**MITRE:** T1090.003 — Proxy: Multi-hop Proxy (Tor)
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for application control log entries
| where Activity has "app-ctrl"
// Extract application control fields from additional extensions
| extend AppName = extract("FTNTFGTapp=([^;]+)", 1, AdditionalExtensions)
| extend AppCat = extract("FTNTFGTappcat=([^;]+)", 1, AdditionalExtensions)
| extend AppRisk = extract("FTNTFGTapprisk=([^;\\s]+)", 1, AdditionalExtensions)
// Only surface critical and high risk applications
| where AppRisk in ("critical", "high")
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          AppName, AppCat, AppRisk, DeviceAction,
          DestinationUserName, DestinationHostName
| order by TimeGenerated desc
```

---

### 17. Unauthorized Remote Access Tool Usage

Detects the use of commercial remote access tools such as TeamViewer, AnyDesk, LogMeIn, and similar software. While these tools have legitimate uses, they are also heavily abused by attackers for persistent remote access to compromised hosts. Many ransomware operators and initial access brokers use these tools to maintain access that blends in with normal IT activity. Unauthorized use should be flagged and validated against approved software lists.

**Importance:** Remote access tools are one of the most common persistence mechanisms used by ransomware operators, and unauthorized usage must be immediately validated against the approved software inventory.

**MITRE:** T1219 — Remote Access Software
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
// Define known remote access tool names to detect
let RemoteAccessApps = dynamic(["TeamViewer", "AnyDesk", "LogMeIn", "RustDesk",
    "Ammyy.Admin", "VNC", "Splashtop", "ConnectWise", "RemotePC",
    "GoToMyPC", "Dameware", "Radmin", "UltraVNC"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for application control log entries
| where Activity has "app-ctrl"
// Extract the detected application name
| extend AppName = extract("FTNTFGTapp=([^;]+)", 1, AdditionalExtensions)
// Match against the list of known remote access tools
| where AppName has_any (RemoteAccessApps)
| project TimeGenerated, SourceIP, DestinationIP, AppName, DeviceAction,
          DestinationUserName, DestinationHostName
```

---

## DNS Security

### 18. DNS Botnet C&C Domain Blocked

Detects DNS queries that the FortiGate DNS filter identified as botnet command-and-control domains. When a host queries a known C2 domain, it strongly indicates that the host is infected with malware and attempting to reach its C2 server for instructions, payload delivery, or data exfiltration. Even though the DNS query was blocked, the infected host still needs to be investigated and remediated.

**Importance:** DNS queries to known botnet C2 domains are a near-certain indicator of active malware infection on the querying host, requiring immediate endpoint isolation and forensic investigation.

**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | QueriedDomain |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for DNS-related log entries
| where Activity has "dns"
// Key filter: identify botnet and C&C related DNS blocks
| where Message has "botnet" or Message has "C&C"
// Extract the queried domain and associated botnet IP for context
| extend QueriedDomain = DestinationHostName
| extend BotnetIP = extract("FTNTFGTbotnetip=([^;\\s]+)", 1, AdditionalExtensions)
| project TimeGenerated, SourceIP, QueriedDomain, BotnetIP,
          DeviceAction, Message
| order by TimeGenerated desc
```

---

### 19. DNS Query to Suspicious Category

Detects DNS queries that were blocked or redirected by FortiGate's DNS filter due to the queried domain falling into a suspicious category. This covers a broader range of threats than just botnet C2, including domains associated with malware hosting, phishing, and other malicious activities. The aggregation by source IP and category helps identify hosts that are repeatedly attempting to resolve suspicious domains.

**Importance:** Repeated blocked DNS queries to suspicious categories from a single host suggest persistent malware infection or ongoing phishing compromise that the endpoint security may have missed.

**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for DNS-related log entries
| where Activity has "dns"
// Key filter: only look at DNS queries that were blocked or redirected
| where DeviceAction in ("block", "redirect")
// Extract category information for context
| extend Category = extract("FTNTFGTcat=(\\d+)", 1, AdditionalExtensions)
| extend CatDesc = extract("FTNTFGTcatdesc=([^;]+)", 1, AdditionalExtensions)
// Aggregate blocked DNS queries per source IP and category for pattern detection
| summarize
    BlockCount = count(),
    Domains = make_set(DestinationHostName, 20)
  by SourceIP, CatDesc, DeviceAction
| order by BlockCount desc
```

---

## Data Loss Prevention

### 20. DLP Policy Violation — Sensitive Data Exfiltration

Detects FortiGate DLP policy violations where sensitive data patterns (credit card numbers, SSNs, proprietary document fingerprints, etc.) were identified in outbound traffic. DLP events indicate that sensitive information is leaving the organization, whether intentionally by a malicious insider or accidentally by an unaware employee. The severity and filter type help prioritize which violations need immediate attention.

**Importance:** DLP violations represent potential exposure of regulated or proprietary data and may trigger compliance notification requirements under GDPR, PCI-DSS, HIPAA, or similar regulations.

**MITRE:** T1567 — Exfiltration Over Web Service
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| URL | Url | RequestURL |
| File | Name | FileName |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for DLP-related log entries
| where Activity has "dlp"
// Extract DLP-specific fields from additional extensions
| extend DLPSeverity = extract("FTNTFGTseverity=([^;\\s]+)", 1, AdditionalExtensions)
| extend FilterType = extract("FTNTFGTfiltertype=([^;\\s]+)", 1, AdditionalExtensions)
| extend Profile = extract("FTNTFGTprofile=([^;\\s]+)", 1, AdditionalExtensions)
| extend FileName = extract("FTNTFGTfilename=([^;]+)", 1, AdditionalExtensions)
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName,
          RequestURL, FileName, FilterType, DLPSeverity, Profile,
          DeviceAction, DestinationUserName, ApplicationProtocol
| order by TimeGenerated desc
```

---

## VPN Security

### 21. SSL VPN Brute Force — Multiple Failed Logins

Detects multiple failed SSL VPN login attempts from a single source IP within a short time window. Brute force attacks against VPN portals are extremely common and represent one of the top initial access vectors for ransomware operators. A high number of failures — especially against multiple user accounts — indicates an active credential stuffing or password spraying attack.

**Importance:** VPN brute force attacks are a leading initial access vector for ransomware, and detecting them early allows blocking the attacker IP before valid credentials are found.

**MITRE:** T1110 — Brute Force
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Account | Name | DestinationUserName |

```kql
let lookback = 1h;
let threshold = 5;
CommonSecurityLog
// Filter to the last 1 hour for near-real-time brute force detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: only look at failed SSL VPN login attempts
| where DeviceAction == "ssl-login-fail"
// Aggregate failure counts per source IP to identify brute force patterns
| summarize
    FailureCount = count(),
    DistinctUsers = dcount(DestinationUserName),
    Users = make_set(DestinationUserName, 10),
    Reasons = make_set(Message, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by SourceIP
// Threshold filter: only alert when failures exceed the brute force threshold
| where FailureCount >= threshold
| project SourceIP, FailureCount, DistinctUsers, Users, Reasons, FirstAttempt, LastAttempt
| order by FailureCount desc
```

---

### 22. VPN Tunnel Flapping — Repeated Up/Down

Detects VPN tunnels that are repeatedly going up and down within a short time period. Tunnel flapping can indicate a denial-of-service attack targeting the VPN infrastructure, network instability caused by an attacker, or an adversary attempting to disrupt VPN connectivity to force users onto less secure channels. It can also signal a compromised tunnel endpoint.

**Importance:** VPN tunnel flapping disrupts business connectivity and may indicate a targeted DoS attack or an attacker manipulating network infrastructure to force traffic through attacker-controlled paths.

**MITRE:** T1498 — Network Denial of Service
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
let lookback = 1h;
let flapThreshold = 5;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: look for tunnel state change events
| where DeviceAction in ("tunnel-up", "tunnel-down")
// Extract tunnel name and type for identification
| extend VPNTunnel = extract("FTNTFGTvpntunnel=([^;\\s]+)", 1, AdditionalExtensions)
| extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
// Aggregate state changes per tunnel — count ups and downs separately
| summarize
    StateChanges = count(),
    UpCount = countif(DeviceAction == "tunnel-up"),
    DownCount = countif(DeviceAction == "tunnel-down"),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
  by VPNTunnel, TunnelType, SourceIP
// Threshold filter: only flag tunnels with excessive state changes (flapping)
| where StateChanges >= flapThreshold
| project VPNTunnel, TunnelType, SourceIP, StateChanges, UpCount, DownCount, FirstEvent, LastEvent
```

---

### 23. SSL VPN Login from Unusual Country

Detects successful SSL VPN connections originating from countries not in the organization's allowed list. An attacker who has obtained valid VPN credentials (through phishing, credential dumps, or brute force) will often connect from infrastructure in foreign countries. This is one of the most reliable indicators of compromised credentials being used by an external threat actor.

**Importance:** VPN logins from unexpected countries are a strong indicator of stolen credentials being used by an attacker, especially when the user has no travel history to that region.

**MITRE:** T1078 — Valid Accounts
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Account | Name | DestinationUserName |

```kql
let lookback = 24h;
// Define the countries where legitimate VPN logins are expected
let AllowedCountries = dynamic(["United States", "Canada", "United Kingdom"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: only look at successful VPN tunnel establishments
| where DeviceAction == "tunnel-up"
// Extract tunnel type to focus on SSL VPN connections
| extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
| where TunnelType has "ssl"
// Extract the source country from additional extensions
| extend SrcCountry = extract("FTNTFGTsrccountry=([^;\\s]+)", 1, AdditionalExtensions)
// Filter out allowed countries and empty/reserved values
| where SrcCountry !in (AllowedCountries) and isnotempty(SrcCountry) and SrcCountry != "Reserved"
| project TimeGenerated, SourceIP, DestinationUserName, SrcCountry,
          TunnelType, DeviceAction
```

**Tuning:** Customize `AllowedCountries` for your organization's geographic footprint.

---

### 24. Concurrent VPN Sessions from Same User

Detects a single user account connected to the SSL VPN from multiple distinct source IP addresses simultaneously. Under normal circumstances, a user connects from one location at a time. Multiple concurrent sessions from different IPs suggest that the user's credentials have been compromised and are being used by an attacker at the same time as the legitimate user, or the credentials have been shared or sold.

**Importance:** Concurrent VPN sessions from different IPs for the same user is a high-confidence indicator of credential compromise, as legitimate users rarely connect from multiple locations simultaneously.

**MITRE:** T1078 — Valid Accounts
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 1h;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: only look at successful VPN tunnel establishments
| where DeviceAction == "tunnel-up"
// Extract tunnel type to focus on SSL VPN connections
| extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
| where TunnelType has "ssl"
// Aggregate sessions per user — count distinct source IPs and countries
| summarize
    SessionCount = count(),
    DistinctIPs = dcount(SourceIP),
    IPList = make_set(SourceIP, 10),
    Countries = make_set(extract("FTNTFGTsrccountry=([^;\\s]+)", 1, AdditionalExtensions), 5)
  by DestinationUserName
// Detection logic: flag users with sessions from more than one distinct IP
| where DistinctIPs > 1
| project DestinationUserName, SessionCount, DistinctIPs, IPList, Countries
```

---

## Administrative Security

### 25. Admin Login Failure — Brute Force

Detects multiple failed administrative login attempts to FortiGate management interfaces from a single source IP. Firewall admin access is one of the highest-value targets for attackers — gaining admin access to the firewall allows complete network control, policy manipulation, and the ability to disable all security features. Brute force attacks against admin interfaces are a critical threat that can lead to total network compromise.

**Importance:** Firewall admin brute force attacks target the single most critical security control in your network, and successful compromise would give an attacker complete control over all network security policies.

**MITRE:** T1110 — Brute Force
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |

```kql
let lookback = 30m;
let threshold = 5;
CommonSecurityLog
// Filter to a short 30-minute window for rapid brute force detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries (admin events)
| where Activity has "system"
// Key filter: FortiGate event ID for admin login failure
| where DeviceEventClassID in ("32002", "0100032002")
// Aggregate login failures per source IP and target device
| summarize
    FailureCount = count(),
    Users = make_set(DestinationUserName, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by SourceIP, DeviceName
// Threshold filter: only alert when failure count indicates brute force
| where FailureCount >= threshold
| project SourceIP, DeviceName, FailureCount, Users, FirstAttempt, LastAttempt
```

---

### 26. Admin Login from Unexpected Source IP

Detects successful administrative logins to FortiGate management interfaces from IP addresses outside the expected management network ranges. Admin access should be restricted to specific management subnets or jump hosts. A successful admin login from an unexpected IP could indicate a compromised credential being used from an attacker-controlled host, or a misconfigured access policy that exposes the management plane.

**Importance:** Admin logins from outside trusted management networks may indicate credential theft or unauthorized access that could lead to complete security control takeover.

**MITRE:** T1078 — Valid Accounts
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |

```kql
let lookback = 24h;
// Define trusted management network ranges — replace with your actual CIDRs
let AllowedAdminSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries (admin events)
| where Activity has "system"
// Key filter: FortiGate event ID for successful admin login
| where DeviceEventClassID in ("32001", "0100032001")
// Admin login success from outside expected management network ranges
| where not(ipv4_is_in_any_range(SourceIP, AllowedAdminSubnets))
| project TimeGenerated, SourceIP, DestinationUserName, DeviceName, Message
```

**Tuning:** Replace `AllowedAdminSubnets` with your actual management network CIDRs.

---

### 27. Configuration Change Detected

Detects any configuration change event on FortiGate devices. Every configuration change should be tracked for audit purposes, and unexpected changes — especially outside maintenance windows or by unfamiliar admin accounts — can indicate an attacker who has gained admin access and is modifying security policies to facilitate their attack. Configuration change monitoring is also a compliance requirement under most security frameworks.

**Importance:** Unauthorized configuration changes can silently disable security controls, open backdoor access, or weaken policies, making change tracking essential for both security and compliance.

**MITRE:** T1562 — Impair Defenses
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: FortiGate event ID for configuration changes
| where DeviceEventClassID in ("32102", "0100032102")
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

### 28. Firmware Upgrade Event

Detects firmware upgrade or downgrade events on FortiGate devices. While firmware updates are routine, they should only occur during planned maintenance windows by authorized personnel. An unexpected firmware change could indicate a supply chain compromise, an attacker attempting to install a backdoored firmware, or a downgrade attack to reintroduce known vulnerabilities. Firmware downgrades are especially suspicious and should always be investigated.

**Importance:** Unexpected firmware changes — especially downgrades — can reintroduce known vulnerabilities or indicate a supply chain compromise, and must be validated against the change management record.

**MITRE:** T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain
**Severity:** Informational

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 7d;
CommonSecurityLog
// Filter to the last 7 days — firmware upgrades are infrequent events
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: look for firmware-related messages including upgrades and downgrades
| where Message has "firmware" and Message has_any ("upgraded", "upgrade", "downgrade")
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP,
          Message, DeviceVersion
```

---

## High Availability

### 29. HA Failover Detected

Detects high availability failover events where the standby FortiGate unit has taken over as the active unit. HA failovers can be triggered by hardware failure, software crashes, or deliberate attacks targeting the primary unit. While failovers ensure continued operation, they should be investigated to determine the root cause — especially if they occur outside of maintenance windows or are accompanied by other suspicious events.

**Importance:** HA failovers indicate the primary firewall experienced a critical failure, which could be caused by a DoS attack, exploit, or hardware issue that requires immediate root cause analysis.

**MITRE:** T1498 — Network Denial of Service
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for HA-related log entries
| where Activity has "ha"
// Key filter: FortiGate event IDs for HA failover events, plus keyword fallback
| where DeviceEventClassID in ("35013", "35016", "0108035013", "0108035016")
    or Message has "failover"
| project TimeGenerated, DeviceName, DeviceExternalID, Message
| order by TimeGenerated desc
```

---

### 30. HA Member State Change

Detects changes in the state of HA cluster members, such as a member going from active to standby, becoming out of sync, or losing heartbeat connectivity. These events can indicate hardware degradation, network issues between HA peers, or an attacker disrupting the HA cluster to create a single point of failure. Monitoring HA member state ensures that the firewall cluster remains resilient and properly synchronized.

**Importance:** HA member state changes can leave your network running on a single firewall without redundancy, creating a critical single point of failure that must be resolved before a second failure occurs.

**MITRE:** N/A — Operational Monitoring
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for HA-related log entries
| where Activity has "ha"
// Key filter: FortiGate event IDs for HA member state changes, plus keyword fallback
| where DeviceEventClassID in ("37892", "0105037892")
    or Message has "member state"
| project TimeGenerated, DeviceName, DeviceExternalID, Message
| order by TimeGenerated desc
```

---

## Network Configuration Changes

### 31. Firewall Policy Change Detected

Detects modifications to firewall policies including security policy changes, address object changes, service group modifications, and VIP or IP pool updates. Firewall policy changes are among the most security-sensitive configuration modifications — an attacker with admin access will modify policies to allow their traffic, disable inspection, or create backdoor access rules. All policy changes should be correlated against authorized change requests.

**Importance:** Unauthorized firewall policy changes can silently open network access paths for attackers, disable security inspection, or create persistent backdoor rules that survive other remediation efforts.

**MITRE:** T1562.004 — Impair Defenses: Disable or Modify System Firewall
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Filter for configuration change event IDs
| where DeviceEventClassID in ("32102", "0100032102")
// Key filter: narrow to policy-related configuration changes
| where Message has_any ("policy", "firewall policy", "security policy",
    "address", "address-group", "service", "service-group",
    "schedule", "vip", "ip-pool", "central-nat")
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

### 32. DHCP Snooping / IP Source Guard Configuration Change

Detects changes to DHCP snooping, IP source guard, ARP inspection, or DHCP server/relay configurations. These Layer 2/3 security features prevent IP spoofing, DHCP starvation, and ARP poisoning attacks. Disabling or weakening these features could allow an attacker to perform man-in-the-middle attacks, hijack IP addresses, or disrupt network connectivity. Changes to these settings are security-critical and should be closely monitored.

**Importance:** Weakening DHCP snooping or ARP inspection opens the door to man-in-the-middle and IP spoofing attacks that can compromise entire network segments without generating traditional alerts.

**MITRE:** T1562 — Impair Defenses
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match DHCP snooping, IP source guard, ARP inspection, and related config changes
| where Message has_any (
    "dhcp-snooping", "dhcp snooping",
    "ip-source-guard", "ip source guard",
    "arp-inspection", "arp inspection",
    "trusted", "untrusted",
    "dhcp server", "dhcp relay"
  )
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

### 33. Port Mirroring Configuration Change

Detects changes to packet capture, traffic mirroring, or sniffer configurations on FortiGate devices. An attacker who has gained admin access may configure port mirroring to capture sensitive traffic (credentials, session tokens, confidential data) for exfiltration. Sniffer policies and diagnostic sniffer commands can also be used to passively intercept traffic without modifying firewall rules, making this a stealthy attack technique.

**Importance:** Unauthorized port mirroring or packet capture configuration enables an attacker to passively intercept all network traffic including credentials and sensitive data without triggering other security alerts.

**MITRE:** T1040 — Network Sniffing
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match sniffer, packet capture, mirroring, and flow export config changes
| where Message has_any (
    "sniffer", "packet-capture", "mirror",
    "port-mirror", "traffic-mirror",
    "sflow", "netflow", "nflow",
    "diag sniff", "diagnose sniffer"
  )
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

**Tuning:** Port mirroring on FortiGate is done via sniffer policies or `diagnose sniffer` CLI commands.

---

### 34. NAT Policy Change Detected

Detects changes to NAT configurations including SNAT, DNAT, virtual IPs, IP pools, and central NAT policies. NAT policy changes can expose internal services to the internet, redirect traffic to attacker-controlled hosts, or create hidden access paths that bypass firewall inspection. An attacker modifying NAT rules can effectively create a backdoor that maps an external IP directly to an internal resource.

**Importance:** NAT policy modifications can silently expose internal services to the internet or redirect traffic to attacker-controlled infrastructure, creating persistent backdoor access.

**MITRE:** T1562 — Impair Defenses
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match NAT-related configuration changes
| where Message has_any (
    "central-nat", "nat", "snat", "dnat",
    "virtual-ip", "vip", "ip-pool",
    "nat-policy", "nat46", "nat64"
  )
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

### 35. Routing Configuration Change Detected

Detects changes to routing configurations including static routes, dynamic routing protocols (BGP, OSPF, RIP, IS-IS), policy routes, route maps, prefix lists, and SD-WAN settings. Routing changes can redirect traffic through attacker-controlled paths, create traffic black holes for denial of service, or enable man-in-the-middle attacks by diverting traffic through interception points. Routing manipulation is a sophisticated attack technique used by advanced threat actors.

**Importance:** Routing manipulation can silently redirect all network traffic through attacker-controlled infrastructure for interception, making it one of the most dangerous configuration changes an attacker can make.

**MITRE:** T1557 — Adversary-in-the-Middle
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Key filter: match routing-related system events or dedicated router log entries
| where (Activity has "system" and Message has_any (
    "static-route", "route", "router bgp", "router ospf",
    "router rip", "router isis", "router multicast",
    "policy-route", "route-map", "prefix-list",
    "sd-wan", "sdwan"
  ))
  or Activity has "router"
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP,
          Message, Activity
| order by TimeGenerated desc
```

---

### 36. SSL/TLS Inspection Configuration Change

Detects changes to SSL/TLS inspection profiles, certificate configurations, and SSL exemption rules. SSL inspection is critical for detecting threats hidden in encrypted traffic. An attacker who disables or weakens SSL inspection effectively creates a blind spot where malware, C2 communications, and data exfiltration can occur undetected. Adding SSL exemptions for specific sites is also a technique attackers use to whitelist their C2 domains from inspection.

**Importance:** Weakening SSL inspection creates encrypted blind spots where malware, C2, and exfiltration can operate undetected, and unauthorized exemptions may whitelist attacker infrastructure.

**MITRE:** T1562 — Impair Defenses
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries
| where Activity has "system"
// Key filter: match SSL/TLS inspection and certificate-related configuration changes
| where Message has_any (
    "ssl-ssh-profile", "ssl inspection", "deep-inspection",
    "certificate-inspection", "ssl-exempt", "ssl exempt",
    "certificate", "ca-cert", "local-cert"
  )
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP, Message
| order by TimeGenerated desc
```

---

## DoS / Anomaly

### 37. DoS Anomaly Detection Triggered

Detects FortiGate DoS anomaly detection events, which fire when traffic patterns match known denial-of-service signatures such as SYN floods, UDP floods, ICMP floods, and other volumetric or protocol-based attacks. These events indicate that someone is actively attempting to overwhelm your network resources or specific services. The aggregation by source IP helps identify the top attacking hosts and their targets.

**Importance:** DoS anomaly events indicate active denial-of-service attacks that can disrupt critical services and may also serve as cover for simultaneous intrusion attempts occurring while the SOC is distracted.

**MITRE:** T1498 — Network Denial of Service
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Host | HostName | DeviceName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for anomaly detection log entries
| where Activity has "anomaly"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          DeviceAction, Message, DeviceName
// Aggregate anomaly events per source IP and device to identify top attackers
| summarize
    AnomalyCount = count(),
    Targets = make_set(DestinationIP, 10),
    Ports = make_set(DestinationPort, 10)
  by SourceIP, DeviceName
| order by AnomalyCount desc
```

---

### 38. Session Table Saturation — Excessive Concurrent Sessions

Detects a single source IP creating an abnormally large number of concurrent sessions, which can exhaust the FortiGate's session table and cause denial of service for all network users. Session table saturation is a resource exhaustion attack that can be more effective than bandwidth-based DoS because it targets the firewall's finite connection tracking capacity. This can also indicate a compromised host running botnet or cryptomining software that opens thousands of connections.

**Importance:** Session table exhaustion can cause the firewall to drop legitimate traffic for all users, and a single compromised host generating thousands of sessions can create a network-wide outage.

**MITRE:** T1499 — Endpoint Denial of Service
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
let lookback = 1h;
// Session threshold — adjust based on your firewall's session table capacity
let sessionThreshold = 5000;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Key filter: only count accepted/started sessions (active connections)
| where DeviceAction in ("accept", "start")
// Aggregate active sessions per source IP in 5-minute bins
| summarize
    ActiveSessions = count(),
    DistinctDests = dcount(DestinationIP),
    DistinctPorts = dcount(DestinationPort)
  by SourceIP, bin(TimeGenerated, 5m)
// Threshold filter: only flag sources exceeding the session threshold
| where ActiveSessions > sessionThreshold
| project TimeGenerated, SourceIP, ActiveSessions, DistinctDests, DistinctPorts
```

---

## Email Security

### 39. Spam/Phishing Email Detected

Detects spam and phishing emails identified by FortiGate's email filter engine. Phishing remains the most common initial access vector for cyberattacks, and tracking email filter events helps identify which users are being targeted, what types of phishing campaigns are active, and whether any malicious emails bypassed filtering. Even blocked phishing attempts provide valuable threat intelligence about current campaigns targeting your organization.

**Importance:** Phishing is the top initial access vector for most cyberattacks, and email filter detections reveal which users and campaigns are actively targeting your organization for prioritized security awareness.

**MITRE:** T1566 — Phishing
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for email filter log entries
| where Activity has "emailfilter"
| project TimeGenerated, SourceIP, DestinationIP,
          DeviceAction, Message, ApplicationProtocol,
          DestinationUserName
| order by TimeGenerated desc
```

---

## SSL Inspection

### 40. SSL Certificate Error — Potential MitM or Misconfiguration

Detects SSL certificate errors encountered during FortiGate's SSL inspection, including self-signed certificates, expired certificates, untrusted certificate authorities, and other certificate validation failures. Certificate errors can indicate a man-in-the-middle attack where an attacker is intercepting encrypted traffic with a fraudulent certificate. They can also indicate misconfigured servers or applications, but in either case, the encrypted connection cannot be trusted and the traffic may be compromised.

**Importance:** SSL certificate errors can indicate an active man-in-the-middle attack intercepting encrypted traffic, and even when caused by misconfiguration, they leave users vulnerable to interception.

**MITRE:** T1557 — Adversary-in-the-Middle
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Host | HostName | DestinationHostName |

```kql
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for SSL-related log entries
| where Activity has "ssl"
// Key filter: match certificate error conditions indicating trust failures
| where Message has_any ("self-signed", "expired", "untrusted", "certificate", "cert-error")
// Extract certificate details for investigation context
| extend CertCN = extract("FTNTFGTcertcn=([^;]+)", 1, AdditionalExtensions)
| extend CertError = extract("FTNTFGTcerterror=([^;\\s]+)", 1, AdditionalExtensions)
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName,
          CertCN, CertError, DeviceAction, Message
| order by TimeGenerated desc
```
