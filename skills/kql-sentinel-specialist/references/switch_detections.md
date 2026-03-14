---
name: kql-sentinel-switch-detections
description: Extreme Networks switch detection rules for Microsoft Sentinel. 45 detections covering port security (MAC lock, learning limits), DHCP snooping, Dynamic ARP Inspection, STP topology changes, link flap monitoring, loop/storm protection, 802.1X and RADIUS/TACACS+ authentication, configuration change auditing (DHCP snooping, port mirroring, ACL, VLAN, STP, routing), LLDP/CDP neighbor discovery, OSPF/BGP routing security, system health, DoS protection, and VOSS Fabric Connect. All queries target the Syslog table via ExtremeXOS EMS messages.
author: Goodness Caleb Ibeh
linkedin: https://linkedin.com/in/caleb-ibeh
---

# KQL Sentinel — Extreme Networks Switch Detections

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

> Comprehensive detection library for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS) in Microsoft Sentinel. All logs ingested via Syslog into the `Syslog` table. All detections use `lookback` as the time variable.

---

## Table of Contents

### Port Security
1. [MAC Lock Violation — Unauthorized Device](#1-mac-lock-violation--unauthorized-device)
2. [MAC Learning Limit Exceeded](#2-mac-learning-limit-exceeded)
3. [MAC Address Movement — Potential ARP Spoofing](#3-mac-address-movement--potential-arp-spoofing)
4. [Port Security Violation Surge](#4-port-security-violation-surge)

### DHCP Security
5. [DHCP Snooping Violation — Rogue DHCP Server](#5-dhcp-snooping-violation--rogue-dhcp-server)
6. [DHCP Snooping Port/MAC Blocked](#6-dhcp-snooping-portmac-blocked)
7. [IP Security Packet Drop](#7-ip-security-packet-drop)

### ARP Security
8. [Dynamic ARP Inspection Violation](#8-dynamic-arp-inspection-violation)
9. [Duplicate IP Address Detected (DAD)](#9-duplicate-ip-address-detected-dad)

### Spanning Tree Protocol
10. [STP Topology Change Detected](#10-stp-topology-change-detected)
11. [STP Root Bridge Change — Potential Attack](#11-stp-root-bridge-change--potential-attack)
12. [Excessive STP Topology Changes — Network Instability](#12-excessive-stp-topology-changes--network-instability)

### Link & Port Monitoring
13. [Port Link Flap Detection](#13-port-link-flap-detection)
14. [Excessive Port State Changes — Anomaly](#14-excessive-port-state-changes--anomaly)
15. [Mass Port Down Event — Potential Cable/Switch Failure](#15-mass-port-down-event--potential-cableswitch-failure)

### Loop & Storm Protection
16. [Loop Detected — ELRP Alert](#16-loop-detected--elrp-alert)
17. [Storm Control Triggered](#17-storm-control-triggered)
18. [EAPS Ring State Change](#18-eaps-ring-state-change)

### Authentication & Access Control
19. [Switch Login Brute Force](#19-switch-login-brute-force)
20. [SSH Connection Rejected/Denied](#20-ssh-connection-rejecteddenied)
21. [Successful Login from Unexpected Source](#21-successful-login-from-unexpected-source)
22. [802.1X Authentication Failure](#22-8021x-authentication-failure)
23. [RADIUS/TACACS+ Authentication Events](#23-radiustacacs-authentication-events)
24. [Admin Session Activity Monitoring](#24-admin-session-activity-monitoring)

### Configuration Changes
25. [Configuration Saved or Loaded](#25-configuration-saved-or-loaded)
26. [CLI Command Audit — Remote Commands](#26-cli-command-audit--remote-commands)
27. [DHCP Snooping Configuration Change](#27-dhcp-snooping-configuration-change)
28. [Port Mirroring Configuration Change](#28-port-mirroring-configuration-change)
29. [ACL/Policy Configuration Change](#29-aclpolicy-configuration-change)
30. [VLAN Configuration Change](#30-vlan-configuration-change)
31. [STP Configuration Change](#31-stp-configuration-change)
32. [Routing Configuration Change](#32-routing-configuration-change)

### Neighbor Discovery
33. [LLDP Neighbor Disappeared — Link Loss](#33-lldp-neighbor-disappeared--link-loss)
34. [New LLDP Neighbor — Rogue Device Detection](#34-new-lldp-neighbor--rogue-device-detection)
35. [CDP Neighbor Timeout](#35-cdp-neighbor-timeout)

### Routing Protocol Security
36. [OSPF Neighbor State Change](#36-ospf-neighbor-state-change)
37. [BGP Peer Event — Session Reset](#37-bgp-peer-event--session-reset)
38. [Routing Instability — Multiple Protocol Flaps](#38-routing-instability--multiple-protocol-flaps)

### Hardware & System Health
39. [Process Crash Detected](#39-process-crash-detected)
40. [Stack/Chassis Failover Event](#40-stackchassis-failover-event)
41. [PoE Power Fault or Denial](#41-poe-power-fault-or-denial)
42. [Critical/Error System Events](#42-criticalerror-system-events)

### DoS Protection
43. [DoS Protection Alert Triggered](#43-dos-protection-alert-triggered)

### VOSS-Specific
44. [VOSS CLI Audit Log Monitoring](#44-voss-cli-audit-log-monitoring)
45. [VOSS IS-IS/Fabric Connect Adjacency Change](#45-voss-is-isfabric-connect-adjacency-change)

---

## Helper: Parsing EXOS EMS Messages

All ExtremeXOS log messages follow the `<Severity:Component.Subcomponent.Condition>` format. Use this base parsing pattern:

```kql
// Standard EXOS message parser
let ParseEXOS = (T: (SyslogMessage: string)) {
    T
    | parse SyslogMessage with * "<" SeverityAbbr ":" FullComponent ">" MessageBody
    | extend ComponentParts = split(FullComponent, ".")
    | extend TopComponent = tostring(ComponentParts[0])
    | extend SubComponent = iff(array_length(ComponentParts) > 1, tostring(ComponentParts[1]), "")
    | extend Condition = iff(array_length(ComponentParts) > 2, strcat_array(array_slice(ComponentParts, 2, -1), "."), "")
    | extend SeverityLevel = case(
        SeverityAbbr == "Crit", "Critical",
        SeverityAbbr == "Erro", "Error",
        SeverityAbbr == "Warn", "Warning",
        SeverityAbbr == "Noti", "Notice",
        SeverityAbbr == "Info", "Informational",
        SeverityAbbr in ("Summ", "Verb", "Data"), "Debug",
        "Unknown"
      )
};
```

### Base filter for Extreme switches:

```kql
Syslog
| where Facility == "local7"  // Default EXOS facility — adjust if configured differently
```

---

## Port Security

### 1. MAC Lock Violation — Unauthorized Device

**Description:** Detects when a device with an unauthorized MAC address attempts to connect to a MAC-locked port on the switch. MAC locking restricts which devices can communicate through specific ports, so a violation indicates a device that is not in the approved list is attempting network access. This is a common indicator of unauthorized device connections or potential network intrusion attempts.

**Importance:** SOC analysts should investigate immediately as this may indicate an attacker plugging a rogue device into a secured network port to gain unauthorized access.

**Category:** Port Security

**EXOS EMS:** `FDB.MacLocking`

**MITRE:** T1200 — Hardware Additions

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours of syslog data for MAC lock violations
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs via facility
| where Facility == "local7"
// Key filter: match FDB MAC locking violation EMS messages
| where SyslogMessage has "FDB.MacLocking"
// Parse out the severity, component, and port from the structured EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" * "Port " Port " " Rest
// Extract the offending MAC address using regex
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Severity, Port, MACAddress, SyslogMessage
| order by TimeGenerated desc
```

---

### 2. MAC Learning Limit Exceeded

**Description:** Detects when a switch port exceeds its configured MAC address learning limit, which restricts how many unique MAC addresses can be learned on a single port. Exceeding this limit often indicates a MAC flooding attack where an adversary sends frames with many spoofed source MAC addresses to overflow the switch's CAM table. It can also indicate a misconfigured hub or unauthorized switch connected downstream.

**Importance:** SOC analysts should investigate as MAC flooding is a classic technique to force switches into hub mode, enabling traffic sniffing across the entire VLAN.

**Category:** Port Security

**EXOS EMS:** `FDB.LrnLimit`

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours of syslog data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match FDB learning limit exceeded messages
| where SyslogMessage has "FDB.LrnLimit"
// Parse port information from the message
| parse SyslogMessage with * "Port " Port " " Rest
// Extract offending MAC address
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
// Aggregate violations per host/port per hour to identify patterns
| summarize
    ViolationCount = count(),
    MACList = make_set(MACAddress, 20)
  by HostName, Port, bin(TimeGenerated, 1h)
| order by ViolationCount desc
```

---

### 3. MAC Address Movement — Potential ARP Spoofing

**Description:** Detects when a MAC address rapidly moves between different switch ports, which may indicate ARP spoofing or MAC spoofing attacks. In a legitimate network, MAC addresses remain relatively stable on their connected ports. Frequent movement suggests an attacker is impersonating another device or that there is a network loop causing instability.

**Importance:** SOC analysts should investigate MAC movement patterns as they are a strong indicator of man-in-the-middle attacks via ARP cache poisoning.

**Category:** Port Security

**EXOS EMS:** `FDB.MACTracking`

**MITRE:** T1557.002 — ARP Cache Poisoning

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours of MAC tracking data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match FDB MAC tracking/movement events
| where SyslogMessage has "FDB.MACTracking"
// Extract the MAC address that moved
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
// Extract source and destination ports of the movement
| extend FromPort = extract(@"from port\s+(\S+)", 1, SyslogMessage)
| extend ToPort = extract(@"to port\s+(\S+)", 1, SyslogMessage)
// Extract VLAN context
| extend VLANName = extract(@"VLAN\s+\"([^\"]+)\"", 1, SyslogMessage)
// Aggregate movement events per MAC in 15-minute windows to detect rapid flapping
| summarize
    MoveCount = count(),
    SourcePorts = make_set(FromPort, 10),
    DestPorts = make_set(ToPort, 10)
  by HostName, MACAddress, VLANName, bin(TimeGenerated, 15m)
// Threshold: more than 3 moves in 15 minutes is suspicious
| where MoveCount > 3 // Frequent MAC movement is suspicious
| order by MoveCount desc
```

---

### 4. Port Security Violation Surge

**Description:** Detects a surge of multiple port security violations occurring on a single switch within a short time window. When many MAC lock, learning limit, and MAC tracking violations fire simultaneously, it typically indicates a coordinated attack such as MAC flooding or a large-scale unauthorized device deployment rather than isolated incidents.

**Importance:** SOC analysts should treat a surge of port security violations as a high-priority event because it suggests an active, ongoing attack against the network switching infrastructure.

**Category:** Port Security

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 15-minute window for detecting violation surges
let lookback = 15m;
// Threshold: more than 10 violations in 5 minutes triggers alert
let threshold = 10;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all port security violation types
| where SyslogMessage has_any ("FDB.MacLocking", "FDB.LrnLimit", "FDB.MACTracking")
// Parse component from the EMS message for categorization
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Aggregate all violations per switch in 5-minute bins to detect surges
| summarize
    ViolationCount = count(),
    Components = make_set(Component, 5),
    Messages = make_set(SyslogMessage, 10)
  by HostName, bin(TimeGenerated, 5m)
// Detection logic: only alert when violations exceed threshold
| where ViolationCount > threshold
| project TimeGenerated, HostName, ViolationCount, Components, Messages
```

---

## DHCP Security

### 5. DHCP Snooping Violation — Rogue DHCP Server

**Description:** Detects DHCP snooping violations that occur when a DHCP server response is received on an untrusted port. This is a critical indicator of a rogue DHCP server on the network, which an attacker can use to distribute malicious DNS servers, default gateways, or IP configurations to redirect victim traffic. DHCP snooping is a first-line defense against this attack vector.

**Importance:** SOC analysts must investigate immediately because a rogue DHCP server can compromise every new device that joins the network, enabling widespread man-in-the-middle attacks.

**Category:** DHCP Security

**EXOS EMS:** `ipSecur.dhcpViol`

**MITRE:** T1557.003 — DHCP Spoofing

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours of DHCP snooping violation data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match DHCP snooping violation messages
| where SyslogMessage has "ipSecur.dhcpViol"
// Extract port, VLAN, and source MAC for incident context
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| extend VLANName = extract(@"VLAN\s+\"([^\"]+)\"", 1, SyslogMessage)
| extend SourceMAC = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, VLANName, SourceMAC, SyslogMessage
// Aggregate violations per host per hour to identify persistent rogue servers
| summarize
    ViolationCount = count(),
    Ports = make_set(Port, 10),
    VLANs = make_set(VLANName, 5),
    MACs = make_set(SourceMAC, 10)
  by HostName, bin(TimeGenerated, 1h)
| order by ViolationCount desc
```

---

### 6. DHCP Snooping Port/MAC Blocked

**Description:** Detects when the switch's DHCP snooping feature actively blocks a port or MAC address due to a security violation. This means the switch has taken enforcement action against a device that violated DHCP security policy, such as sending unauthorized DHCP responses or exceeding rate limits. The block may be temporary or permanent depending on configuration.

**Importance:** SOC analysts should investigate blocked ports/MACs as they confirm that a security violation was severe enough to trigger automated enforcement, indicating an active threat or misconfigured device.

**Category:** DHCP Security

**EXOS EMS:** `ipSecur.blkPort`, `ipSecur.blkMac`

**MITRE:** T1557.003 — DHCP Spoofing

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours of DHCP snooping block events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match port-blocked or MAC-blocked events from IP security
| where SyslogMessage has_any ("ipSecur.blkPort", "ipSecur.blkMac")
// Extract port, MAC, and block duration for triage
| extend Port = extract(@"[Pp]ort\s+(\S+)", 1, SyslogMessage)
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| extend BlockDuration = extract(@"(\d+)\s+seconds", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, MACAddress, BlockDuration, SyslogMessage
| order by TimeGenerated desc
```

---

### 7. IP Security Packet Drop

**Description:** Detects when the switch's IP security feature drops packets that fail validation checks such as source IP verification, DHCP snooping binding table lookups, or ARP inspection. A high volume of dropped packets on specific ports indicates either persistent attack attempts or a misconfigured device that is generating invalid traffic.

**Importance:** SOC analysts should monitor drop rates as sustained packet drops may indicate an ongoing spoofing or injection attack that the switch is actively mitigating.

**Category:** DHCP Security

**EXOS EMS:** `ipSecur.drpPkt`

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 1 hour — shorter window for high-frequency packet drop events
let lookback = 1h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match IP security dropped packet messages
| where SyslogMessage has "ipSecur.drpPkt"
// Extract the port where drops are occurring
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
// Aggregate drops per switch in 5-minute bins to identify sustained activity
| summarize
    DropCount = count(),
    Ports = make_set(Port, 20)
  by HostName, bin(TimeGenerated, 5m)
// Threshold: more than 10 drops in 5 minutes warrants investigation
| where DropCount > 10
| order by DropCount desc
```

---

## ARP Security

### 8. Dynamic ARP Inspection Violation

**Description:** Detects ARP packets that fail Dynamic ARP Inspection (DAI) validation on the switch. DAI validates ARP packets against the DHCP snooping binding table to ensure the IP-to-MAC mapping is legitimate. Violations indicate that a device is sending ARP replies with forged IP-to-MAC mappings, which is the hallmark of ARP spoofing/poisoning attacks used for man-in-the-middle interception.

**Importance:** SOC analysts should treat DAI violations as strong evidence of an active ARP poisoning attack attempting to intercept traffic between hosts on the same VLAN.

**Category:** ARP Security

**EXOS EMS:** `ipSecur.arpViol`

**MITRE:** T1557.002 — ARP Cache Poisoning

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | IPAddress |

```kql
// Lookback: 24 hours of ARP inspection violation data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match ARP violation messages from IP security subsystem
| where SyslogMessage has "ipSecur.arpViol"
// Extract port, VLAN, IP, and MAC for full incident context
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| extend VLANName = extract(@"VLAN\s+\"([^\"]+)\"", 1, SyslogMessage)
| extend IPAddress = extract(@"IP\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, VLANName, IPAddress, MACAddress, SyslogMessage
// Aggregate violations per host/VLAN per hour to detect patterns
| summarize
    ViolationCount = count(),
    Ports = make_set(Port, 10),
    IPs = make_set(IPAddress, 10),
    MACs = make_set(MACAddress, 10)
  by HostName, VLANName, bin(TimeGenerated, 1h)
| order by ViolationCount desc
```

---

### 9. Duplicate IP Address Detected (DAD)

**Description:** Detects when the switch's Duplicate Address Detection mechanism identifies two devices claiming the same IP address on the network. This can result from a misconfigured static IP, but it is also a technique used in ARP spoofing attacks where the attacker assumes the IP of a legitimate host (such as the default gateway) to intercept traffic.

**Importance:** SOC analysts should investigate duplicate IP alerts promptly because if the conflicting IP belongs to a gateway or critical server, it may indicate an active man-in-the-middle attack.

**Category:** ARP Security

**EXOS EMS:** `vlan.dad.IPAddrDup`

**MITRE:** T1557.002 — ARP Cache Poisoning

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | DuplicateIP |

```kql
// Lookback: 24 hours for duplicate address detection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match duplicate IP address detection messages
| where SyslogMessage has "vlan.dad.IPAddrDup"
// Extract the conflicting IP, neighbor MAC, and interface
| extend DuplicateIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend NeighborMAC = extract(@"Neighbor\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| extend Interface = extract(@"interface\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, DuplicateIP, NeighborMAC, Interface, SyslogMessage
| order by TimeGenerated desc
```

---

## Spanning Tree Protocol

### 10. STP Topology Change Detected

**Description:** Detects Spanning Tree Protocol topology change notifications (TCNs) on the switch. STP topology changes cause the switch to flush its MAC address table and temporarily flood traffic, which degrades network performance. While some TCNs are expected during maintenance, unexpected changes may indicate physical link failures, misconfigurations, or deliberate STP manipulation.

**Importance:** SOC analysts should correlate STP topology changes with other events because they can be a side effect of physical intrusion, unauthorized device connections, or deliberate network attacks.

**Category:** Spanning Tree

**EXOS EMS:** `STP.State.Topology`, `STP.InTopChg`, `STP.SendClntTopoChgMsg`

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for STP topology change events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all STP topology change related EMS messages
| where SyslogMessage has_any ("STP.State.Topology", "STP.InTopChg", "STP.SendClntTopoChgMsg")
// Parse severity and component from structured EMS format
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Extract the STP domain name for context
| extend StpDomain = extract(@"\[([^\]]+)\]", 1, SyslogMessage)
| project TimeGenerated, HostName, Severity, Component, StpDomain, SyslogMessage
| order by TimeGenerated desc
```

---

### 11. STP Root Bridge Change — Potential Attack

**Description:** Detects when the root bridge for a Spanning Tree domain changes. The root bridge is the central node that determines the entire Layer 2 forwarding topology. An attacker can inject BPDUs with a lower bridge priority to force themselves to become the root bridge, enabling them to intercept all traffic traversing the spanning tree. This is one of the most dangerous Layer 2 attacks.

**Importance:** SOC analysts must investigate root bridge changes immediately because an unauthorized root bridge change gives an attacker the ability to see and manipulate all switched traffic in the affected domain.

A root bridge change can indicate a **STP manipulation attack** where an attacker injects BPDUs with a lower priority to become root and intercept all traffic.

**Category:** Spanning Tree

**EXOS EMS:** `STP.State.RootChg`

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for root bridge change events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match STP root change events or related root keywords
| where SyslogMessage has "STP.State.RootChg"
    or (SyslogMessage has "STP" and SyslogMessage has_any ("Root", "root bridge", "root change"))
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

### 12. Excessive STP Topology Changes — Network Instability

**Description:** Detects when an unusually high number of STP topology changes occur on a single switch within a short time window. Excessive topology changes cause repeated MAC table flushes and traffic flooding, leading to severe network degradation. This pattern may indicate a deliberate STP DoS attack, a flapping link, or a misconfigured device sending rapid BPDUs.

**Importance:** SOC analysts should escalate excessive STP topology changes because they indicate either an active Layer 2 attack or a hardware/configuration issue causing significant network instability.

**Category:** Spanning Tree

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 30-minute window for detecting excessive topology changes
let lookback = 30m;
// Threshold: more than 5 topology changes in 10 minutes is abnormal
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all STP topology and root change events
| where SyslogMessage has_any ("STP.State.Topology", "STP.InTopChg", "STP.State.RootChg")
// Aggregate topology change events per switch in 10-minute bins
| summarize
    TCNCount = count(),
    Messages = make_set(SyslogMessage, 10)
  by HostName, bin(TimeGenerated, 10m)
// Detection logic: alert only when count exceeds threshold
| where TCNCount > threshold
| project TimeGenerated, HostName, TCNCount, Messages
```

---

## Link & Port Monitoring

### 13. Port Link Flap Detection

**Description:** Detects when the switch's built-in link flap detection mechanism triggers, indicating that a port is rapidly transitioning between up and down states. Link flapping can be caused by a faulty cable, a failing NIC, an overloaded switch port, or a deliberate attempt to destabilize the network. The switch may automatically disable the flapping port to protect network stability.

**Importance:** SOC analysts should investigate link flaps because persistent flapping on a port can cause widespread disruption across the VLAN and may indicate physical tampering or hardware failure.

**Category:** Link Monitoring

**EXOS EMS:** `vlan.msgs.PortLinkFlapActLogEvent`

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for link flap log events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match the port link flap action log event
| where SyslogMessage has "PortLinkFlapActLogEvent"
// Extract the affected port and its flap status
| extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
| extend FlapStatus = extract(@"status is (\w+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, FlapStatus, SyslogMessage
| order by TimeGenerated desc
```

---

### 14. Excessive Port State Changes — Anomaly

**Description:** Detects when a specific switch port undergoes an abnormally high number of link state transitions (up/down) within a short window. Unlike the built-in flap detection in detection #13, this rule catches rapid oscillation patterns across all port state change messages. Excessive state changes on a port generate heavy control plane load and can cause MAC table instability.

**Importance:** SOC analysts should investigate excessive port state changes because they may indicate a deliberate link-layer attack, a failing device, or a physical security breach where cables are being tampered with.

**Category:** Link Monitoring

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 10-minute window for detecting rapid port state changes
let lookback = 10m;
// Threshold: more than 10 state changes in the window is anomalous
let threshold = 10;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all port link state change messages (both EXOS and HAL variants)
| where SyslogMessage has_any ("portLinkStateUp", "portLinkStateDown", "HAL.Port.LinkUp", "HAL.Port.LinkDown")
// Extract port identifier and determine state direction
| extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
| extend PortState = iff(SyslogMessage has_any ("Up", "UP"), "Up", "Down")
// Aggregate state changes per port to find oscillating ports
| summarize
    FlipCount = count(),
    UpCount = countif(PortState == "Up"),
    DownCount = countif(PortState == "Down")
  by HostName, Port
// Detection logic: alert when total state changes exceed threshold
| where FlipCount > threshold
| project HostName, Port, FlipCount, UpCount, DownCount
| order by FlipCount desc
```

---

### 15. Mass Port Down Event — Potential Cable/Switch Failure

**Description:** Detects when multiple ports on the same switch go down simultaneously or within a very short time window. A mass port-down event typically indicates a hardware failure (failed line card, power supply issue), a severed cable trunk, or a catastrophic switch failure. It can also indicate a physical attack where an attacker disconnects infrastructure cabling.

**Importance:** SOC analysts should treat mass port-down events as high priority because they indicate either critical infrastructure failure or potential physical sabotage affecting network availability.

**Category:** Link Monitoring

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 5-minute window for detecting mass port failures
let lookback = 5m;
// Threshold: 5 or more ports going down simultaneously is a mass event
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match port link-down messages only
| where SyslogMessage has_any ("portLinkStateDown", "HAL.Port.LinkDown")
// Extract the port identifier for each down event
| extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
// Aggregate down events per switch in 2-minute bins to detect simultaneous failures
| summarize
    DownCount = count(),
    AffectedPorts = make_set(Port, 50)
  by HostName, bin(TimeGenerated, 2m)
// Detection logic: alert when port-down count reaches threshold
| where DownCount >= threshold
| project TimeGenerated, HostName, DownCount, AffectedPorts
```

---

## Loop & Storm Protection

### 16. Loop Detected — ELRP Alert

**Description:** Detects when the Extreme Loop Recovery Protocol (ELRP) identifies a Layer 2 loop in the network. Loops cause broadcast storms that can overwhelm switch CPUs and saturate bandwidth, effectively bringing down the entire VLAN or network segment. ELRP sends test packets and alerts when they return to the originating switch, confirming a loop condition.

**Importance:** SOC analysts must respond to loop detections urgently because an unresolved loop can cascade into a complete network outage within seconds.

**Category:** Loop Protection

**EXOS EMS:** `ELRP.Detect`, `ELRP.Action`

**MITRE:** T1498 — Network Denial of Service

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for loop detection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match ELRP loop detection and action events
| where SyslogMessage has_any ("ELRP.Detect", "ELRP.Action")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

### 17. Storm Control Triggered

**Description:** Detects when the switch's storm control (bandwidth management) feature triggers because broadcast, multicast, or unknown unicast traffic has exceeded the configured threshold on a port. Traffic storms consume all available bandwidth and processing capacity, causing network-wide disruption. Storm control triggers often coincide with loop conditions, broadcast amplification attacks, or malfunctioning NICs.

**Importance:** SOC analysts should investigate storm control triggers as they may indicate an active broadcast storm, network loop, or deliberate traffic amplification attack.

**Category:** Storm Protection

**EXOS EMS:** `bwMgr.Warning`, `bwMgr.Critical`

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for storm control events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match bandwidth manager warnings/critical events or storm-related keywords
| where SyslogMessage has_any ("bwMgr.Warning", "bwMgr.Critical")
    or (SyslogMessage has "storm" and SyslogMessage has_any ("control", "detect", "threshold"))
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

### 18. EAPS Ring State Change

**Description:** Detects state changes in the Ethernet Automatic Protection Switching (EAPS) ring topology. EAPS provides sub-second failover for ring-based network designs common in campus and metro Ethernet deployments. A state change from Complete to Failed indicates a ring break, while rapid state transitions may indicate instability in the ring that could lead to traffic blackholing or loops.

**Importance:** SOC analysts should monitor EAPS state changes because ring failures affect redundancy and can lead to traffic loss or loops if the protection mechanism does not converge correctly.

**Category:** Ring Protection

**EXOS EMS:** `EAPS.State`, `EAPS.Topology`

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for EAPS ring state events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match EAPS state and topology change events
| where SyslogMessage has_any ("EAPS.State", "EAPS.Topology")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Authentication & Access Control

### 19. Switch Login Brute Force

**Description:** Detects multiple failed authentication attempts against the switch management interface from a single source IP address within a short time window. Brute force attacks against network infrastructure are particularly dangerous because compromising a switch grants the attacker the ability to reconfigure VLANs, mirror traffic, disable security features, and pivot deeper into the network.

**Importance:** SOC analysts should prioritize switch brute force alerts because network device compromise provides attackers with privileged access to intercept and manipulate all traffic traversing the switch.

**Category:** Authentication

**EXOS EMS:** `AAA.authFail`

**MITRE:** T1110 — Brute Force

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | SourceIP |
| Account | Name | Users |

```kql
// Lookback: 30-minute window for detecting brute force patterns
let lookback = 30m;
// Threshold: 5 or more failures from the same source is brute force
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match authentication failure events
| where SyslogMessage has "AAA.authFail"
// Extract user, authentication method, and source IP from the message
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
| extend Method = extract(@"through\s+(\S+)", 1, SyslogMessage)
| extend SourceIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
// Aggregate failures per source IP per target switch to detect brute force patterns
| summarize
    FailCount = count(),
    Users = make_set(User, 10),
    Methods = make_set(Method, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by HostName, SourceIP
// Detection logic: alert when failure count reaches brute force threshold
| where FailCount >= threshold
| project HostName, SourceIP, FailCount, Users, Methods, FirstAttempt, LastAttempt
| order by FailCount desc
```

---

### 20. SSH Connection Rejected/Denied

**Description:** Detects rejected or denied SSH connection attempts to the switch management interface. SSH rejections occur when connections are denied due to access control lists, maximum session limits, or authentication failures at the SSH protocol level (before AAA). Tracking these events helps identify reconnaissance activity and unauthorized access attempts targeting network infrastructure.

**Importance:** SOC analysts should monitor SSH rejections as they may reveal scanning activity or an attacker probing the network for accessible management interfaces.

**Category:** Authentication

**EXOS EMS:** `exsshd.RejctConnAccessDeny`, `exsshd.AuthFail`

**MITRE:** T1110 — Brute Force

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Lookback: 24 hours for SSH rejection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match SSH rejection and authentication failure messages
| where SyslogMessage has_any ("exsshd.RejctConnAccessDeny", "exsshd.AuthFail")
// Extract the source IP of the rejected connection
| extend SourceIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
// Aggregate rejections per source IP per hour to detect persistent attackers
| summarize
    RejectCount = count(),
    Switches = make_set(HostName, 10)
  by SourceIP, bin(TimeGenerated, 1h)
| order by RejectCount desc
```

---

### 21. Successful Login from Unexpected Source

**Description:** Detects successful authentication to the switch management interface from IP addresses outside the defined management network subnets. Legitimate switch administration should only originate from designated management networks. A successful login from an unexpected source may indicate credential theft, a compromised jump host, or an attacker who has gained valid credentials through phishing or other means.

**Importance:** SOC analysts should investigate unexpected source logins urgently because they indicate an attacker with valid credentials accessing network infrastructure from an unauthorized location.

**Category:** Authentication

**EXOS EMS:** `AAA.authPass`

**MITRE:** T1078 — Valid Accounts

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | SourceIP |
| Account | Name | User |

```kql
// Lookback: 24 hours for successful authentication events
let lookback = 24h;
// Define allowed management subnets — customize for your environment
let AllowedMgmtSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match successful authentication events
| where SyslogMessage has "AAA.authPass"
// Extract user, authentication method, and source IP
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
| extend Method = extract(@"through\s+(\S+)", 1, SyslogMessage)
| extend SourceIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
// Only evaluate events with a parseable source IP
| where isnotempty(SourceIP)
// Detection logic: flag logins from IPs NOT in approved management subnets
| where not(ipv4_is_in_any_range(SourceIP, AllowedMgmtSubnets))
| project TimeGenerated, HostName, User, Method, SourceIP, SyslogMessage
```

**Tuning:** Replace `AllowedMgmtSubnets` with your management network CIDRs.

---

### 22. 802.1X Authentication Failure

**Description:** Detects failed 802.1X (Network Access Control) authentication attempts on switch ports. 802.1X provides port-based access control where devices must authenticate before gaining network access. Failures indicate that a device was unable to present valid credentials, which may be a misconfigured endpoint, an expired certificate, or an unauthorized device attempting to connect to the network.

**Importance:** SOC analysts should monitor 802.1X failures because repeated failures on the same port may indicate an attacker attempting to bypass network access control with stolen or brute-forced credentials.

**Category:** Authentication

**EXOS EMS:** `nl.ClientStateChange`, `netLogin.ClientStateChange`

**MITRE:** T1110 — Brute Force

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for 802.1X authentication events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match netLogin client state change events
| where SyslogMessage has_any ("nl.ClientStateChange", "netLogin.ClientStateChange")
// Further filter to only failure/rejection states
| where SyslogMessage has_any ("Reject", "reject", "Fail", "fail", "Denied", "denied")
// Extract the client MAC address, port, and VLAN context
| extend MACAddress = extract(@"Station\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| extend VLANName = extract(@"VLAN\s+\"([^\"]+)\"", 1, SyslogMessage)
| project TimeGenerated, HostName, MACAddress, Port, VLANName, SyslogMessage
// Aggregate failures per MAC per hour to detect persistent attempts
| summarize
    FailCount = count(),
    Ports = make_set(Port, 10)
  by HostName, MACAddress, bin(TimeGenerated, 1h)
| order by FailCount desc
```

---

### 23. RADIUS/TACACS+ Authentication Events

**Description:** Monitors authentication events that are directed to external RADIUS or TACACS+ servers for centralized authentication. Tracking which authentication servers are handling requests and which users are authenticating helps establish baselines and detect anomalies such as failover to a backup server, authentication to an unexpected server, or a sudden spike in authentication requests that may indicate credential stuffing.

**Importance:** SOC analysts should track RADIUS/TACACS+ events to ensure authentication is flowing to expected servers and to detect anomalies in authentication patterns.

**Category:** Authentication

**EXOS EMS:** `AAA.usingRadius`, `AAA.usingTacacs`

**MITRE:** T1078 — Valid Accounts

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | Name | Users |

```kql
// Lookback: 24 hours for external authentication events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match RADIUS and TACACS+ authentication events
| where SyslogMessage has_any ("AAA.usingRadius", "AAA.usingTacacs")
// Extract the authentication server and user from the message
| extend AuthServer = extract(@"server\s+(\S+)", 1, SyslogMessage)
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
// Aggregate authentication attempts per server per hour for trend analysis
| summarize
    AuthAttempts = count(),
    Users = make_set(User, 20),
    Switches = make_set(HostName, 20)
  by AuthServer, bin(TimeGenerated, 1h)
```

---

### 24. Admin Session Activity Monitoring

**Description:** Monitors administrative session lifecycle events including logins, logouts, connections, and disconnections to the switch management interface. This provides an audit trail of who accessed the switch and when, enabling detection of unusual access patterns such as sessions at odd hours, unusually long sessions, or sessions from unexpected users.

**Importance:** SOC analysts should review admin session activity to maintain an accurate audit trail and detect unauthorized or suspicious administrative access patterns.

**Category:** Authentication

**EXOS EMS:** `CLI.connect`, `CLI.disconnect`

**MITRE:** T1078 — Valid Accounts

**Severity:** Informational

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| Account | Name | User |

```kql
// Lookback: 24 hours for admin session events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match session lifecycle events (connect, disconnect, auth, logout)
| where SyslogMessage has_any ("CLI.connect", "CLI.disconnect", "AAA.authPass", "AAA.logout")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Classify the event type based on component for easier analysis
| extend EventType = case(
    Component has "connect" or Component has "authPass", "SessionStart",
    Component has "disconnect" or Component has "logout", "SessionEnd",
    "Other"
  )
// Extract the username associated with the session
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, User, EventType, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Configuration Changes

### 25. Configuration Saved or Loaded

**Description:** Detects when a switch configuration is saved to persistent storage or when a new configuration file is loaded. Configuration saves typically follow administrative changes, while configuration loads may indicate a device restore, firmware upgrade, or an attacker loading a modified configuration to establish persistence or alter security settings.

**Importance:** SOC analysts should correlate configuration save/load events with authorized change windows to detect unauthorized configuration modifications.

**Category:** Configuration Change

**EXOS EMS:** `cm.SaveCfg`, `cm.UseCfg`

**MITRE:** T1565 — Data Manipulation

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for configuration save/load events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match configuration save, use, and file operation events
| where SyslogMessage has_any ("cm.SaveCfg", "cm.UseCfg", "cm.fileOps")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

### 26. CLI Command Audit — Remote Commands

**Description:** Audits CLI commands executed on the switch, distinguishing between remote (SSH/Telnet) and local (console) sessions. Remote command execution is the primary method attackers use after gaining switch access. Monitoring all commands provides forensic evidence and enables detection of destructive or suspicious commands such as disabling security features, creating backdoor accounts, or modifying ACLs.

**Importance:** SOC analysts should review CLI command audits to detect post-compromise activity such as security feature disablement, backdoor creation, or configuration tampering.

**Category:** Configuration Change

**EXOS EMS:** `CLI.logRemoteCmd`, `CLI.logLocalCmd`

**MITRE:** T1059 — Command and Scripting Interpreter

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for CLI command audit events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match remote and local CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Classify as remote vs local for risk assessment (remote is higher risk)
| extend CommandType = iff(SyslogMessage has "Remote", "Remote", "Local")
| project TimeGenerated, HostName, CommandType, SyslogMessage
| order by TimeGenerated desc
```

---

### 27. DHCP Snooping Configuration Change

**Description:** Detects when DHCP snooping is enabled, disabled, or modified on the switch. DHCP snooping is a critical network security feature that prevents rogue DHCP servers. Disabling or weakening it exposes the entire VLAN to DHCP spoofing attacks. An attacker with switch access may disable DHCP snooping as a prerequisite to deploying a rogue DHCP server.

**Importance:** SOC analysts must investigate DHCP snooping configuration changes immediately because disabling this feature removes a fundamental Layer 2 security control and enables DHCP-based attacks.

**Category:** Configuration Change — Network Security Feature

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for DHCP snooping configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events (where config changes are recorded)
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match DHCP snooping and IP security related commands
| where SyslogMessage has_any (
    "ip-security dhcp-snooping",
    "dhcp-snooping",
    "trusted-server",
    "trusted-port",
    "ip-security",
    "configure ip-security",
    "enable ip-security",
    "disable ip-security",
    "configure trusted-server",
    "configure trusted-port"
  )
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has "disable", "DISABLED",
    SyslogMessage has "enable", "ENABLED",
    SyslogMessage has "configure", "MODIFIED",
    "CHANGED"
  )
| project TimeGenerated, HostName, Action, SyslogMessage
| order by TimeGenerated desc
```

---

### 28. Port Mirroring Configuration Change

**Description:** Detects when port mirroring is configured, enabled, or disabled on the switch. Port mirroring duplicates traffic from one or more ports to a monitoring port, and while it is a legitimate tool for network troubleshooting, unauthorized port mirroring is a primary technique for traffic interception and data exfiltration. An attacker with switch access can mirror sensitive traffic to a port connected to their capture device.

**Importance:** SOC analysts must investigate port mirroring changes as unauthorized mirroring is a direct indicator of traffic interception and potential data exfiltration.

**Category:** Configuration Change — Network Visibility

**MITRE:** T1040 — Network Sniffing

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for port mirroring configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match CLI commands related to port mirroring or HAL mirror events
| where (SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
    and SyslogMessage has_any (
        "mirror", "port-mirror", "mirroring",
        "configure mirror", "enable mirror", "disable mirror",
        "create mirror", "delete mirror",
        "monitor port", "analyzer port"
    ))
    or SyslogMessage has "HAL.Mirror"
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has_any ("disable", "delete"), "DISABLED/DELETED",
    SyslogMessage has_any ("enable", "create"), "ENABLED/CREATED",
    SyslogMessage has "configure", "MODIFIED",
    "CHANGED"
  )
| project TimeGenerated, HostName, Action, SyslogMessage
| order by TimeGenerated desc
```

---

### 29. ACL/Policy Configuration Change

**Description:** Detects when Access Control Lists (ACLs) or policies are created, modified, bound, or unbound on the switch. ACLs are the primary mechanism for enforcing traffic filtering and segmentation at Layer 2/3. Unauthorized ACL changes can open previously blocked pathways, disable traffic filtering, or redirect traffic. An attacker may modify ACLs to permit their traffic or remove restrictions that block lateral movement.

**Importance:** SOC analysts should investigate ACL changes because unauthorized modifications can silently open network pathways that were previously secured.

**Category:** Configuration Change

**EXOS EMS:** `ACL.bind`, `ACL.unBind`, `ACL.Change`, `ACL.DynACL`

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
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

### 30. VLAN Configuration Change

**Description:** Detects when VLANs are created, deleted, or modified on the switch, including port membership changes. VLAN manipulation is a key technique in VLAN hopping attacks and network segmentation bypass. An attacker who modifies VLAN configuration can move ports between VLANs to gain access to restricted network segments, or remove VLAN isolation entirely.

**Importance:** SOC analysts should monitor VLAN changes because unauthorized modifications can break network segmentation and expose sensitive network zones to unauthorized access.

**Category:** Configuration Change

**MITRE:** T1599 — Network Boundary Bridging

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for VLAN configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match VLAN-related configuration commands
| where SyslogMessage has_any (
    "create vlan", "delete vlan", "configure vlan",
    "add vlan", "add ports", "delete ports",
    "vlan tag", "vlan untag",
    "configure vlan-translation",
    "enable vlan", "disable vlan"
  )
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has "delete", "DELETED",
    SyslogMessage has "create", "CREATED",
    SyslogMessage has "configure", "MODIFIED",
    "CHANGED"
  )
| project TimeGenerated, HostName, Action, SyslogMessage
| order by TimeGenerated desc
```

---

### 31. STP Configuration Change

**Description:** Detects when STP configuration is modified, including changes to bridge priority, BPDU guard settings, root guard, or enabling/disabling STP entirely. STP configuration changes are high-risk because they directly affect the Layer 2 forwarding topology. An attacker may lower the bridge priority to become the root bridge, disable BPDU guard to allow their injected BPDUs, or disable STP entirely to create loops.

**Importance:** SOC analysts should investigate STP configuration changes immediately because they can be precursors to STP manipulation attacks or may indicate an attacker weakening Layer 2 security controls.

**Category:** Configuration Change

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for STP configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match STP-related configuration commands
| where SyslogMessage has_any (
    "stpd", "spanning-tree", "stp",
    "configure stpd", "enable stpd", "disable stpd",
    "bpdu-guard", "bpdu-restrict", "bpdu-filter",
    "loop-protect", "edge-safeguard",
    "priority", "root-guard",
    "create stpd", "delete stpd"
  )
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has "disable", "DISABLED",
    SyslogMessage has "enable", "ENABLED",
    SyslogMessage has "configure", "MODIFIED",
    SyslogMessage has "delete", "DELETED",
    SyslogMessage has "create", "CREATED",
    "CHANGED"
  )
| project TimeGenerated, HostName, Action, SyslogMessage
| order by TimeGenerated desc
```

---

### 32. Routing Configuration Change

**Description:** Detects when routing protocol configurations (OSPF, BGP, RIP, IS-IS) or static routes are modified on the switch. Routing changes directly affect how traffic flows through the network. An attacker who modifies routing can redirect traffic through attacker-controlled paths for interception, create black holes to deny service, or inject malicious routes to intercept traffic destined for specific subnets.

**Importance:** SOC analysts should investigate routing configuration changes because unauthorized modifications can enable traffic interception, black hole routing, or route hijacking attacks.

**Category:** Configuration Change

**MITRE:** T1565 — Data Manipulation

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for routing configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match routing protocol configuration commands across all protocols
| where SyslogMessage has_any (
    "configure ospf", "enable ospf", "disable ospf",
    "configure bgp", "enable bgp", "disable bgp",
    "configure rip", "enable rip", "disable rip",
    "configure isis", "enable isis", "disable isis",
    "iproute", "static route", "route-map", "prefix-list",
    "configure ospf area", "configure bgp neighbor",
    "create ospf", "delete ospf",
    "create bgp", "delete bgp"
  )
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

## Neighbor Discovery

### 33. LLDP Neighbor Disappeared — Link Loss

**Description:** Detects when an LLDP (Link Layer Discovery Protocol) neighbor is removed from the switch's neighbor table, indicating that a previously connected device is no longer reachable. LLDP neighbor disappearances can indicate a physical link failure, a device being powered off or rebooted, or a cable being disconnected. Multiple simultaneous disappearances may indicate a larger infrastructure failure.

**Importance:** SOC analysts should investigate LLDP neighbor disappearances because they may indicate physical tampering, unauthorized device removal, or infrastructure failures that affect network connectivity.

**Category:** Neighbor Discovery

**EXOS EMS:** `LLDP.NbrRemove`

**MITRE:** T1200 — Hardware Additions

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for LLDP neighbor removal events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match LLDP neighbor removal events
| where SyslogMessage has "LLDP.NbrRemove"
// Extract the port where the neighbor was lost
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, SyslogMessage
// Aggregate lost neighbors per switch in 30-minute bins to detect mass losses
| summarize
    LostNeighbors = count(),
    AffectedPorts = make_set(Port, 20)
  by HostName, bin(TimeGenerated, 30m)
| order by LostNeighbors desc
```

---

### 34. New LLDP Neighbor — Rogue Device Detection

**Description:** Detects when a new LLDP neighbor appears on a switch port. While new neighbors are expected during legitimate deployments, unexpected neighbors may indicate a rogue device such as an unauthorized switch, access point, or network tap being connected to the infrastructure. Cross-referencing new neighbors against a known device inventory is essential for identifying unauthorized devices.

**Importance:** SOC analysts should investigate new LLDP neighbors that do not correspond to approved change requests, as they may indicate unauthorized device deployment or physical intrusion.

**Category:** Neighbor Discovery

**EXOS EMS:** `LLDP.NbrAdd`

**MITRE:** T1200 — Hardware Additions

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for new LLDP neighbor events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match LLDP neighbor addition events
| where SyslogMessage has "LLDP.NbrAdd"
// Extract the port where the new neighbor was detected
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, Port, SyslogMessage
| order by TimeGenerated desc
```

**Tuning:** Cross-reference new neighbors against a known device inventory to identify unauthorized devices.

---

### 35. CDP Neighbor Timeout

**Description:** Detects when a CDP (Cisco Discovery Protocol) neighbor times out on the switch. In mixed-vendor environments, CDP timeouts indicate that a previously connected Cisco device is no longer reachable. This may indicate link failure, device failure, or physical disconnection. While CDP is primarily a Cisco protocol, Extreme switches can receive and process CDP frames.

**Importance:** SOC analysts should monitor CDP timeouts in multi-vendor environments to detect device disappearances that may indicate infrastructure issues or unauthorized disconnections.

**Category:** Neighbor Discovery

**EXOS EMS:** `CDP.Timeout`

**MITRE:** T1200 — Hardware Additions

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for CDP timeout events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match CDP neighbor timeout events
| where SyslogMessage has "CDP.Timeout"
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

## Routing Protocol Security

### 36. OSPF Neighbor State Change

**Description:** Detects OSPF neighbor or interface state changes on the switch. OSPF adjacency changes affect routing convergence and traffic forwarding. A neighbor transitioning from Full to Down indicates a lost adjacency, which can result from link failure, configuration changes, or an attacker injecting malicious OSPF packets. Unexpected state changes in a stable environment are always worth investigating.

**Importance:** SOC analysts should investigate OSPF state changes in stable environments because they may indicate routing attacks, unauthorized route injection, or infrastructure failures affecting traffic forwarding.

**Category:** Routing Security

**EXOS EMS:** `OSPF.NbrStateChg`, `OSPF.IntfStateChg`

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for OSPF state change events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match OSPF neighbor and interface state change events
| where SyslogMessage has_any ("OSPF.NbrStateChg", "OSPF.IntfStateChg")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

### 37. BGP Peer Event — Session Reset

**Description:** Detects BGP session resets, failures, and state transitions to down/idle states. BGP session disruptions can cause route withdrawals and reconvergence, leading to traffic blackholing or suboptimal routing. In a targeted attack, an adversary may send TCP RST packets or exploit BGP vulnerabilities to tear down peering sessions and disrupt network routing.

**Importance:** SOC analysts should investigate BGP session resets because they can indicate a targeted routing attack, peering misconfiguration, or infrastructure failure affecting upstream connectivity.

**Category:** Routing Security

**EXOS EMS:** `BGP.event`, `BGP.misc`

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for BGP session events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match BGP event and miscellaneous messages
| where SyslogMessage has_any ("BGP.event", "BGP.misc")
// Further filter to session disruption keywords only
| where SyslogMessage has_any ("Down", "down", "Reset", "reset", "Idle", "idle", "cease")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

### 38. Routing Instability — Multiple Protocol Flaps

**Description:** Detects when multiple routing protocol events (OSPF, BGP, IS-IS, RIP) occur in rapid succession on the same switch, indicating widespread routing instability. When multiple protocols flap simultaneously, it typically indicates a systemic issue such as a control plane overload, a route redistribution loop, or a targeted attack against the switch's routing processes.

**Importance:** SOC analysts should escalate routing instability alerts because simultaneous multi-protocol flapping can lead to widespread traffic blackholing and network partitioning.

**Category:** Routing Security

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 30-minute window for detecting routing instability
let lookback = 30m;
// Threshold: more than 5 routing events in 15 minutes indicates instability
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match routing protocol state change events across all protocols
| where SyslogMessage has_any (
    "OSPF.NbrStateChg", "OSPF.IntfStateChg",
    "BGP.event", "BGP.misc",
    "ISIS.AdjState",
    "RIP.Config"
  )
// Parse component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Aggregate routing events per switch in 15-minute bins, tracking which protocols are affected
| summarize
    EventCount = count(),
    Protocols = make_set(TopComponent = tostring(split(Component, ".")[0]), 5),
    Messages = make_set(SyslogMessage, 10)
  by HostName, bin(TimeGenerated, 15m)
// Detection logic: alert when event count exceeds instability threshold
| where EventCount > threshold
| project TimeGenerated, HostName, EventCount, Protocols, Messages
```

---

## Hardware & System Health

### 39. Process Crash Detected

**Description:** Detects when a software process crashes or is unexpectedly stopped on the switch. Process crashes can affect switch functionality ranging from losing specific protocol support to a complete management plane failure. Crashes may be caused by software bugs, resource exhaustion, or deliberate exploitation of vulnerabilities in switch software. Repeated crashes of the same process may indicate an active exploit attempt.

**Importance:** SOC analysts should investigate process crashes because they may indicate exploitation of a switch vulnerability or denial-of-service attack against the switch's control plane.

**Category:** System Health

**EXOS EMS:** `epm.ProcCrash`

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for process crash events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match process crash and unexpected stop events
| where SyslogMessage has_any ("epm.ProcCrash", "epm.ProcStop")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Extract the name of the crashed process for triage
| extend ProcessName = extract(@"Process\s+(\S+)", 1, Rest)
| project TimeGenerated, HostName, Severity, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

---

### 40. Stack/Chassis Failover Event

**Description:** Detects failover events in stacked or chassis-based switch deployments, including master/backup transitions, slot failures, and power issues. Failover events indicate that the primary unit or component has failed and the backup has taken over. While failover is a designed resilience mechanism, unexpected failovers may indicate hardware failure, power issues, or an attacker deliberately crashing the primary unit to force a potentially less-secured backup to take over.

**Importance:** SOC analysts should investigate unexpected failover events because they may indicate hardware failure requiring immediate attention or deliberate sabotage of the primary switch unit.

**Category:** System Health

**EXOS EMS:** `cm.VSM`, `dm.Warn`, `dm.Error`, `ELSM.State`, `ELSM.Transition`

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for stack/chassis failover events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match stack management, device manager, and ELSM events
| where SyslogMessage has_any (
    "cm.VSM", "dm.Warn", "dm.Error",
    "ELSM.State", "ELSM.Transition",
    "epm.ProcCrash"
  )
// Further filter to failover-specific keywords
| where SyslogMessage has_any ("failover", "master", "backup", "standby",
    "stack", "slot", "power", "insufficient", "crash")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

### 41. PoE Power Fault or Denial

**Description:** Detects Power over Ethernet (PoE) faults, power denials, and overload conditions on switch ports. PoE issues can affect IP phones, wireless access points, cameras, and other powered devices. A power denial indicates the switch cannot allocate sufficient power to a port, a power fault indicates a wiring or device issue, and an overload means the total PoE budget is exceeded. These events can be caused by hardware failures or deliberate PoE exhaustion attacks.

**Importance:** SOC analysts should monitor PoE events because power denial to critical devices like security cameras or access points can be used to create blind spots in physical security.

**Category:** System Health

**EXOS EMS:** `PoE.PwrDeny`, `PoE.PwrFault`, `PoE.Overload`

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for PoE power events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match PoE power denial, fault, and overload events
| where SyslogMessage has_any ("PoE.PwrDeny", "PoE.PwrFault", "PoE.Overload")
// Extract the affected port
| extend Port = extract(@"[Pp]ort\s+(\S+)", 1, SyslogMessage)
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, Port, SyslogMessage
| order by TimeGenerated desc
```

---

### 42. Critical/Error System Events

**Description:** Detects all Critical and Error severity events from the switch, providing a catch-all for system issues that may not be covered by more specific detections. These events represent the highest severity conditions reported by the switch operating system and can include hardware failures, memory exhaustion, firmware errors, and other conditions that threaten switch stability or security.

**Importance:** SOC analysts should review critical and error events as a catch-all to ensure no significant system issues are missed by the more targeted detection rules.

**Category:** System Health

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for critical and error system events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match messages with Critical or Error severity prefixes
| where SyslogMessage has_any ("<Crit:", "<Erro:")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Aggregate events per host/severity per hour to identify patterns and volume
| summarize
    EventCount = count(),
    Components = make_set(Component, 10),
    SampleMessages = make_set(SyslogMessage, 5)
  by HostName, Severity, bin(TimeGenerated, 1h)
| order by EventCount desc
```

---

## DoS Protection

### 43. DoS Protection Alert Triggered

**Description:** Detects when the switch's built-in DoS protection feature triggers an alert or takes action against suspected denial-of-service traffic. The switch can detect various DoS attack patterns including SYN floods, ICMP floods, and other volumetric attacks directed at the switch's control plane. When triggered, the switch may rate-limit or block the offending traffic to protect itself.

**Importance:** SOC analysts should investigate DoS protection alerts because they confirm that attack traffic has reached sufficient volume to trigger hardware-level protection, indicating an active denial-of-service attack.

**Category:** Threat Detection

**EXOS EMS:** `dosprotect.Alert`, `dosprotect.Action`

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for DoS protection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match DoS protection alert and action events
| where SyslogMessage has_any ("dosprotect.Alert", "dosprotect.Action")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## VOSS-Specific

### 44. VOSS CLI Audit Log Monitoring

**Description:** Monitors all CLI commands executed on VOSS (Virtual Services Platform Operating System) switches via the CLILOG facility. VOSS uses a different logging format than ExtremeXOS, so this detection uses a broader filter. Every command entered by an administrator is logged, providing a complete audit trail for forensic analysis and compliance. This is the VOSS equivalent of detection #26 for ExtremeXOS.

**Importance:** SOC analysts should review VOSS CLI audit logs to detect unauthorized configuration changes, backdoor creation, or security feature disablement on VOSS-based switches.

**Category:** Configuration Audit (VOSS)

**MITRE:** T1059 — Command and Scripting Interpreter

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for VOSS CLI audit events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Key filter: match VOSS CLI log entries (note: no Facility filter — VOSS may use different facilities)
| where SyslogMessage has "CLILOG"
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

### 45. VOSS IS-IS/Fabric Connect Adjacency Change

**Description:** Detects IS-IS adjacency state changes and Fabric Connect (SPBM) events on VOSS switches. IS-IS is the routing protocol that underpins Extreme's Fabric Connect architecture, and adjacency changes directly affect fabric connectivity and service reachability. A lost adjacency means traffic can no longer traverse that fabric link, potentially isolating network segments or services.

**Importance:** SOC analysts should investigate IS-IS/Fabric Connect adjacency changes because they can indicate fabric infrastructure failures, unauthorized topology modifications, or deliberate attacks against the fabric overlay network.

**Category:** Routing Security (VOSS)

**VOSS Module:** ISIS, SPBM

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Lookback: 24 hours for IS-IS and SPBM adjacency events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Key filter: match IS-IS adjacency state, SPF calculation, and SPBM events (no Facility filter for VOSS)
| where SyslogMessage has_any ("ISIS.AdjState", "ISIS.SPF", "SPBM")
// Further filter to state disruption keywords
| where SyslogMessage has_any ("Down", "down", "Lost", "lost", "Change", "change")
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

## Cross-Category: Comprehensive Security Dashboard Query

This single query surfaces all security-relevant events across all categories:

```kql
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
| where Facility == "local7"
| where SyslogMessage has_any (
    // Port Security
    "FDB.MacLocking", "FDB.LrnLimit", "FDB.MACTracking",
    // DHCP/ARP Security
    "ipSecur.dhcpViol", "ipSecur.arpViol", "ipSecur.blkPort", "ipSecur.blkMac", "ipSecur.drpPkt",
    "vlan.dad.IPAddrDup",
    // STP
    "STP.State.Topology", "STP.State.RootChg", "STP.InTopChg",
    // Authentication
    "AAA.authFail", "AAA.authPass", "exsshd.RejctConnAccessDeny", "exsshd.AuthFail",
    // Configuration
    "cm.SaveCfg", "cm.UseCfg", "ACL.Change", "ACL.bind", "ACL.unBind",
    // System Health
    "epm.ProcCrash", "dm.Error",
    // Loop/Storm/DoS
    "ELRP.Detect", "bwMgr.Critical", "dosprotect.Alert",
    // Routing
    "OSPF.NbrStateChg", "BGP.event", "ISIS.AdjState",
    // Link
    "PortLinkFlapActLogEvent"
  )
| parse SyslogMessage with * "<" SeverityAbbr ":" FullComponent ">" MessageBody
| extend Category = case(
    FullComponent has_any ("FDB.Mac", "FDB.Lrn"), "Port Security",
    FullComponent has "ipSecur" or FullComponent has "vlan.dad", "IP Security",
    FullComponent has "STP", "Spanning Tree",
    FullComponent has_any ("AAA", "exsshd", "thttpd"), "Authentication",
    FullComponent has_any ("cm.", "ACL", "CLI"), "Configuration",
    FullComponent has_any ("epm", "dm."), "System Health",
    FullComponent has_any ("ELRP", "bwMgr", "dosprotect"), "Threat Detection",
    FullComponent has_any ("OSPF", "BGP", "ISIS"), "Routing",
    FullComponent has_any ("vlan.msgs", "HAL.Port"), "Link Monitoring",
    "Other"
  )
| extend SeverityLevel = case(
    SeverityAbbr == "Crit", "Critical",
    SeverityAbbr == "Erro", "Error",
    SeverityAbbr == "Warn", "Warning",
    SeverityAbbr == "Noti", "Notice",
    "Informational"
  )
| project TimeGenerated, HostName, SeverityLevel, Category, FullComponent, MessageBody
| order by TimeGenerated desc
```
