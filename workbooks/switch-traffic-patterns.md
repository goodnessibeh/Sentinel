# Switch Traffic Patterns

Comprehensive Extreme Networks switch monitoring dashboard with Layer 2/3 security visibility. Provides real-time analysis of port security violations, spanning tree events, authentication activity, configuration changes, and link health using Syslog data from Extreme switches (Facility local7).

- **Switch Health Overview** — Hero KPI tiles for total events, critical/error counts, warnings, security violations, and authentication events
- **Event Severity Timeline** — Area chart of event severity distribution over time
- **Events by Switch** — Bar chart of top 20 switches by event volume
- **Port Security Violations with Sparkline** — Table with per-switch violation counts, trend sparklines, and violation types
- **DHCP Snooping Violations** — Table of DHCP snooping violations with port and MAC details
- **ARP Inspection Violations** — Table of ARP/DAI violations with IP and MAC extraction
- **MAC Address Movement** — Table of suspicious MAC address flapping across ports
- **STP Topology Changes** — Time chart of spanning tree topology change notifications
- **STP Events by Switch** — Table with TCN counts and root changes per switch
- **Loop & Storm Events** — Table of ELRP loop detections and bandwidth storm events
- **Login Activity Summary** — Tiles for successful/failed logins, SSH rejections, and config changes
- **Failed Login Sources** — Table of top failed login source IPs with heatmap
- **Authentication Timeline** — Time chart of authentication success vs failure over time
- **Configuration Changes Timeline** — Time chart of configuration save and CLI command events
- **Security Feature Changes** — Table of critical security configuration modifications with threshold coloring
- **Config Changes by Switch** — Bar chart of configuration events per switch
- **Port Flap Events** — Table of port link flap events with heatmap
- **LLDP Neighbor Changes** — Table of LLDP neighbor additions and removals with threshold coloring
- **Routing Protocol Events** — Table of OSPF, BGP, and ISIS adjacency events

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

---

## Workbook JSON — Paste into Code Editor (`</>`)

```json
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1,
      "content": {
        "json": "# Switch Traffic Patterns\n---\nComprehensive Extreme Networks switch monitoring with Layer 2/3 security visibility.\nSelect your Sentinel workspace and switch filter above to load data."
      },
      "name": "title"
    },
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "param-sub",
            "version": "KqlParameterItem/1.0",
            "name": "Subscription",
            "label": "Subscription",
            "type": 6,
            "isRequired": true,
            "typeSettings": {
              "additionalResourceOptions": [],
              "includeAll": false
            }
          },
          {
            "id": "param-workspace",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "label": "Workspace",
            "type": 5,
            "isRequired": true,
            "query": "resources\n| where type == 'microsoft.operationalinsights/workspaces'\n| project id",
            "crossComponentResources": ["{Subscription}"],
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": []
            },
            "queryType": 1,
            "resourceType": "microsoft.resourcegraph/resources"
          },
          {
            "id": "param-timerange",
            "version": "KqlParameterItem/1.0",
            "name": "TimeRange",
            "label": "Time Range",
            "type": 4,
            "isRequired": true,
            "typeSettings": {
              "selectableValues": [
                { "durationMs": 3600000 },
                { "durationMs": 14400000 },
                { "durationMs": 43200000 },
                { "durationMs": 86400000 },
                { "durationMs": 259200000 },
                { "durationMs": 604800000 },
                { "durationMs": 1209600000 },
                { "durationMs": 2592000000 }
              ],
              "allowCustom": true
            },
            "value": { "durationMs": 86400000 }
          },
          {
            "id": "param-switch",
            "version": "KqlParameterItem/1.0",
            "name": "SwitchFilter",
            "label": "Switch",
            "type": 2,
            "isRequired": true,
            "query": "Syslog\n| where Facility == \"local7\"\n| distinct HostName\n| order by HostName asc",
            "crossComponentResources": ["{Workspace}"],
            "typeSettings": {
              "additionalResourceOptions": ["value::all"],
              "showDefault": false
            },
            "defaultValue": "value::all",
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "value": "All"
          }
        ]
      },
      "name": "parameters"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Switch Health Overview\nReal-time event metrics across all monitored Extreme Networks switches."
      },
      "name": "group1-header"
    },
    {
      "type": 12,
      "content": {
        "version": "NotebookGroup/1.0",
        "groupType": "editable",
        "items": [
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| summarize\n    TotalEvents = count(),\n    CriticalErrorEvents = countif(SyslogMessage has_any (\"<Crit:\", \"<Erro:\")),\n    WarningEvents = countif(SyslogMessage has \"<Warn:\"),\n    SecurityViolations = countif(SyslogMessage has_any (\"ipSecur\", \"FDB.MacLocking\", \"FDB.LrnLimit\")),\n    AuthenticationEvents = countif(SyslogMessage has_any (\"AAA.authPass\", \"AAA.authFail\"))\n| project\n    Metric = pack_array('Total Events', 'Critical/Error Events', 'Warning Events', 'Security Violations', 'Authentication Events'),\n    Value = pack_array(TotalEvents, CriticalErrorEvents, WarningEvents, SecurityViolations, AuthenticationEvents)\n| mv-expand Metric to typeof(string), Value to typeof(real)",
              "size": 4,
              "title": "Hero KPI Tiles",
              "noDataMessage": "No switch data found in the selected time range.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "tiles",
              "tileSettings": {
                "titleContent": { "columnMatch": "Metric", "formatter": 1 },
                "leftContent": {
                  "columnMatch": "Value",
                  "formatter": 12,
                  "formatOptions": { "palette": "auto" },
                  "numberFormat": { "unit": 17, "options": { "maximumSignificantDigits": 4 } }
                },
                "showBorder": true,
                "colorSettings": {
                  "colorConditions": [
                    { "operator": "contains", "value": "Critical/Error", "color": "#D13438" },
                    { "operator": "contains", "value": "Warning", "color": "#F7630C" },
                    { "operator": "contains", "value": "Security Violations", "color": "#D13438" },
                    { "operator": "contains", "value": "Authentication", "color": "#0078D4" },
                    { "operator": "contains", "value": "Total Events", "color": "#0078D4" },
                    { "operator": "Default", "color": "#004578" }
                  ],
                  "rowColoring": "Metric"
                }
              }
            },
            "name": "hero-kpi-tiles"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| extend SeverityBucket = case(\n    SyslogMessage has \"<Crit:\", \"Critical\",\n    SyslogMessage has \"<Erro:\", \"Error\",\n    SyslogMessage has \"<Warn:\", \"Warning\",\n    SyslogMessage has \"<Noti:\", \"Notice\",\n    \"Info\")\n| make-series\n    EventCount = count() default = 0\n    on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h\n    by SeverityBucket",
              "size": 1,
              "title": "Event Severity Timeline",
              "noDataMessage": "No severity data found in the selected time range.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "areachart",
              "chartSettings": {
                "seriesLabelSettings": [
                  { "seriesName": "Critical", "label": "Critical", "color": "#D13438" },
                  { "seriesName": "Error", "label": "Error", "color": "#F7630C" },
                  { "seriesName": "Warning", "label": "Warning", "color": "#FFC300" },
                  { "seriesName": "Notice", "label": "Notice", "color": "#0078D4" },
                  { "seriesName": "Info", "label": "Info", "color": "#107C10" }
                ]
              }
            },
            "name": "event-severity-timeline"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| summarize EventCount = count() by HostName\n| top 20 by EventCount desc",
              "size": 1,
              "title": "Events by Switch",
              "noDataMessage": "No switch event data found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "barchart",
              "chartSettings": {
                "xAxis": "HostName",
                "yAxis": ["EventCount"]
              }
            },
            "name": "events-by-switch-bar"
          }
        ]
      },
      "name": "group-switch-health"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Port Security & Layer 2 Threats\nMAC locking violations, DHCP snooping, ARP inspection, and MAC address movement tracking."
      },
      "name": "group2-header"
    },
    {
      "type": 12,
      "content": {
        "version": "NotebookGroup/1.0",
        "groupType": "editable",
        "items": [
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"FDB.MacLocking\", \"FDB.LrnLimit\", \"FDB.MACTracking\")\n| extend Component = extract(@\"<[^>]+>\\s+\\S+\\s+(\\S+)\", 1, SyslogMessage)\n| summarize\n    ViolationCount = count(),\n    Trend = make_list(bin(TimeGenerated, 1h)),\n    Types = make_set(Component)\n    by HostName\n| top 15 by ViolationCount desc\n| project HostName, ViolationCount, Trend, Types",
              "size": 0,
              "title": "Port Security Violations with Sparkline",
              "noDataMessage": "No port security violations found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "ViolationCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "Trend",
                    "formatter": 9,
                    "formatOptions": { "palette": "redBright" }
                  },
                  {
                    "columnMatch": "Types",
                    "formatter": 1
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "ViolationCount", "sortOrder": 2 }]
              }
            },
            "name": "port-security-violations"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has \"ipSecur.dhcpViol\"\n| extend\n    Port = extract(@\"port\\s+(\\S+)\", 1, SyslogMessage),\n    VLANName = extract(@\"vlan\\s+(\\S+)\", 1, SyslogMessage),\n    SourceMAC = extract(@\"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\", 1, SyslogMessage)\n| summarize\n    Count = count(),\n    Ports = make_set(Port),\n    MACs = make_set(SourceMAC)\n    by HostName\n| order by Count desc\n| project HostName, Count, Ports, MACs",
              "size": 0,
              "title": "DHCP Snooping Violations",
              "noDataMessage": "No DHCP snooping violations found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "Count",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "Ports",
                    "formatter": 1
                  },
                  {
                    "columnMatch": "MACs",
                    "formatter": 1
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
              }
            },
            "name": "dhcp-snooping-violations"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"ipSecur.arpViol\", \"vlan.dad.IPAddrDup\")\n| extend\n    IPAddress = extract(@\"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage),\n    MACAddress = extract(@\"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\", 1, SyslogMessage)\n| summarize\n    Count = count()\n    by HostName, IPAddress, MACAddress\n| order by Count desc\n| project HostName, IPAddress, MACAddress, Count",
              "size": 0,
              "title": "ARP Inspection Violations",
              "noDataMessage": "No ARP inspection violations found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "Count",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
              }
            },
            "name": "arp-inspection-violations"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has \"FDB.MACTracking\"\n| extend\n    MACAddress = extract(@\"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\", 1, SyslogMessage),\n    FromPort = extract(@\"from port\\s+(\\S+)\", 1, SyslogMessage),\n    ToPort = extract(@\"to port\\s+(\\S+)\", 1, SyslogMessage),\n    VLAN = extract(@\"vlan\\s+(\\S+)\", 1, SyslogMessage)\n| summarize\n    MoveCount = count()\n    by HostName, MACAddress, VLAN\n| where MoveCount > 2\n| order by MoveCount desc\n| project HostName, MACAddress, VLAN, MoveCount",
              "size": 0,
              "title": "MAC Address Movement",
              "noDataMessage": "No suspicious MAC address movement detected (threshold: >2 moves).",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "MoveCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "MoveCount", "sortOrder": 2 }]
              }
            },
            "name": "mac-address-movement"
          }
        ]
      },
      "name": "group-port-security"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Spanning Tree & Loop Protection\nSTP topology changes, root bridge elections, and loop/storm detection events."
      },
      "name": "group3-header"
    },
    {
      "type": 12,
      "content": {
        "version": "NotebookGroup/1.0",
        "groupType": "editable",
        "items": [
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"STP.State.Topology\", \"STP.InTopChg\", \"STP.State.RootChg\")\n| make-series\n    EventCount = count() default = 0\n    on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h",
              "size": 1,
              "title": "STP Topology Changes",
              "noDataMessage": "No STP topology change events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "timechart",
              "chartSettings": {
                "seriesLabelSettings": [
                  { "seriesName": "EventCount", "label": "Topology Changes", "color": "#F7630C" }
                ]
              }
            },
            "name": "stp-topology-changes"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"STP.State.Topology\", \"STP.InTopChg\", \"STP.State.RootChg\")\n| summarize\n    TCNCount = count(),\n    RootChanges = countif(SyslogMessage has \"RootChg\")\n    by HostName\n| order by TCNCount desc\n| project HostName, TCNCount, RootChanges",
              "size": 0,
              "title": "STP Events by Switch",
              "noDataMessage": "No STP events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "TCNCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "RootChanges",
                    "formatter": 18,
                    "formatOptions": {
                      "thresholdsOptions": "colors",
                      "thresholdsGrid": [
                        { "operator": ">", "thresholdValue": "0", "representation": "redBright", "text": "{0}" },
                        { "operator": "Default", "representation": "green", "text": "{0}" }
                      ]
                    }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "TCNCount", "sortOrder": 2 }]
              }
            },
            "name": "stp-events-by-switch"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"ELRP.Detect\", \"ELRP.Action\", \"bwMgr.Warning\", \"bwMgr.Critical\")\n| extend\n    Severity = case(\n        SyslogMessage has \"<Crit:\", \"Critical\",\n        SyslogMessage has \"<Erro:\", \"Error\",\n        SyslogMessage has \"<Warn:\", \"Warning\",\n        \"Info\"),\n    Component = case(\n        SyslogMessage has \"ELRP.Detect\", \"ELRP.Detect\",\n        SyslogMessage has \"ELRP.Action\", \"ELRP.Action\",\n        SyslogMessage has \"bwMgr.Warning\", \"bwMgr.Warning\",\n        SyslogMessage has \"bwMgr.Critical\", \"bwMgr.Critical\",\n        \"Unknown\")\n| project TimeGenerated, HostName, Severity, Component, SyslogMessage\n| order by TimeGenerated desc\n| take 100",
              "size": 0,
              "title": "Loop & Storm Events",
              "noDataMessage": "No loop or storm events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "Severity",
                    "formatter": 18,
                    "formatOptions": {
                      "thresholdsOptions": "colors",
                      "thresholdsGrid": [
                        { "operator": "==", "thresholdValue": "Critical", "representation": "redBright", "text": "Critical" },
                        { "operator": "==", "thresholdValue": "Error", "representation": "orange", "text": "Error" },
                        { "operator": "==", "thresholdValue": "Warning", "representation": "yellow", "text": "Warning" },
                        { "operator": "Default", "representation": "blue", "text": "{0}" }
                      ]
                    }
                  },
                  {
                    "columnMatch": "TimeGenerated",
                    "formatter": 6
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "TimeGenerated", "sortOrder": 2 }]
              }
            },
            "name": "loop-storm-events"
          }
        ]
      },
      "name": "group-stp-loop"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Authentication & Access Control\nLogin activity, failed authentication sources, and SSH rejection monitoring."
      },
      "name": "group4-header"
    },
    {
      "type": 12,
      "content": {
        "version": "NotebookGroup/1.0",
        "groupType": "editable",
        "items": [
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| summarize\n    SuccessfulLogins = countif(SyslogMessage has \"AAA.authPass\"),\n    FailedLogins = countif(SyslogMessage has \"AAA.authFail\"),\n    SSHRejections = countif(SyslogMessage has_any (\"exsshd.RejctConnAccessDeny\", \"exsshd.AuthFail\")),\n    ConfigChanges = countif(SyslogMessage has_any (\"cm.SaveCfg\", \"cm.UseCfg\"))\n| project\n    Metric = pack_array('Successful Logins', 'Failed Logins', 'SSH Rejections', 'Config Changes'),\n    Value = pack_array(SuccessfulLogins, FailedLogins, SSHRejections, ConfigChanges)\n| mv-expand Metric to typeof(string), Value to typeof(real)",
              "size": 4,
              "title": "Login Activity Summary",
              "noDataMessage": "No authentication data found in the selected time range.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "tiles",
              "tileSettings": {
                "titleContent": { "columnMatch": "Metric", "formatter": 1 },
                "leftContent": {
                  "columnMatch": "Value",
                  "formatter": 12,
                  "formatOptions": { "palette": "auto" },
                  "numberFormat": { "unit": 17, "options": { "maximumSignificantDigits": 4 } }
                },
                "showBorder": true,
                "colorSettings": {
                  "colorConditions": [
                    { "operator": "contains", "value": "Failed Logins", "color": "#D13438" },
                    { "operator": "contains", "value": "SSH Rejections", "color": "#F7630C" },
                    { "operator": "contains", "value": "Successful Logins", "color": "#0078D4" },
                    { "operator": "contains", "value": "Config Changes", "color": "#0078D4" },
                    { "operator": "Default", "color": "#004578" }
                  ],
                  "rowColoring": "Metric"
                }
              }
            },
            "name": "login-activity-tiles"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has \"AAA.authFail\"\n| extend\n    User = extract(@\"user\\s+(\\S+)\", 1, SyslogMessage),\n    SourceIP = extract(@\"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage)\n| summarize\n    FailCount = count(),\n    Users = make_set(User),\n    Switches = make_set(HostName)\n    by SourceIP\n| top 15 by FailCount desc\n| project SourceIP, FailCount, Users, Switches",
              "size": 0,
              "title": "Failed Login Sources",
              "noDataMessage": "No failed login sources found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "FailCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "Users",
                    "formatter": 1
                  },
                  {
                    "columnMatch": "Switches",
                    "formatter": 1
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "FailCount", "sortOrder": 2 }]
              }
            },
            "name": "failed-login-sources"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"AAA.authPass\", \"AAA.authFail\")\n| extend Result = iff(SyslogMessage has \"authPass\", \"Success\", \"Failure\")\n| make-series\n    EventCount = count() default = 0\n    on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h\n    by Result",
              "size": 1,
              "title": "Authentication Timeline",
              "noDataMessage": "No authentication events found in the selected time range.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "timechart",
              "chartSettings": {
                "seriesLabelSettings": [
                  { "seriesName": "Success", "label": "Success", "color": "#107C10" },
                  { "seriesName": "Failure", "label": "Failure", "color": "#D13438" }
                ]
              }
            },
            "name": "authentication-timeline"
          }
        ]
      },
      "name": "group-auth-access"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Configuration Change Audit\nConfiguration save/load events, security feature modifications, and CLI command tracking."
      },
      "name": "group5-header"
    },
    {
      "type": 12,
      "content": {
        "version": "NotebookGroup/1.0",
        "groupType": "editable",
        "items": [
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"cm.SaveCfg\", \"cm.UseCfg\", \"CLI.logRemoteCmd\", \"CLI.logLocalCmd\")\n| make-series\n    EventCount = count() default = 0\n    on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d",
              "size": 1,
              "title": "Configuration Changes Timeline",
              "noDataMessage": "No configuration change events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "timechart",
              "chartSettings": {
                "seriesLabelSettings": [
                  { "seriesName": "EventCount", "label": "Config Changes", "color": "#0078D4" }
                ]
              }
            },
            "name": "config-changes-timeline"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"CLI.logRemoteCmd\", \"CLI.logLocalCmd\")\n| where SyslogMessage has_any (\"dhcp-snooping\", \"mirror\", \"port-mirror\", \"stpd\", \"spanning-tree\", \"acl\", \"access-list\")\n| extend ChangeType = case(\n    SyslogMessage has \"dhcp-snooping\", \"DHCP Snooping\",\n    SyslogMessage has \"mirror\", \"Port Mirroring\",\n    SyslogMessage has \"stpd\" or SyslogMessage has \"spanning-tree\", \"STP\",\n    SyslogMessage has \"acl\" or SyslogMessage has \"access-list\", \"ACL/Policy\",\n    \"Other\")\n| project TimeGenerated, HostName, ChangeType, SyslogMessage\n| order by TimeGenerated desc",
              "size": 0,
              "title": "Security Feature Changes",
              "noDataMessage": "No security feature changes found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "ChangeType",
                    "formatter": 18,
                    "formatOptions": {
                      "thresholdsOptions": "colors",
                      "thresholdsGrid": [
                        { "operator": "==", "thresholdValue": "Port Mirroring", "representation": "redBright", "text": "Port Mirroring" },
                        { "operator": "==", "thresholdValue": "DHCP Snooping", "representation": "redBright", "text": "DHCP Snooping" },
                        { "operator": "==", "thresholdValue": "STP", "representation": "orange", "text": "STP" },
                        { "operator": "==", "thresholdValue": "ACL/Policy", "representation": "yellow", "text": "ACL/Policy" },
                        { "operator": "Default", "representation": "blue", "text": "{0}" }
                      ]
                    }
                  },
                  {
                    "columnMatch": "TimeGenerated",
                    "formatter": 6
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "TimeGenerated", "sortOrder": 2 }]
              }
            },
            "name": "security-feature-changes"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"cm.SaveCfg\", \"cm.UseCfg\", \"CLI.logRemoteCmd\", \"CLI.logLocalCmd\")\n| summarize EventCount = count() by HostName\n| top 15 by EventCount desc",
              "size": 1,
              "title": "Config Changes by Switch",
              "noDataMessage": "No configuration change data found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "barchart",
              "chartSettings": {
                "xAxis": "HostName",
                "yAxis": ["EventCount"]
              }
            },
            "name": "config-changes-by-switch"
          }
        ]
      },
      "name": "group-config-audit"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Link & Neighbor Monitoring\nPort flap detection, LLDP neighbor changes, and routing protocol adjacency events."
      },
      "name": "group6-header"
    },
    {
      "type": 12,
      "content": {
        "version": "NotebookGroup/1.0",
        "groupType": "editable",
        "items": [
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has \"PortLinkFlapActLogEvent\"\n| extend\n    Port = extract(@\"port\\s+(\\S+)\", 1, SyslogMessage),\n    Status = extract(@\"(up|down)\", 1, SyslogMessage)\n| summarize\n    FlapCount = count()\n    by HostName, Port\n| order by FlapCount desc\n| project HostName, Port, FlapCount",
              "size": 0,
              "title": "Port Flap Events",
              "noDataMessage": "No port flap events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "FlapCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "FlapCount", "sortOrder": 2 }]
              }
            },
            "name": "port-flap-events"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"LLDP.NbrAdd\", \"LLDP.NbrRemove\")\n| extend\n    EventType = iff(SyslogMessage has \"NbrAdd\", \"New Neighbor\", \"Neighbor Lost\"),\n    Port = extract(@\"port\\s+(\\S+)\", 1, SyslogMessage)\n| summarize\n    Count = count()\n    by HostName, EventType\n| order by Count desc\n| project HostName, EventType, Count",
              "size": 0,
              "title": "LLDP Neighbor Changes",
              "noDataMessage": "No LLDP neighbor change events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "EventType",
                    "formatter": 18,
                    "formatOptions": {
                      "thresholdsOptions": "colors",
                      "thresholdsGrid": [
                        { "operator": "==", "thresholdValue": "Neighbor Lost", "representation": "redBright", "text": "Neighbor Lost" },
                        { "operator": "==", "thresholdValue": "New Neighbor", "representation": "green", "text": "New Neighbor" },
                        { "operator": "Default", "representation": "blue", "text": "{0}" }
                      ]
                    }
                  },
                  {
                    "columnMatch": "Count",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "blue" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
              }
            },
            "name": "lldp-neighbor-changes"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "Syslog\n| where TimeGenerated {TimeRange}\n| where Facility == \"local7\"\n| where '*' == '{SwitchFilter}' or HostName == '{SwitchFilter}'\n| where SyslogMessage has_any (\"OSPF.NbrStateChg\", \"BGP.event\", \"ISIS.AdjState\")\n| extend Component = case(\n    SyslogMessage has \"OSPF.NbrStateChg\", \"OSPF\",\n    SyslogMessage has \"BGP.event\", \"BGP\",\n    SyslogMessage has \"ISIS.AdjState\", \"IS-IS\",\n    \"Unknown\")\n| summarize\n    Count = count()\n    by HostName, Component\n| order by Count desc\n| project HostName, Component, Count",
              "size": 0,
              "title": "Routing Protocol Events",
              "noDataMessage": "No routing protocol events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "Count",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
              }
            },
            "name": "routing-protocol-events"
          }
        ]
      },
      "name": "group-link-neighbor"
    }
  ],
  "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
```

---

## How to Deploy

1. **Sentinel > Workbooks > + Add workbook**
2. Click the **`</>`** (code editor) icon
3. Delete all existing JSON, paste the block above
4. Click **Apply** then **Save**
5. Select your **Subscription**, **Workspace**, and **Switch** filter from the dropdowns at the top

---

## Permissions Required

Microsoft Sentinel Reader (or higher) on the workspace. Syslog data requires a Syslog data connector configured for the Extreme Networks switch appliances with Facility local7 forwarding enabled.
