# Firewall Traffic Patterns

Comprehensive firewall traffic analysis dashboard for Fortinet FortiGate and multi-vendor environments. Provides real-time visibility into session volumes, threat detections, application usage, VPN status, and bandwidth consumption using CommonSecurityLog data.

- **Traffic Overview** — Hero KPI tiles for total/allowed/blocked sessions, unique IPs, destinations, and data transferred
- **Traffic Action Distribution** — Pie chart breakdown of firewall actions (allow, deny, drop, etc.)
- **Hourly Traffic Volume** — Area chart of allowed vs blocked traffic over time
- **Top Blocked Sources with Sparkline** — Table with per-IP block counts, trend sparklines, and port targeting
- **IPS/UTM Detections** — Threat detection table with severity coloring for IPS, antivirus, web filter, and app control
- **Blocked Destinations Map** — Geographic heatmap of blocked destination IPs
- **Top Applications** — Bar chart of most active applications extracted from FortiGate logs
- **Application Risk Distribution** — Pie chart of application risk levels
- **Protocol Distribution** — Pie chart of network protocols by session count
- **Top Destination Ports** — Bar chart of most targeted ports for allowed traffic
- **VPN Tunnel Status** — Table of VPN tunnel up/down counts with last event timestamps
- **Admin Login Activity** — Table of administrator authentication events with success/failure status
- **Data Transfer by Source** — Table of top bandwidth consumers with heatmap visualization
- **Bandwidth Timeline** — Area chart of inbound vs outbound data transfer over time

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
        "json": "# Firewall Traffic Patterns\n---\nComprehensive firewall traffic analysis for Fortinet FortiGate and multi-vendor environments.\nSelect your Sentinel workspace and device vendor filter above to load data."
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
            "id": "param-vendor",
            "version": "KqlParameterItem/1.0",
            "name": "DeviceVendorFilter",
            "label": "Device Vendor",
            "type": 2,
            "isRequired": true,
            "jsonData": "[\"All\", \"Fortinet\", \"Palo Alto Networks\", \"Check Point\", \"Cisco\"]",
            "value": "All"
          }
        ]
      },
      "name": "parameters"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Traffic Overview\nReal-time session metrics across all monitored firewall appliances."
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
              "query": "let allowed_actions = dynamic(['accept','close','allow','pass','permit']);\nlet blocked_actions = dynamic(['deny','drop','block','reject','blocked']);\nCommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| summarize\n    TotalSessions = count(),\n    AllowedSessions = countif(tolower(DeviceAction) in (allowed_actions)),\n    BlockedSessions = countif(tolower(DeviceAction) in (blocked_actions)),\n    UniqueSourceIPs = dcount(SourceIP),\n    UniqueDestinations = dcount(DestinationIP),\n    TotalDataMB = round(sum(tolong(SentBytes) + tolong(ReceivedBytes)) / 1048576.0, 2)\n| project\n    Metric = pack_array('Total Sessions', 'Allowed Sessions', 'Blocked Sessions', 'Unique Source IPs', 'Unique Destinations', 'Total Data (MB)'),\n    Value = pack_array(TotalSessions, AllowedSessions, BlockedSessions, UniqueSourceIPs, UniqueDestinations, TotalDataMB)\n| mv-expand Metric to typeof(string), Value to typeof(real)",
              "size": 4,
              "title": "Hero KPI Tiles",
              "noDataMessage": "No firewall data found in the selected time range.",
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
                    { "operator": "contains", "value": "Blocked", "color": "#D13438" },
                    { "operator": "contains", "value": "Allowed", "color": "#107C10" },
                    { "operator": "contains", "value": "Total Sessions", "color": "#0078D4" },
                    { "operator": "contains", "value": "Unique Source", "color": "#0078D4" },
                    { "operator": "contains", "value": "Unique Destinations", "color": "#0078D4" },
                    { "operator": "contains", "value": "Total Data", "color": "#0078D4" },
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
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| summarize SessionCount = count() by DeviceAction\n| top 10 by SessionCount desc",
              "size": 3,
              "title": "Traffic Action Distribution",
              "noDataMessage": "No firewall action data found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "piechart"
            },
            "name": "traffic-action-pie"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "let allowed_actions = dynamic(['accept','close','allow','pass','permit']);\nlet blocked_actions = dynamic(['deny','drop','block','reject','blocked']);\nCommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| make-series\n    AllowedCount = countif(tolower(DeviceAction) in (allowed_actions)) default = 0,\n    BlockedCount = countif(tolower(DeviceAction) in (blocked_actions)) default = 0\n    on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h",
              "size": 1,
              "title": "Hourly Traffic Volume",
              "noDataMessage": "No traffic data found in the selected time range.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "areachart",
              "chartSettings": {
                "seriesLabelSettings": [
                  { "seriesName": "AllowedCount", "label": "Allowed", "color": "#107C10" },
                  { "seriesName": "BlockedCount", "label": "Blocked", "color": "#D13438" }
                ]
              }
            },
            "name": "hourly-traffic-area"
          }
        ]
      },
      "name": "group-traffic-overview"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Threat Analysis\nBlocked source intelligence, IPS/UTM detections, and geographic threat mapping."
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
              "query": "let blocked_actions = dynamic(['deny','drop','block','reject','blocked']);\nCommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where tolower(DeviceAction) in (blocked_actions)\n| summarize\n    BlockCount = count(),\n    PortsTargeted = dcount(DestinationPort),\n    Trend = make_list(bin(TimeGenerated, 1h))\n    by SourceIP\n| top 15 by BlockCount desc\n| project SourceIP, BlockCount, PortsTargeted, Trend",
              "size": 0,
              "title": "Top Blocked Sources with Sparkline",
              "noDataMessage": "No blocked sources found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "BlockCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "Trend",
                    "formatter": 9,
                    "formatOptions": { "palette": "redBright" }
                  },
                  {
                    "columnMatch": "PortsTargeted",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "blue" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "BlockCount", "sortOrder": 2 }]
              }
            },
            "name": "top-blocked-sources"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where Activity has_any ('ips', 'virus', 'webfilter', 'app-ctrl', 'dns', 'dlp')\n| extend\n    AttackName = extract(@'FTNTFGTattack=([^;]+)', 1, AdditionalExtensions),\n    ThreatLevel = extract(@'FTNTFGTseverity=([^;]+)', 1, AdditionalExtensions),\n    ControlLevel = extract(@'FTNTFGTcrlevel=([^;]+)', 1, AdditionalExtensions)\n| where isnotempty(AttackName)\n| summarize\n    HitCount = count(),\n    UniqueTargets = dcount(DestinationIP)\n    by AttackName, ThreatLevel\n| top 20 by HitCount desc\n| project AttackName, ThreatLevel, HitCount, UniqueTargets",
              "size": 0,
              "title": "IPS/UTM Detections",
              "noDataMessage": "No IPS/UTM detections found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "ThreatLevel",
                    "formatter": 18,
                    "formatOptions": {
                      "thresholdsOptions": "colors",
                      "thresholdsGrid": [
                        { "operator": "==", "thresholdValue": "critical", "representation": "redBright", "text": "Critical" },
                        { "operator": "==", "thresholdValue": "high", "representation": "orange", "text": "High" },
                        { "operator": "==", "thresholdValue": "medium", "representation": "yellow", "text": "Medium" },
                        { "operator": "==", "thresholdValue": "low", "representation": "blue", "text": "Low" },
                        { "operator": "Default", "representation": "gray", "text": "{0}" }
                      ]
                    }
                  },
                  {
                    "columnMatch": "HitCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "UniqueTargets",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "blue" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "HitCount", "sortOrder": 2 }]
              }
            },
            "name": "ips-utm-detections"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "let blocked_actions = dynamic(['deny','drop','block','reject','blocked']);\nCommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where tolower(DeviceAction) in (blocked_actions)\n| where isnotempty(DestinationIP)\n| extend GeoInfo = geo_info_from_ip_address(DestinationIP)\n| extend\n    Country = tostring(GeoInfo.country),\n    Latitude = toreal(GeoInfo.latitude),\n    Longitude = toreal(GeoInfo.longitude)\n| where isnotempty(Country)\n| summarize BlockCount = count() by Country, Latitude, Longitude",
              "size": 0,
              "title": "Blocked Destinations Map",
              "noDataMessage": "No geo-locatable blocked destinations found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "map",
              "mapSettings": {
                "locInfo": "LatLong",
                "latitude": "Latitude",
                "longitude": "Longitude",
                "sizeSettings": "BlockCount",
                "sizeAggregation": "Sum",
                "labelSettings": "Country",
                "legendMetric": "BlockCount",
                "legendAggregation": "Sum",
                "itemColorSettings": {
                  "nodeColorField": "BlockCount",
                  "colorAggregation": "Sum",
                  "type": "heatmap",
                  "heatmapPalette": "greenRed"
                }
              }
            },
            "name": "blocked-destinations-map"
          }
        ]
      },
      "name": "group-threat-analysis"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Application & Protocol Intelligence\nApplication visibility, risk classification, protocol breakdown, and port analysis."
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
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| extend AppName = extract(@'FTNTFGTapp=([^;]+)', 1, AdditionalExtensions)\n| where isnotempty(AppName)\n| summarize SessionCount = count() by AppName\n| top 15 by SessionCount desc",
              "size": 1,
              "title": "Top Applications",
              "noDataMessage": "No application data found. FortiGate logs required.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "barchart",
              "chartSettings": {
                "xAxis": "AppName",
                "yAxis": ["SessionCount"]
              }
            },
            "name": "top-applications-bar"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| extend AppRisk = extract(@'FTNTFGTapprisk=([^;]+)', 1, AdditionalExtensions)\n| where isnotempty(AppRisk)\n| summarize SessionCount = count() by AppRisk\n| order by SessionCount desc",
              "size": 3,
              "title": "Application Risk Distribution",
              "noDataMessage": "No application risk data found. FortiGate logs required.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "piechart"
            },
            "name": "app-risk-pie"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where isnotempty(ApplicationProtocol)\n| summarize SessionCount = count() by ApplicationProtocol\n| top 10 by SessionCount desc",
              "size": 3,
              "title": "Protocol Distribution",
              "noDataMessage": "No protocol data found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "piechart"
            },
            "name": "protocol-dist-pie"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "let allowed_actions = dynamic(['accept','close','allow','pass','permit']);\nCommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where tolower(DeviceAction) in (allowed_actions)\n| where isnotempty(DestinationPort)\n| summarize SessionCount = count() by tostring(DestinationPort)\n| top 15 by SessionCount desc",
              "size": 1,
              "title": "Top Destination Ports (Allowed Traffic)",
              "noDataMessage": "No destination port data found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "barchart",
              "chartSettings": {
                "xAxis": "DestinationPort",
                "yAxis": ["SessionCount"]
              }
            },
            "name": "top-dest-ports-bar"
          }
        ]
      },
      "name": "group-app-protocol"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## VPN & Admin Activity\nVPN tunnel health monitoring and administrator authentication tracking."
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
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where Activity has 'vpn'\n| where DeviceAction in ('tunnel-up', 'tunnel-down')\n| extend\n    VPNTunnel = extract(@'FTNTFGTvpntunnel=([^;]+)', 1, AdditionalExtensions),\n    TunnelType = extract(@'FTNTFGTtunneltype=([^;]+)', 1, AdditionalExtensions)\n| where isnotempty(VPNTunnel)\n| summarize\n    UpCount = countif(DeviceAction == 'tunnel-up'),\n    DownCount = countif(DeviceAction == 'tunnel-down'),\n    LastEvent = max(TimeGenerated)\n    by VPNTunnel, TunnelType\n| project VPNTunnel, TunnelType, UpCount, DownCount, LastEvent\n| order by DownCount desc",
              "size": 0,
              "title": "VPN Tunnel Status",
              "noDataMessage": "No VPN tunnel events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "UpCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "green" }
                  },
                  {
                    "columnMatch": "DownCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "LastEvent",
                    "formatter": 6
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "DownCount", "sortOrder": 2 }]
              }
            },
            "name": "vpn-tunnel-status"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where DeviceEventClassID in ('32001', '32002', '0100032001', '0100032002')\n| extend LoginResult = iff(DeviceEventClassID in ('32001', '0100032001'), 'Success', 'Failure')\n| summarize\n    EventCount = count(),\n    LastAttempt = max(TimeGenerated)\n    by SourceIP, DestinationUserName, LoginResult, DeviceName\n| project SourceIP, DestinationUserName, LoginResult, DeviceName, EventCount, LastAttempt\n| order by EventCount desc",
              "size": 0,
              "title": "Admin Login Activity",
              "noDataMessage": "No admin login events found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "LoginResult",
                    "formatter": 18,
                    "formatOptions": {
                      "thresholdsOptions": "colors",
                      "thresholdsGrid": [
                        { "operator": "==", "thresholdValue": "Success", "representation": "green", "text": "Success" },
                        { "operator": "==", "thresholdValue": "Failure", "representation": "redBright", "text": "Failure" },
                        { "operator": "Default", "representation": "gray", "text": "{0}" }
                      ]
                    }
                  },
                  {
                    "columnMatch": "EventCount",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "LastAttempt",
                    "formatter": 6
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "EventCount", "sortOrder": 2 }]
              }
            },
            "name": "admin-login-activity"
          }
        ]
      },
      "name": "group-vpn-admin"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Bandwidth & Performance\nData transfer analysis by source IP and inbound/outbound bandwidth trends."
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
              "query": "let allowed_actions = dynamic(['accept','close','allow','pass','permit']);\nCommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| where tolower(DeviceAction) in (allowed_actions)\n| summarize\n    TotalMB = round(sum(tolong(SentBytes) + tolong(ReceivedBytes)) / 1048576.0, 2),\n    SentMB = round(sum(tolong(SentBytes)) / 1048576.0, 2),\n    ReceivedMB = round(sum(tolong(ReceivedBytes)) / 1048576.0, 2),\n    Sessions = count()\n    by SourceIP\n| top 15 by TotalMB desc\n| project SourceIP, TotalMB, SentMB, ReceivedMB, Sessions",
              "size": 0,
              "title": "Data Transfer by Source",
              "noDataMessage": "No data transfer records found.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "table",
              "gridSettings": {
                "formatters": [
                  {
                    "columnMatch": "TotalMB",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
                  },
                  {
                    "columnMatch": "SentMB",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "orange" }
                  },
                  {
                    "columnMatch": "ReceivedMB",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "blue" }
                  },
                  {
                    "columnMatch": "Sessions",
                    "formatter": 8,
                    "formatOptions": { "min": 0, "palette": "green" }
                  }
                ],
                "filter": true,
                "sortBy": [{ "itemKey": "TotalMB", "sortOrder": 2 }]
              }
            },
            "name": "data-transfer-table"
          },
          {
            "type": 3,
            "content": {
              "version": "KqlItem/1.0",
              "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where '*' == '{DeviceVendorFilter}' or DeviceVendor == '{DeviceVendorFilter}'\n| make-series\n    InboundMB = round(sum(tolong(ReceivedBytes)) / 1048576.0, 2) default = 0,\n    OutboundMB = round(sum(tolong(SentBytes)) / 1048576.0, 2) default = 0\n    on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h",
              "size": 1,
              "title": "Bandwidth Timeline",
              "noDataMessage": "No bandwidth data found in the selected time range.",
              "queryType": 0,
              "resourceType": "microsoft.operationalinsights/workspaces",
              "crossComponentResources": ["{Workspace}"],
              "visualization": "areachart",
              "chartSettings": {
                "seriesLabelSettings": [
                  { "seriesName": "InboundMB", "label": "Inbound (MB)", "color": "#0078D4" },
                  { "seriesName": "OutboundMB", "label": "Outbound (MB)", "color": "#F7630C" }
                ]
              }
            },
            "name": "bandwidth-timeline-area"
          }
        ]
      },
      "name": "group-bandwidth"
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
5. Select your **Subscription**, **Workspace**, and **Device Vendor** from the dropdowns at the top

---

## Permissions Required

Microsoft Sentinel Reader (or higher) on the workspace. CommonSecurityLog data requires a CEF/Syslog data connector configured for the firewall appliance(s).
