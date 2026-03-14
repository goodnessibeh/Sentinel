# Network Security Dashboard

Firewall and network traffic analysis for Microsoft Sentinel. Provides blocked traffic KPIs, DNS anomalies, geographic source mapping, protocol distribution, and firewall rule hit analysis.

- **KPI Tiles** — Total blocked connections, unique source IPs, unique destination ports, total allowed connections
- **Blocked Traffic Trend** — Hourly area chart of denied/dropped/blocked/rejected connections
- **Top Blocked Source IPs** — Bar chart of the 20 most-blocked source addresses
- **Top Targeted Destination Ports** — Bar chart of the 15 most-targeted ports in blocked traffic
- **Traffic by Protocol** — Pie chart of application protocol distribution
- **Geographic Source Map** — Geo-map of blocked traffic origins with heatmap coloring
- **Network Traffic Volume** — Hourly inbound vs outbound traffic volume in MB
- **Top Firewall Rules Hit** — Table of most-triggered firewall policy rules with block ratios

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
        "json": "# Network Security Dashboard\n---\nFirewall and network traffic analysis.\nSelect your Sentinel workspace above to load data."
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
                { "durationMs": 86400000 },
                { "durationMs": 259200000 },
                { "durationMs": 604800000 },
                { "durationMs": 1209600000 },
                { "durationMs": 2592000000 },
                { "durationMs": 5184000000 },
                { "durationMs": 7776000000 }
              ],
              "allowCustom": true
            },
            "value": { "durationMs": 2592000000 }
          }
        ]
      },
      "name": "parameters"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Network Security KPIs\nKey firewall and traffic metrics at a glance."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let blocked = CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where DeviceAction in ('Deny', 'Drop', 'Block', 'Reject', 'deny', 'drop', 'block', 'reject')\n| summarize TotalBlocked = count();\nlet allowed = CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where DeviceAction in ('Accept', 'Close', 'Allow', 'accept', 'close', 'allow')\n| summarize TotalAllowed = count();\nlet srcIPs = CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| summarize UniqueSourceIPs = dcount(SourceIP);\nlet dstPorts = CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| summarize UniqueDestPorts = dcount(DestinationPort);\nblocked\n| extend Metric = 'Total Blocked', Value = TotalBlocked\n| project Metric, Value\n| union (\n    srcIPs\n    | extend Metric = 'Unique Source IPs', Value = UniqueSourceIPs\n    | project Metric, Value\n)\n| union (\n    dstPorts\n    | extend Metric = 'Unique Dest Ports', Value = UniqueDestPorts\n    | project Metric, Value\n)\n| union (\n    allowed\n    | extend Metric = 'Total Allowed', Value = TotalAllowed\n    | project Metric, Value\n)",
        "size": 4,
        "title": "Network Security KPIs",
        "noDataMessage": "No CommonSecurityLog data found.",
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
              { "operator": "contains", "value": "Source IPs", "color": "#F7630C" },
              { "operator": "contains", "value": "Dest Ports", "color": "#0078D4" },
              { "operator": "contains", "value": "Allowed", "color": "#107C10" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Metric"
          }
        }
      },
      "name": "network-kpi-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Blocked Traffic Trend\nHourly count of denied, dropped, blocked, and rejected connections."
      },
      "name": "blocked-trend-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where DeviceAction in ('Deny', 'Drop', 'Block', 'Reject', 'deny', 'drop', 'block', 'reject')\n| make-series BlockCount = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h",
        "size": 1,
        "title": "Blocked Traffic Trend",
        "noDataMessage": "No blocked traffic found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "blocked-traffic-trend"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top 20 Blocked Source IPs\nMost frequently blocked source addresses."
      },
      "name": "top-blocked-ips-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where DeviceAction in ('Deny', 'Drop', 'Block', 'Reject', 'deny', 'drop', 'block', 'reject')\n| summarize BlockCount = count() by SourceIP\n| top 20 by BlockCount desc",
        "size": 1,
        "title": "Top 20 Blocked Source IPs",
        "noDataMessage": "No blocked source IPs found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "top-blocked-source-ips"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top 15 Targeted Destination Ports\nMost frequently targeted ports in blocked traffic."
      },
      "name": "top-dest-ports-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where DeviceAction in ('Deny', 'Drop', 'Block', 'Reject', 'deny', 'drop', 'block', 'reject')\n| summarize HitCount = count() by tostring(DestinationPort)\n| top 15 by HitCount desc",
        "size": 1,
        "title": "Top 15 Targeted Destination Ports",
        "noDataMessage": "No blocked destination port data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "top-targeted-dest-ports"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Traffic by Protocol\nApplication protocol distribution across all firewall traffic."
      },
      "name": "protocol-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| summarize ConnectionCount = count() by ApplicationProtocol\n| top 10 by ConnectionCount desc",
        "size": 3,
        "title": "Traffic by Protocol",
        "noDataMessage": "No protocol data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "traffic-by-protocol"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Geographic Source Map — Blocked Traffic\nOrigin countries of blocked connections with heatmap intensity."
      },
      "name": "geo-map-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where DeviceAction in ('Deny', 'Drop', 'Block', 'Reject', 'deny', 'drop', 'block', 'reject')\n| where isnotempty(SourceIP)\n| extend GeoInfo = geo_info_from_ip_address(SourceIP)\n| extend Country = tostring(GeoInfo.country),\n         Latitude = toreal(GeoInfo.latitude),\n         Longitude = toreal(GeoInfo.longitude)\n| where isnotempty(Country)\n| summarize BlockCount = count() by Country, Latitude, Longitude",
        "size": 1,
        "title": "Geographic Source Map — Blocked Traffic",
        "noDataMessage": "No geolocation data available for blocked traffic.",
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
      "name": "geo-source-map"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Network Traffic Volume\nHourly inbound and outbound traffic volume in megabytes."
      },
      "name": "traffic-volume-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| make-series InboundMB = sum(ReceivedBytes) / 1048576.0 default = 0, OutboundMB = sum(SentBytes) / 1048576.0 default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1h",
        "size": 1,
        "title": "Network Traffic Volume (MB)",
        "noDataMessage": "No traffic volume data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "network-traffic-volume"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top 15 Firewall Rules Hit\nMost-triggered firewall policy rules with block count breakdown."
      },
      "name": "firewall-rules-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| extend PolicyId = extract(@'FTNTFGTpolicyid=(\\d+)', 1, AdditionalExtensions)\n| where isnotempty(PolicyId)\n| summarize HitCount = count(), Blocked = countif(DeviceAction in ('Deny', 'Drop', 'Block', 'Reject', 'deny', 'drop', 'block', 'reject')) by PolicyId, DeviceVendor\n| top 15 by HitCount desc\n| project PolicyId, DeviceVendor, HitCount, Blocked\n| order by HitCount desc",
        "size": 0,
        "title": "Top 15 Firewall Rules Hit",
        "noDataMessage": "No firewall rule data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "HitCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
            },
            {
              "columnMatch": "Blocked",
              "formatter": 8,
              "formatOptions": { "min": 0, "palette": "redBright" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "HitCount", "sortOrder": 2 }]
        }
      },
      "name": "top-firewall-rules"
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
5. Select your **Subscription** and **Workspace** from the dropdowns at the top

---

## Permissions Required

Microsoft Sentinel Reader (or higher) on the workspace.
