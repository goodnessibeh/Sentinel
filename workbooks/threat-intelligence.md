# Threat Intelligence Dashboard

IOC matches, feed coverage, hit rate, and indicator freshness for Microsoft Sentinel. Tracks active threat intelligence indicators, their types, confidence levels, expiration status, and cross-table matches.

- **KPI Tiles** — Total active IOCs, IP indicators, domain indicators, URL indicators, hash indicators
- **Indicator Type Distribution** — Pie chart of indicator types (Domain, URL, IP, Email, Hash, Other)
- **New Indicators Per Day** — Daily trend of newly ingested threat intelligence indicators
- **Expiring Indicators** — Table of indicators expiring within 7 days with urgency coloring
- **TI Matches — IP Hits Across Tables** — Cross-table IP match results with heatmap
- **Indicator Confidence Distribution** — Bar chart of confidence score buckets
- **Threat Type Breakdown** — Pie chart of top 10 threat types

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
        "json": "# Threat Intelligence Dashboard\n---\nIOC matches, feed coverage, hit rate, and indicator freshness.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Active Indicator Overview\nTotal active IOCs broken down by indicator type."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "ThreatIntelligenceIndicator\n| where TimeGenerated {TimeRange}\n| where Active == true and ExpirationDateTime > now()\n| summarize\n    TotalActiveIOCs = count(),\n    IPIndicators = countif(isnotempty(NetworkIP)),\n    DomainIndicators = countif(isnotempty(DomainName)),\n    URLIndicators = countif(isnotempty(Url)),\n    HashIndicators = countif(isnotempty(FileHashValue))\n| project pack_array(\n    pack('Metric', 'Total Active IOCs', 'Value', TotalActiveIOCs),\n    pack('Metric', 'IP Indicators', 'Value', IPIndicators),\n    pack('Metric', 'Domain Indicators', 'Value', DomainIndicators),\n    pack('Metric', 'URL Indicators', 'Value', URLIndicators),\n    pack('Metric', 'Hash Indicators', 'Value', HashIndicators)\n)\n| mv-expand Column1\n| evaluate bag_unpack(Column1)",
        "size": 4,
        "title": "Active Indicator Overview",
        "noDataMessage": "No active threat intelligence indicators found.",
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
              { "operator": "contains", "value": "Total", "color": "#0078D4" },
              { "operator": "contains", "value": "IP", "color": "#D13438" },
              { "operator": "contains", "value": "Domain", "color": "#F7630C" },
              { "operator": "contains", "value": "URL", "color": "#107C10" },
              { "operator": "contains", "value": "Hash", "color": "#5C2D91" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Metric"
          }
        }
      },
      "name": "kpi-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Indicator Type Distribution\nBreakdown of active indicators by type (Domain, URL, IP, Email, Hash, Other)."
      },
      "name": "type-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "ThreatIntelligenceIndicator\n| where TimeGenerated {TimeRange}\n| where Active == true and ExpirationDateTime > now()\n| extend IndicatorType = case(\n    isnotempty(DomainName), \"Domain\",\n    isnotempty(Url), \"URL\",\n    isnotempty(NetworkIP), \"IP\",\n    isnotempty(EmailSenderAddress), \"Email\",\n    isnotempty(FileHashValue), \"Hash\",\n    \"Other\")\n| summarize IndicatorCount = count() by IndicatorType\n| order by IndicatorCount desc",
        "size": 3,
        "title": "Indicator Type Distribution",
        "noDataMessage": "No active indicators found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "indicator-type-piechart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## New Indicators Per Day\nDaily ingestion trend of new threat intelligence indicators over the past 30 days."
      },
      "name": "new-indicators-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "ThreatIntelligenceIndicator\n| where Active == true and ExpirationDateTime > now()\n| make-series NewIndicators = count() default=0 on TimeGenerated from ago(30d) to now() step 1d",
        "size": 1,
        "title": "New Indicators Per Day",
        "noDataMessage": "No indicator ingestion data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "timechart"
      },
      "name": "new-indicators-timechart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Expiring Indicators\nIndicators expiring within the next 7 days, with urgency coloring."
      },
      "name": "expiring-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "ThreatIntelligenceIndicator\n| where TimeGenerated {TimeRange}\n| where Active == true and ExpirationDateTime > now()\n| where ExpirationDateTime between (now() .. now() + 7d)\n| extend DaysUntilExpiry = datetime_diff(\"day\", ExpirationDateTime, now())\n| extend Urgency = case(\n    DaysUntilExpiry <= 1, \"Expiring Today\",\n    DaysUntilExpiry <= 3, \"Expiring Soon\",\n    \"OK\")\n| extend IndicatorValue = coalesce(NetworkIP, DomainName, Url, FileHashValue, \"N/A\")\n| project ThreatType, IndicatorValue, DaysUntilExpiry, Confidence, Urgency\n| order by DaysUntilExpiry asc",
        "size": 0,
        "title": "Expiring Indicators (Next 7 Days)",
        "noDataMessage": "No indicators expiring within the next 7 days.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "Urgency",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                  { "operator": "==", "thresholdValue": "Expiring Today", "representation": "redBright", "text": "Expiring Today" },
                  { "operator": "==", "thresholdValue": "Expiring Soon", "representation": "orange", "text": "Expiring Soon" },
                  { "operator": "==", "thresholdValue": "OK", "representation": "green", "text": "OK" },
                  { "operator": "Default", "representation": "gray", "text": "{0}" }
                ]
              }
            },
            {
              "columnMatch": "DaysUntilExpiry",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 7, "palette": "redGreen" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "DaysUntilExpiry", "sortOrder": 1 }]
        }
      },
      "name": "expiring-indicators-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## TI Matches — IP Hits Across Tables\nMalicious IP indicators matched against SigninLogs, CommonSecurityLog, and DeviceNetworkEvents."
      },
      "name": "ti-matches-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let MaliciousIPs = ThreatIntelligenceIndicator\n| where TimeGenerated {TimeRange}\n| where Active == true and ExpirationDateTime > now()\n| where isnotempty(NetworkIP)\n| distinct NetworkIP;\nlet SigninMatches = SigninLogs\n| where TimeGenerated {TimeRange}\n| where IPAddress in (MaliciousIPs)\n| summarize MatchCount = count() by MatchedIP = IPAddress\n| extend SourceTable = \"SigninLogs\";\nlet CSLMatches = CommonSecurityLog\n| where TimeGenerated {TimeRange}\n| where SourceIP in (MaliciousIPs) or DestinationIP in (MaliciousIPs)\n| extend MatchedIP = iff(SourceIP in (MaliciousIPs), SourceIP, DestinationIP)\n| summarize MatchCount = count() by MatchedIP\n| extend SourceTable = \"CommonSecurityLog\";\nlet DeviceMatches = DeviceNetworkEvents\n| where TimeGenerated {TimeRange}\n| where RemoteIP in (MaliciousIPs)\n| summarize MatchCount = count() by MatchedIP = RemoteIP\n| extend SourceTable = \"DeviceNetworkEvents\";\nunion SigninMatches, CSLMatches, DeviceMatches\n| summarize MatchCount = sum(MatchCount) by SourceTable, MatchedIP\n| order by MatchCount desc",
        "size": 0,
        "title": "TI Matches — IP Hits Across Tables",
        "noDataMessage": "No IP indicator matches found across monitored tables.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "MatchCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "MatchCount", "sortOrder": 2 }]
        }
      },
      "name": "ti-ip-matches-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Indicator Confidence Distribution\nActive indicators grouped by confidence score buckets."
      },
      "name": "confidence-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "ThreatIntelligenceIndicator\n| where TimeGenerated {TimeRange}\n| where Active == true and ExpirationDateTime > now()\n| extend ConfidenceBucket = case(\n    Confidence >= 80, \"High (80-100)\",\n    Confidence >= 50, \"Medium (50-79)\",\n    Confidence >= 1, \"Low (1-49)\",\n    \"Unknown\")\n| summarize IndicatorCount = count() by ConfidenceBucket\n| order by case(\n    ConfidenceBucket == \"High (80-100)\", 1,\n    ConfidenceBucket == \"Medium (50-79)\", 2,\n    ConfidenceBucket == \"Low (1-49)\", 3,\n    4) asc",
        "size": 1,
        "title": "Indicator Confidence Distribution",
        "noDataMessage": "No active indicators with confidence data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "confidence-barchart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Threat Type Breakdown\nTop 10 threat types across active indicators."
      },
      "name": "threat-type-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "ThreatIntelligenceIndicator\n| where TimeGenerated {TimeRange}\n| where Active == true and ExpirationDateTime > now()\n| summarize IndicatorCount = count() by ThreatType\n| top 10 by IndicatorCount desc",
        "size": 3,
        "title": "Threat Type Breakdown",
        "noDataMessage": "No threat type data available.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "threat-type-piechart"
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
