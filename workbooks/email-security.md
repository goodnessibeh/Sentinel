# Email Security Dashboard

Phishing defense and email threat analysis for Microsoft Sentinel. Tracks inbound email threats, phishing and malware blocks, BEC attempts, attachment analysis, and targeted recipient patterns.

- **KPI Tiles** — Total inbound emails, phishing blocked, malware blocked, and phishing delivered counts
- **Email Threat Timeline** — Daily threat volume broken down by category (Phishing, Malware, Spam, Other)
- **Delivery Action Distribution** — Pie chart of email delivery outcomes for inbound mail
- **Top Phishing Sender Domains** — Highest-volume phishing sender domains
- **Targeted Recipients** — Most-targeted users by phishing and malware email count
- **Malicious Attachments** — Attachment file analysis with malware verdict breakdown
- **Email Volume Trend** — Daily total vs threat email volume overlay

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
        "json": "# Email Security Dashboard\n---\nPhishing defense and email threat analysis.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Email Security KPIs\nInbound email volume and threat blocking effectiveness."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailEvents\n| where TimeGenerated {TimeRange}\n| where EmailDirection == 'Inbound'\n| summarize TotalInbound = count(),\n    PhishBlocked = countif(ThreatTypes has 'Phish' and DeliveryAction != 'Delivered'),\n    MalwareBlocked = countif(ThreatTypes has 'Malware' and DeliveryAction != 'Delivered'),\n    PhishDelivered = countif(ThreatTypes has 'Phish' and DeliveryAction == 'Delivered')\n| project Metric = 'Total Inbound', Value = TotalInbound\n| union (\n    EmailEvents\n    | where TimeGenerated {TimeRange}\n    | where EmailDirection == 'Inbound'\n    | summarize PhishBlocked = countif(ThreatTypes has 'Phish' and DeliveryAction != 'Delivered')\n    | project Metric = 'Phish Blocked', Value = PhishBlocked\n)\n| union (\n    EmailEvents\n    | where TimeGenerated {TimeRange}\n    | where EmailDirection == 'Inbound'\n    | summarize MalwareBlocked = countif(ThreatTypes has 'Malware' and DeliveryAction != 'Delivered')\n    | project Metric = 'Malware Blocked', Value = MalwareBlocked\n)\n| union (\n    EmailEvents\n    | where TimeGenerated {TimeRange}\n    | where EmailDirection == 'Inbound'\n    | summarize PhishDelivered = countif(ThreatTypes has 'Phish' and DeliveryAction == 'Delivered')\n    | project Metric = 'Phish Delivered', Value = PhishDelivered\n)",
        "size": 4,
        "title": "Email Security KPIs",
        "noDataMessage": "No email data found.",
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
              { "operator": "contains", "value": "Total Inbound", "color": "#0078D4" },
              { "operator": "contains", "value": "Phish Blocked", "color": "#107C10" },
              { "operator": "contains", "value": "Malware Blocked", "color": "#107C10" },
              { "operator": "contains", "value": "Phish Delivered", "color": "#D13438" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Metric"
          }
        }
      },
      "name": "email-kpi-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Email Threat Timeline\nDaily inbound email threat volume by category."
      },
      "name": "threat-timeline-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailEvents\n| where TimeGenerated {TimeRange}\n| where EmailDirection == 'Inbound'\n| where ThreatTypes != ''\n| extend ThreatCategory = case(\n    ThreatTypes has 'Phish', 'Phishing',\n    ThreatTypes has 'Malware', 'Malware',\n    ThreatTypes has 'Spam', 'Spam',\n    'Other')\n| make-series Count = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d by ThreatCategory",
        "size": 1,
        "title": "Email Threat Timeline",
        "noDataMessage": "No email threats found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "threat-timeline-area"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Delivery Action Distribution\nBreakdown of delivery outcomes for inbound emails."
      },
      "name": "delivery-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailEvents\n| where TimeGenerated {TimeRange}\n| where EmailDirection == 'Inbound'\n| summarize EmailCount = count() by DeliveryAction\n| order by EmailCount desc",
        "size": 3,
        "title": "Delivery Action Distribution",
        "noDataMessage": "No inbound email data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "delivery-action-pie"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top Phishing Sender Domains\nMost prolific domains sending phishing emails."
      },
      "name": "phish-domains-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailEvents\n| where TimeGenerated {TimeRange}\n| where EmailDirection == 'Inbound'\n| where ThreatTypes has 'Phish'\n| summarize PhishCount = count() by SenderFromDomain\n| top 20 by PhishCount desc",
        "size": 1,
        "title": "Top Phishing Sender Domains",
        "noDataMessage": "No phishing emails found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "phish-sender-domains-bar"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Targeted Recipients\nMost-targeted users by phishing and malware email volume."
      },
      "name": "targeted-recipients-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailEvents\n| where TimeGenerated {TimeRange}\n| where EmailDirection == 'Inbound'\n| where ThreatTypes has_any ('Phish', 'Malware')\n| summarize ThreatCount = count(), Senders = make_set(SenderFromAddress, 10), Subjects = make_set(Subject, 5) by RecipientEmailAddress\n| top 20 by ThreatCount desc",
        "size": 0,
        "title": "Targeted Recipients (Top 20)",
        "noDataMessage": "No targeted recipients found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "ThreatCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "ThreatCount", "sortOrder": 2 }]
        }
      },
      "name": "targeted-recipients-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Malicious Attachments\nFile-level analysis of attachments flagged by malware filters."
      },
      "name": "malicious-attachments-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailAttachmentInfo\n| where TimeGenerated {TimeRange}\n| where MalwareFilterVerdict != 'none' and MalwareFilterVerdict != ''\n| summarize Count = count(), UniqueFiles = dcount(SHA256), Recipients = make_set(RecipientEmailAddress, 5) by FileName, FileType, MalwareFilterVerdict\n| order by Count desc",
        "size": 0,
        "title": "Malicious Attachments",
        "noDataMessage": "No malicious attachments found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "Count",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 50, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
        }
      },
      "name": "malicious-attachments-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Email Volume Trend\nDaily total inbound email volume overlaid with threat email volume."
      },
      "name": "volume-trend-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "EmailEvents\n| where TimeGenerated {TimeRange}\n| where EmailDirection == 'Inbound'\n| make-series TotalEmails = count() default = 0, ThreatEmails = countif(ThreatTypes != '') default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d",
        "size": 1,
        "title": "Email Volume Trend",
        "noDataMessage": "No inbound email data found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "email-volume-trend-area"
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
