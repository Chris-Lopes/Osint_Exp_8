# Dashboard Features Guide

## 🎯 New Features Added

### 1. **Multi-Page Navigation**
The dashboard now has 3 main sections accessible via tabs:

#### 📊 Overview (Default)
- Total threat statistics (Critical, High, Medium/Low)
- Trend charts (Last 7 days)
- Priority distribution pie chart
- Searchable threat table with pagination (50 items per page)
- Real-time data collection button
- Manual refresh functionality

#### 🔗 Correlation Graph
- **Indicator Selector**: Search and select any indicator (IP, domain, hash, URL)
- **Visual Network Graph**: Shows selected indicator at center with correlated indicators around it
- **Color-coded Nodes**:
  - 🔵 Blue = Selected indicator
  - 🔴 Red = P1 Critical correlations
  - 🟠 Orange = P2 High correlations
  - 🟢 Green = P3/P4 Low correlations
- **Correlation Stats**: 
  - Total correlated indicators
  - Risk scores
  - Source information
  - Indicator types
- **Export**: Download graph as PNG image

**Correlation Logic**:
- Same source (e.g., all from URLhaus)
- Same indicator type (e.g., all domains)
- Same priority level
- Limited to 15 most relevant correlations

#### 📝 Rules Generation
Automatically generates detection rules from threat indicators:

**Supported Rule Types**:
1. **Sigma Rules**: For SIEM systems (Splunk, Elastic, QRadar)
2. **Snort Rules**: Network IDS rules
3. **YARA Rules**: Malware detection signatures
4. **Suricata Rules**: Network security monitoring

**Filters**:
- **Indicator Type**: IP, Domain, URL, SHA256, MD5
- **Priority**: P1/P2/P3/P4
- **Max Rules**: 10, 25, 50, or 100 rules

**Features**:
- Copy individual rules with one click
- Copy all generated rules at once
- Color-coded by priority
- Includes metadata (author, date, priority, source)
- UUID generation for Sigma rules
- Proper SID numbering for Snort/Suricata

## 🚀 How to Use

### Access the Dashboard
```bash
# Make sure server is running
python dashboard_api.py

# Open in browser
http://localhost:5000
```

### Use Correlation Graph
1. Click **"🔗 Correlation Graph"** tab
2. Type in search box or select indicator from dropdown
3. Click **"🔍 Show Correlations"**
4. View network graph with connected indicators
5. Click **"📥 Export Graph"** to download PNG

### Generate Detection Rules
1. Click **"📝 Rules Generation"** tab
2. Select **Rule Type** (Sigma/Snort/YARA/Suricata)
3. Filter by **Indicator Type** and **Priority**
4. Set **Max Rules** limit
5. Click **"⚡ Generate Rules"**
6. Copy individual rules or all at once

### Example: Generate Sigma Rules for Critical IPs
```
1. Navigate to Rules Generation tab
2. Rule Type: Sigma Rule
3. Indicator Type: IP Address
4. Priority: P1 - Critical
5. Max Rules: 25
6. Click Generate Rules
7. Copy rules for deployment
```

## 📊 Data Loading

The dashboard now loads **ALL threat data** (no 1,000 limit):
- ✅ All 29,531+ indicators loaded from data files
- ✅ 60-second cache to improve performance
- ✅ Pagination shows 50 items per page
- ✅ Search and filter work across entire dataset

## 🎨 Visual Elements

### Graph Visualization
- Interactive canvas-based rendering
- Center node (selected indicator) larger and highlighted
- Edge connections show relationships
- Truncated labels for readability
- Legend explains color coding

### Rule Cards
- Syntax-highlighted code blocks
- Dark theme for readability
- Copy buttons for quick deployment
- Metadata footer with key information

## 🔧 Technical Details

### JavaScript Functions Added
- `showPage(pageName)` - Tab navigation
- `loadIndicatorsList()` - Fetch all indicators for dropdown
- `loadCorrelationGraph()` - Build and render network graph
- `drawNetworkGraph(ctx, canvas, center, nodes)` - Canvas drawing logic
- `exportGraph()` - Download graph as image
- `generateRules()` - Main rules generation
- `generateSigmaRule(threat, index)` - Sigma rule builder
- `generateSnortRule(threat, index)` - Snort rule builder
- `generateYaraRule(threat, index)` - YARA rule builder
- `generateSuricataRule(threat, index)` - Suricata rule builder
- `displayRules(rules, ruleType)` - Render rule cards
- `copyRule(button)` - Copy single rule
- `copyAllRules()` - Copy all rules
- `generateUUID()` - UUID generator for Sigma

### CSS Classes Added
- `.nav-tabs`, `.nav-tab` - Tab navigation
- `.page`, `.page.active` - Page switching
- `.correlation-controls` - Graph controls container
- `.indicator-selector` - Dropdown/input styling
- `#graphCanvas` - Canvas element for graph
- `.graph-legend` - Color legend
- `.rules-controls` - Rules form container
- `.rule-card` - Individual rule display
- `.rule-content` - Code block styling

## 📝 Example Generated Rules

### Sigma Rule Example
```yaml
title: Detect IPV4 - 192.168.1.100
id: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: Detection rule for ipv4 indicator 192.168.1.100
logsource:
    category: network
    product: firewall
detection:
    selection:
        dst_ip: '192.168.1.100'
    condition: selection
level: critical
```

### Snort Rule Example
```
alert tcp any any -> 192.168.1.100 any (msg:"Malicious IP 192.168.1.100"; sid:1000001; rev:1;)
```

### YARA Rule Example
```
rule Threat_domain_5 {
    meta:
        description = "Detects domain indicator evil.com"
        author = "OSINT Threat Intelligence"
        priority = "P1"
    
    strings:
        $indicator = "evil.com" wide ascii
    
    condition:
        any of them
}
```

## 🎯 Use Cases

1. **SOC Analyst Workflow**:
   - View dashboard for threat overview
   - Select high-priority indicator
   - Check correlation graph for campaign identification
   - Generate Sigma rules for SIEM deployment

2. **Threat Hunter**:
   - Search for specific indicator
   - Visualize relationships
   - Export graph for documentation
   - Generate YARA rules for malware hunting

3. **Network Security**:
   - Filter by IP indicators
   - Generate Snort/Suricata rules
   - Deploy rules to IDS/IPS
   - Monitor blocked connections

## 🔄 Future Enhancements

Potential additions:
- Advanced correlation algorithms (MITRE ATT&CK mapping)
- Graph clustering and community detection
- Rule validation and testing
- Bulk rule export (ZIP download)
- Graph zoom and pan controls
- Timeline visualization
- Threat campaign grouping
