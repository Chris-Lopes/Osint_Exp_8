# Threat Intelligence Dashboard

## Overview
A real-time web dashboard that visualizes threat intelligence data collected from the OSINT pipeline.

## Features
- **Live Statistics**: Total threats, priority distribution (P1-P4)
- **Trend Analysis**: 7-day threat trends visualization
- **Threat Indicators Table**: Searchable and filterable IOC list
- **Priority Distribution**: Visual breakdown by severity
- **Auto-refresh**: Updates every 30 seconds

## Quick Start

### 1. Start the Dashboard API Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start the Flask API server
python dashboard_api.py
```

The API server will start on `http://localhost:5000`

### 2. Access the Dashboard

Open your browser and navigate to:
```
http://localhost:5000
```

## Dashboard Components

### Top Statistics Cards
- **Total Threats**: All indicators collected
- **Critical (P1)**: Highest priority threats requiring immediate action
- **High Priority (P2)**: Important threats needing attention
- **Medium/Low (P3-P4)**: Monitored threats

### Charts
- **Threat Trends**: Line chart showing daily threat volumes over the last 7 days
- **Priority Distribution**: Doughnut chart breaking down threats by priority level

### Threat Indicators Table
- **Search**: Filter threats by indicator value
- **Priority Filter**: Filter by P1, P2, P3, or P4
- **Type Filter**: Filter by URL, IPv4, Domain, SHA256, MD5, etc.
- **Pagination**: Browse through threats 20 at a time
- **Columns**:
  - Indicator: The actual IOC (IP, URL, hash, domain)
  - Type: Classification of the indicator
  - Score: Risk score (0-100)
  - Priority: P1 (Critical) to P4 (Low)
  - Status: Active/Inactive
  - Sources: Origin feed (urlhaus, otx, malwarebazaar, etc.)
  - Last Seen: Timestamp of last observation

## API Endpoints

### GET /api/stats
Returns dashboard statistics and chart data.

**Response:**
```json
{
  "total_threats": 91539,
  "critical": 0,
  "high": 0,
  "medium": 183078,
  "priority_distribution": [...],
  "source_distribution": [...],
  "trend_data": [...]
}
```

### GET /api/threats
Returns paginated threat indicators with filtering.

**Query Parameters:**
- `search`: Filter by indicator value
- `priority`: Filter by P1, P2, P3, P4
- `type`: Filter by type (url, ipv4, domain, sha256, etc.)
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 50)

**Response:**
```json
{
  "threats": [...],
  "total": 91539,
  "page": 1,
  "per_page": 50,
  "total_pages": 1831
}
```

### GET /api/threat/<indicator>
Returns details for a specific threat indicator.

## Data Sources

The dashboard automatically loads threat data from:
- `data/raw/` - Raw collected data
- `data/processed/` - Normalized indicators
- `data/enriched/` - Enriched with context
- `data/merged/` - Deduplicated data

## Running with the Full Pipeline

To collect fresh data and view it in the dashboard:

```bash
# 1. Run the collection pipeline
make all-parallel

# 2. Start the dashboard (if not already running)
python dashboard_api.py

# 3. Open browser to http://localhost:5000
```

## Stopping the Dashboard

To stop the dashboard server:
```bash
# Find the process
ps aux | grep dashboard_api

# Kill the process
pkill -f dashboard_api
```

Or press `Ctrl+C` in the terminal where it's running.

## Troubleshooting

### Dashboard shows "Error loading threat data"
- Ensure the Flask API server is running on port 5000
- Check `logs/dashboard.log` for errors
- Verify data exists in `data/raw/`, `data/processed/`, or `data/enriched/`

### No threats displayed
- Run the collection pipeline: `make all-parallel` or `python run_lab_analysis.py`
- Check that data files exist with: `ls -la data/raw/*/`

### Port 5000 already in use
- Stop the conflicting process or change the port in `dashboard_api.py`:
  ```python
  app.run(debug=True, host='0.0.0.0', port=5001)  # Change to 5001
  ```

## Screenshots

The dashboard displays:
1. **Top Cards**: Real-time threat counts by priority
2. **Trend Chart**: Line graph of threat volume over time
3. **Priority Pie Chart**: Visual breakdown of threat priorities
4. **IOC Table**: Searchable, filterable table of all indicators

## Integration with Streamlit

You can run both dashboards simultaneously:
- **Flask Dashboard** (port 5000): Real-time threat viewer
- **Streamlit App** (port 8501): Pipeline execution and reports

```bash
# Terminal 1: Start Flask dashboard
python dashboard_api.py

# Terminal 2: Start Streamlit app
streamlit run app.py
```
