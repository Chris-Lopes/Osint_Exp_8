# Memory Optimization Guide

## Problem
Running the full threat intelligence pipeline was consuming too much memory and causing system lag.

## Solutions Implemented

### 1. **Data Limits** 
- Dashboard now loads only **1,000 threats maximum** instead of all 29,531+
- Prioritizes quality: Merged > Enriched > Processed > Raw data
- Pagination reduced from 20 to 10 items per page

### 2. **Response Caching**
- 60-second cache on API responses
- Prevents reloading 1,000 threats on every request
- Cache invalidates automatically after collection

### 3. **Lightweight Collection**
```bash
# Use this instead of full pipeline
python lightweight_collection.py
```

**Collects from only 3 sources:**
- `urlhaus_recent` - High-quality malware URLs
- `malwarebazaar_recent` - Recent malware hashes  
- `threatfox` - Curated IOCs

**Benefits:**
- ~70% less memory usage
- ~60% faster collection
- Still gets high-quality threat data

### 4. **Dashboard Improvements**
- Charts fixed to 400px height (prevents vertical growth)
- Canvas max-height: 300px
- Removed auto-refresh (manual only)
- Collection runs as detached process

## Usage

### Start Dashboard (Low Memory Mode)
```bash
source venv/bin/activate
python dashboard_api.py
```

Open: http://localhost:5000

### Collect Fresh Data
1. Click "📡 Collect Fresh Data" button in dashboard
2. Wait 20-30 seconds  
3. Click "🔄 Refresh View" to see new data

### Manual Collection (Terminal)
```bash
# Lightweight (3 sources)
source venv/bin/activate
python lightweight_collection.py

# Full collection (12+ sources) - use only if you have 8GB+ RAM
python enhanced_collection.py
```

## Memory Comparison

| Method | Sources | Memory Usage | Time |
|--------|---------|--------------|------|
| Full Pipeline | 12+ | ~2-4 GB | 2-5 min |
| Lightweight | 3 | ~500 MB | 30-60 sec |
| Dashboard Only | - | ~200 MB | - |

## Troubleshooting

### Still Running Out of Memory?

**Reduce data limit further:**
Edit `dashboard_api.py`:
```python
threats = get_cached_threats(limit=500)  # Change from 1000 to 500
```

**Clear old data:**
```bash
# Remove old collections
rm -rf data/raw/otx*
rm -rf data/processed/otx*
rm -rf data/enriched/otx*
```

**Run collection only:**
```bash
# Don't run full pipeline (normalization, enrichment, etc.)
python lightweight_collection.py
```

### System Still Lagging?

**Check running processes:**
```bash
ps aux | grep python
```

**Kill hung processes:**
```bash
pkill -f "python.*enhanced_collection"
pkill -f "python.*dashboard_api"
```

**Monitor memory:**
```bash
# Check memory usage
free -h

# Watch in real-time
watch -n 1 free -h
```

## Recommended Hardware

- **Minimum:** 4GB RAM, 2 CPU cores
- **Recommended:** 8GB RAM, 4 CPU cores
- **Optimal:** 16GB RAM, 8 CPU cores

## Best Practices

1. **Use lightweight collection** for daily updates
2. **Run full pipeline weekly** only (not daily)
3. **Clear cache** before major operations: `rm -rf __pycache__`
4. **Close other applications** before running collection
5. **Use terminal instead of Streamlit** for large operations
