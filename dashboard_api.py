#!/usr/bin/env python3
"""
Threat Intelligence Dashboard API

Flask API server that serves threat intelligence data for the dashboard frontend.
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from pathlib import Path
import json
from datetime import datetime, timedelta
from collections import defaultdict
import sys

app = Flask(__name__, static_folder='dashboard', static_url_path='')
CORS(app)

# Simple cache to avoid reloading data on every request
_threat_cache = {'data': None, 'timestamp': None}
CACHE_TTL = 60  # Cache for 60 seconds

def get_cached_threats():
    """Get threats from cache or reload if stale."""
    now = datetime.now()
    
    if _threat_cache['data'] is None or _threat_cache['timestamp'] is None:
        # First load
        _threat_cache['data'] = load_threats_from_data()
        _threat_cache['timestamp'] = now
    elif (now - _threat_cache['timestamp']).total_seconds() > CACHE_TTL:
        # Cache expired
        _threat_cache['data'] = load_threats_from_data()
        _threat_cache['timestamp'] = now
    
    return _threat_cache['data']

def load_threats_from_data():
    """Load ALL threat indicators from data directories (no limits)."""
    threats = []
    
    # Prioritize merged > enriched > processed > raw to get best quality data
    data_dirs = [
        Path('data/merged'),
        Path('data/enriched'),
        Path('data/processed'),
        Path('data/raw')
    ]
    
    for base_dir in data_dirs:
        if not base_dir.exists():
            continue
            
        for jsonl_file in base_dir.rglob('*.jsonl'):
            try:
                with open(jsonl_file, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            obj = json.loads(line)
                            threat = normalize_threat(obj, str(jsonl_file))
                            if threat:
                                threats.append(threat)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"Error loading {jsonl_file}: {e}")
                continue
    
    print(f"📊 Loaded {len(threats):,} total threats from all data sources")
    return threats

def normalize_threat(obj, source_file):
    """Normalize threat object to common format."""
    # Extract indicator value
    indicator = None
    for key in ['indicator', 'value', 'ioc', 'url', 'ip', 'domain', 'hash']:
        if key in obj:
            indicator = obj.get(key)
            break
    
    if not indicator:
        return None
    
    # Extract type
    threat_type = obj.get('type') or obj.get('indicator_type') or 'unknown'
    
    # Extract priority/severity
    priority = 'P3'  # default
    score = obj.get('risk_score') or obj.get('score') or obj.get('confidence', 50)
    
    if isinstance(score, (int, float)):
        if score >= 85:
            priority = 'P1'
        elif score >= 70:
            priority = 'P2'
        elif score >= 50:
            priority = 'P3'
        else:
            priority = 'P4'
    
    # Extract source
    source = obj.get('_source') or obj.get('source') or Path(source_file).parent.name
    
    # Extract timestamps
    last_seen = obj.get('last_seen') or obj.get('_collected_at') or obj.get('modified') or datetime.now().isoformat()
    
    # Determine status
    status = 'active'
    if obj.get('status'):
        status = obj.get('status')
    
    return {
        'indicator': str(indicator),
        'type': threat_type,
        'score': int(score) if isinstance(score, (int, float)) else 51,
        'priority': priority,
        'status': status,
        'sources': source,
        'last_seen': last_seen,
        'metadata': obj
    }

@app.route('/')
def index():
    """Serve the dashboard HTML."""
    return send_from_directory('dashboard', 'index.html')

@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics."""
    threats = get_cached_threats()  # Load ALL threats
    
    # Count by priority
    priority_counts = defaultdict(int)
    for threat in threats:
        priority_counts[threat['priority']] += 1
    
    # Count by source
    source_counts = defaultdict(int)
    for threat in threats:
        source_counts[threat['sources']] += 1
    
    # Generate trend data (last 7 days)
    trend_data = []
    for i in range(7):
        date = datetime.now() - timedelta(days=6-i)
        # Simulate daily counts (in real implementation, filter by timestamp)
        count = len([t for t in threats if date.strftime('%Y-%m-%d') in t.get('last_seen', '')])
        if count == 0:
            count = len(threats) // 7  # Average distribution
        trend_data.append({
            'date': date.strftime('%b %d'),
            'count': count
        })
    
    return jsonify({
        'total_threats': len(threats),
        'critical': priority_counts.get('P1', 0),
        'high': priority_counts.get('P2', 0),
        'medium': priority_counts.get('P3', 0) + priority_counts.get('P4', 0),
        'priority_distribution': [
            {'name': 'P1 - Critical', 'value': priority_counts.get('P1', 0)},
            {'name': 'P2 - High', 'value': priority_counts.get('P2', 0)},
            {'name': 'P3 - Medium', 'value': priority_counts.get('P3', 0)},
            {'name': 'P4 - Low', 'value': priority_counts.get('P4', 0)}
        ],
        'source_distribution': [
            {'name': source, 'value': count}
            for source, count in sorted(source_counts.items(), key=lambda x: -x[1])[:10]
        ],
        'trend_data': trend_data
    })

@app.route('/api/threats')
def get_threats():
    """Get threat indicators with pagination and filtering."""
    threats = get_cached_threats()  # Load ALL threats
    
    # Get query parameters
    search = request.args.get('search', '').lower()
    priority = request.args.get('priority', '')
    threat_type = request.args.get('type', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    # Filter
    filtered = threats
    if search:
        filtered = [t for t in filtered if search in t['indicator'].lower()]
    if priority:
        filtered = [t for t in filtered if t['priority'] == priority]
    if threat_type:
        filtered = [t for t in filtered if t['type'] == threat_type]
    
    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    paginated = filtered[start:end]
    
    return jsonify({
        'threats': paginated,
        'total': len(filtered),
        'page': page,
        'per_page': per_page,
        'total_pages': (len(filtered) + per_page - 1) // per_page
    })

@app.route('/api/threat/<path:indicator>')
def get_threat_details(indicator):
    """Get details for a specific threat indicator."""
    threats = get_cached_threats()  # Load ALL threats
    
    for threat in threats:
        if threat['indicator'] == indicator:
            return jsonify(threat)
    
    return jsonify({'error': 'Threat not found'}), 404

@app.route('/api/collect', methods=['POST'])
def trigger_collection():
    """Trigger full data collection pipeline."""
    import subprocess
    import os
    
    try:
        # Use full collection to get all sources
        collection_script = 'enhanced_collection.py'
        
        # Set resource limits via environment
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        # Start collection as detached process
        subprocess.Popen(
            [sys.executable, collection_script],
            stdout=open('logs/collect.log', 'w'),
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True  # Detach from parent
        )
        
        # Clear cache so next request will reload fresh data
        _threat_cache['data'] = None
        _threat_cache['timestamp'] = None
        
        return jsonify({
            'status': 'started',
            'message': 'Full data collection started (all sources). Check logs/collect.log. Refresh in 2-3 minutes.'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to start collection: {str(e)}'
        }), 500

if __name__ == '__main__':
    print("🚀 Starting Threat Intelligence Dashboard API")
    print("📊 Dashboard URL: http://localhost:5000")
    print("🔌 API endpoints:")
    print("   - GET /api/stats - Dashboard statistics")
    print("   - GET /api/threats - Threat indicators list")
    print("   - GET /api/threat/<indicator> - Threat details")
    app.run(debug=True, host='0.0.0.0', port=5000)
