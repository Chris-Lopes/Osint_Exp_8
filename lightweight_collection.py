#!/usr/bin/env python3
"""
Lightweight Collection Script

Collects from only the most critical sources with memory limits.
Use this instead of enhanced_collection.py for low-resource environments.
"""

import sys
from pathlib import Path
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.collectors.run_all import CollectionOrchestrator

def lightweight_collect():
    """Run collection with limited sources to save memory."""
    print("🔄 Starting lightweight collection...")
    print("📊 Limited to high-value sources only")
    
    # Initialize orchestrator
    orchestrator = CollectionOrchestrator()
    
    # Override to only run specific sources
    priority_sources = [
        'urlhaus_recent',      # High-quality malware URLs
        'malwarebazaar_recent', # Recent malware hashes
        'threatfox'            # Curated IOCs
    ]
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'sources': {},
        'total_collected': 0
    }
    
    # Run only priority sources
    for source_name in priority_sources:
        try:
            print(f"\n📡 Collecting from {source_name}...")
            source_results = orchestrator.run_source(source_name)
            
            if source_results:
                results['sources'][source_name] = source_results
                count = source_results.get('count', 0)
                results['total_collected'] += count
                print(f"✅ {source_name}: {count} indicators")
            else:
                print(f"⚠️  {source_name}: No data collected")
                
        except Exception as e:
            print(f"❌ {source_name} failed: {e}")
            results['sources'][source_name] = {'error': str(e)}
    
    # Save summary
    summary_file = Path('data/raw/lightweight_collection_summary.json')
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(summary_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Collection complete: {results['total_collected']} total indicators")
    print(f"📄 Summary saved to {summary_file}")
    
    return results

if __name__ == '__main__':
    try:
        lightweight_collect()
    except KeyboardInterrupt:
        print("\n⚠️  Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Collection failed: {e}")
        sys.exit(1)
